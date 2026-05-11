/**
 * Mock Partner ID (PID) — emulates stg-partner.hmg-corp.io
 *
 * This mock replicates the SAML IdP behavior observed in the Canada ADFS
 * SAML trace (PID-ILS-Test0901). It:
 *   1. Receives a SAMLRequest from the IAM Broker (acting as ADFS proxy)
 *   2. Shows a login page (LDAP + OTP, simplified for POC)
 *   3. Returns a signed SAMLResponse with the full PID attribute set
 *
 * The attribute schema matches the real PID payload exactly:
 *   - http://schemas.xmlsoap.org/claims/hmgpid
 *   - http://schemas.xmlsoap.org/claims/pid
 *   - http://schemas.xmlsoap.org/claims/username
 *   - http://schemas.xmlsoap.org/claims/dealercode
 *   - http://schemas.microsoft.com/ws/2008/06/identity/claims/role
 *   - http://schemas.xmlsoap.org/claims/memberOf
 *   - ... (40+ attributes from the real PID)
 */
const crypto = require('crypto');
const express = require('express');
const forge = require('node-forge');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = 3006;
const PID_ISSUER = 'https://stg-partner.hmg-corp.io/auth';
const PID_PUBLIC_URL = 'http://pid.sso.test:8000';

// Generate a self-signed cert for SAML signing (matches PID cert structure)
const { cert, privateKey } = generateSelfSignedCert();

// In-memory session store for pending SAML requests
const pendingRequests = new Map();

// Test users — attribute values match the real PID SAML trace
const TEST_USERS = require('./users');

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── SAML SSO Endpoint ───────────────────────────────────────────────
// Receives SAMLRequest via GET (redirect binding) or POST (post binding)
app.get('/auth/saml/sso', (req, res) => {
  const samlRequest = req.query.SAMLRequest;
  const relayState = req.query.RelayState || '';

  if (!samlRequest) {
    // No SAMLRequest — check if user has active session, generate response
    const sessionId = req.headers.cookie?.match(/PID_SSO_SESSION=([^;]+)/)?.[1];
    if (sessionId && pendingRequests.has(sessionId)) {
      const pending = pendingRequests.get(sessionId);
      return generateAndPostResponse(res, pending.user, pending.acsUrl, pending.requestId, pending.relayState, pending.issuer);
    }
    return res.status(400).send('No SAMLRequest provided');
  }

  // Decode SAMLRequest (deflate + base64)
  let xml;
  try {
    const buf = Buffer.from(samlRequest, 'base64');
    const zlib = require('zlib');
    xml = zlib.inflateRawSync(buf).toString('utf8');
  } catch (_) {
    // Try plain base64 (no deflate)
    xml = Buffer.from(samlRequest, 'base64').toString('utf8');
  }

  // Parse key fields from AuthnRequest
  const requestId = xml.match(/ID="([^"]+)"/)?.[1] || '_' + crypto.randomUUID();
  const acsUrl = xml.match(/AssertionConsumerServiceURL="([^"]+)"/)?.[1]
    || xml.match(/Destination="([^"]+)"/)?.[1]
    || '';
  const issuer = xml.match(/<(?:saml:)?Issuer[^>]*>([^<]+)<\/(?:saml:)?Issuer>/)?.[1] || '';

  // Store pending request
  const sessionId = crypto.randomUUID();
  pendingRequests.set(sessionId, { requestId, acsUrl, relayState, issuer, xml });

  // Redirect to login page
  res.setHeader('Set-Cookie', `PID_SSO_SESSION=${sessionId}; Path=/; HttpOnly`);
  res.redirect(`${PID_PUBLIC_URL}/auth/login?session=${sessionId}`);
});

// POST binding for SAMLRequest
app.post('/auth/saml/sso', (req, res) => {
  const samlRequest = req.body.SAMLRequest;
  const relayState = req.body.RelayState || '';

  if (!samlRequest) return res.status(400).send('No SAMLRequest');

  let xml;
  try {
    xml = Buffer.from(samlRequest, 'base64').toString('utf8');
  } catch (_) {
    return res.status(400).send('Invalid SAMLRequest encoding');
  }

  const requestId = xml.match(/ID="([^"]+)"/)?.[1] || '_' + crypto.randomUUID();
  const acsUrl = xml.match(/AssertionConsumerServiceURL="([^"]+)"/)?.[1] || '';
  const issuer = xml.match(/<(?:saml:)?Issuer[^>]*>([^<]+)<\/(?:saml:)?Issuer>/)?.[1] || '';

  const sessionId = crypto.randomUUID();
  pendingRequests.set(sessionId, { requestId, acsUrl, relayState, issuer, xml });

  res.setHeader('Set-Cookie', `PID_SSO_SESSION=${sessionId}; Path=/; HttpOnly`);
  res.redirect(`${PID_PUBLIC_URL}/auth/login?session=${sessionId}`);
});

// ─── Login Page ──────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const sessionId = req.query.session || '';
  const error = req.query.error || '';
  res.send(buildLoginPage(sessionId, error));
});

// ─── Login Submit (LDAP auth) ────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { username, password, session } = req.body;

  if (!session || !pendingRequests.has(session)) {
    return res.redirect(`${PID_PUBLIC_URL}/auth/login?error=invalid_session`);
  }

  const user = TEST_USERS[username];
  if (!user) {
    return res.redirect(`${PID_PUBLIC_URL}/auth/login?session=${session}&error=user_not_found`);
  }

  const pending = pendingRequests.get(session);
  pending.user = user;

  // Report step 4 to the broker's flow tracker AND the dashboard
  try {
    const http = require('http');
    const body = JSON.stringify({
      flowId: pending.requestId,
      step: 4,
      stepName: 'PID_USER_AUTHENTICATED',
      service: 'pid',
      description: `User "${username}" authenticated at Partner ID (PID). In the real system this involves LDAP credential check + RSA key exchange + OTP verification. The PID looked up the user in its directory and found ${Object.keys(user.attributes || {}).length}+ attributes to include in the SAML response.`,
      detail: {
        username,
        pid: user.pid,
        roles: user.attributes?.roles || [],
        dealerCode: user.attributes?.dealerCode || '',
        inResponseTo: pending.requestId,
      },
    });
    // Send to broker flow tracker
    const r = http.request({ hostname: 'iam-broker', port: 3003, path: '/flow/event', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } });
    r.on('error', () => {});
    r.write(body);
    r.end();

    // Send to dashboard
    const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://flow-dashboard:3007';
    const dashBody = JSON.stringify({
      flowId: pending.requestId,
      flowType: 'sp-initiated',
      step: 4,
      stepName: 'PID_AUTHENTICATES_USER',
      service: 'pid',
      description: `User "${username}" entered credentials at PID login page. PID verified identity via LDAP lookup. Found user with PID="${user.pid}", ${Object.keys(user.attributes || {}).length}+ attributes. In the real system, this also involves RSA key exchange and OTP verification. Now generating SAMLResponse with full attribute set.`,
      detail: {
        username, pid: user.pid,
        roles: user.attributes?.roles || [],
        dealerCode: user.attributes?.dealerCode || '',
        attributeCount: Object.keys(user.attributes || {}).length,
        inResponseTo: pending.requestId,
        acsUrl: pending.acsUrl,
      },
    });
    const dUrl = new URL(DASHBOARD_URL + '/api/event');
    const dr = http.request({ hostname: dUrl.hostname, port: dUrl.port, path: dUrl.pathname, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(dashBody) } });
    dr.on('error', () => {});
    dr.write(dashBody);
    dr.end();
  } catch (_) { /* not critical */ }

  // Generate SAML Response and POST back to ACS
  generateAndPostResponse(res, user, pending.acsUrl, pending.requestId, pending.relayState, pending.issuer);

  // Cleanup
  setTimeout(() => pendingRequests.delete(session), 5000);
});

// ─── Metadata Endpoint ───────────────────────────────────────────────
app.get('/auth/saml/metadata', (_req, res) => {
  const certPem = cert.replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\n/g, '');

  res.type('application/xml').send(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${PID_ISSUER}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>${certPem}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="${PID_PUBLIC_URL}/auth/saml/sso"/>
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${PID_PUBLIC_URL}/auth/saml/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`);
});

// ─── Flow Trace Endpoint (for visualization) ─────────────────────────
const flowLog = [];
app.get('/auth/flow-log', (_req, res) => {
  res.json(flowLog.slice(-50));
});
app.post('/auth/flow-log', (req, res) => {
  flowLog.push({ ts: new Date().toISOString(), ...req.body });
  res.json({ ok: true });
});

// ─── Helpers ─────────────────────────────────────────────────────────

function generateAndPostResponse(res, user, acsUrl, inResponseTo, relayState, audienceIssuer) {
  const now = new Date();
  const notOnOrAfter = new Date(now.getTime() + 30 * 60 * 1000); // 30 min
  const sessionExpiry = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour (per Jin Tae's directive)
  const responseId = '_' + crypto.randomUUID();
  const assertionId = '_' + crypto.randomUUID();
  const sessionIndex = '_' + crypto.randomUUID();

  // Build attribute statements matching the real PID payload
  const attrs = buildAttributeStatements(user);

  const assertion = `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ID="${assertionId}" IssueInstant="${now.toISOString()}" Version="2.0"><saml2:Issuer>${PID_ISSUER}</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${user.pid}</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="${inResponseTo}" NotOnOrAfter="${notOnOrAfter.toISOString()}"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="${new Date(now.getTime() - 60000).toISOString()}" NotOnOrAfter="${notOnOrAfter.toISOString()}"><saml2:AudienceRestriction><saml2:Audience>${audienceIssuer || 'http://broker.sso.test'}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="${sessionIndex}" SessionNotOnOrAfter="${sessionExpiry.toISOString()}"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement>${attrs}</saml2:AttributeStatement></saml2:Assertion>`;

  const samlResponse = `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ID="${responseId}" InResponseTo="${inResponseTo}" IssueInstant="${now.toISOString()}" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">${PID_ISSUER}</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>${assertion}</saml2p:Response>`;

  const encoded = Buffer.from(samlResponse).toString('base64');

  // Log the flow step
  flowLog.push({
    ts: now.toISOString(),
    step: 'PID_SAML_RESPONSE',
    user: user.pid,
    acsUrl,
    responseId,
    assertionId,
    attributes: Object.keys(user.attributes || {}),
  });

  // Auto-POST form back to ACS URL (browser-mediated)
  // Use the broker's public URL for the ACS
  const targetAcs = acsUrl.replace(/http:\/\/iam-broker:3003/, 'http://broker.sso.test:8000')
    || 'http://broker.sso.test:8000/saml/acs';

  res.send(`<!DOCTYPE html>
<html><head><title>PID SSO</title></head>
<body>
<p>Authenticating via Partner ID...</p>
<form method="post" action="${escapeHtml(targetAcs)}">
  <input type="hidden" name="SAMLResponse" value="${encoded}">
  <input type="hidden" name="RelayState" value="${escapeHtml(relayState)}">
  <noscript><button type="submit">Continue</button></noscript>
</form>
<script>document.forms[0].submit();</script>
</body></html>`);
}

function buildAttributeStatements(user) {
  const a = user.attributes || {};
  const attrEntries = [
    ['http://schemas.xmlsoap.org/claims/hmgpid', 'HMG PID', a.hmgpid || ''],
    ['http://schemas.xmlsoap.org/claims/pid', 'PID', a.pid || user.pid],
    ['User.FederationIdentifier', 'User.FederationIdentifier', a.federationId || user.pid],
    ['http://schemas.xmlsoap.org/claims/username', 'UserName', a.username || user.pid],
    ['http://schemas.xmlsoap.org/claims/samaccountname', 'sAMAccountName', a.samAccountName || user.pid],
    ['http://schemas.xmlsoap.org/claims/haccpid', 'HACC PID', a.haccpid || ''],
    ['http://schemas.xmlsoap.org/claims/nameid', 'Name ID', a.nameId || ''],
    ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn', 'UPN', a.upn || ''],
    ['http://schemas.xmlsoap.org/claims/userprincipalname', 'UserPrincipalName', a.upn || ''],
    ['http://schemas.xmlsoap.org/claims/firstname', 'FirstName', a.firstName || ''],
    ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', 'Given Name', a.firstName || ''],
    ['http://schemas.xmlsoap.org/claims/lastname', 'LastName', a.lastName || ''],
    ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname', 'Surname', a.lastName || ''],
    ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', 'EmailAddress', a.email || ''],
    ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', 'Name', a.name || user.pid],
    ['http://schemas.xmlsoap.org/claims/fullname', 'Full Name', a.fullName || user.pid],
    ['http://schemas.microsoft.com/2012/01/devicecontext/claims/displayname', 'displayName', a.displayName || user.pid],
    ['http://schemas.xmlsoap.org/claims/dealercode', 'DealerCode', a.dealerCode || ''],
    ['http://schemas.xmlsoap.org/claims/hac/dealercode', 'HAC/DealerCode', a.hacDealerCode || ''],
    ['http://hyundaicanada.com/physicalDeliveryOfficeName', 'PhysicalDeliveryOfficeName', a.physicalDeliveryOffice || ''],
    ['http://schemas.xmlsoap.org/claims/department', 'department', a.department || ''],
    ['http://schemas.xmlsoap.org/claims/position', 'Position', a.position || ''],
    ['http://schemas.xmlsoap.org/claims/company', 'Company', a.company || ''],
    ['http://schemas.xmlsoap.org/claims/dealerrole', 'Dealer Role', a.dealerRole || ''],
    ['http://schemas.xmlsoap.org/claims/dealerrolecode', 'DealerRoleCode', a.dealerRoleCode || ''],
    ['http://schemas.xmlsoap.org/claims/hac/rolecode', 'HAC/RoleCode', a.hacRoleCode || ''],
    ['http://schemas.xmlsoap.org/claims/hac/title', 'HAC/Title', a.hacTitle || user.pid],
    ['http://schemas.xmlsoap.org/claims/title', 'Title', a.title || user.pid],
    ['http://schemas.xmlsoap.org/claims/zone', 'Zone', a.zone || ''],
    ['http://schemas.xmlsoap.org/claims/hac/zone', 'HAC/Zone', a.hacZone || ''],
    ['http://schemas.xmlsoap.org/claims/zonecode', 'ZoneCode', a.zoneCode || ''],
    ['http://schemas.xmlsoap.org/claims/co', 'Co', a.co || ''],
    ['http://schemas.xmlsoap.org/claims/district', 'District', a.district || ''],
    ['http://schemas.xmlsoap.org/claims/userlevel', 'User Level', a.userLevel || ''],
    ['http://hyundaicanada.com/Language', 'Language', a.language || ''],
    ['http://schemas.xmlsoap.org/claims/telephonenumber', 'telephoneNumber', a.phone || ''],
    ['http://schemas.xmlsoap.org/claims/hac/email', 'HAC/E-Mail', a.hacEmail || ''],
    ['http://schemas.xmlsoap.org/claims/url', 'Url', a.url || ''],
  ];

  let xml = '';
  for (const [name, friendly, value] of attrEntries) {
    xml += `<saml2:Attribute FriendlyName="${friendly}" Name="${name}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">${escapeXml(value)}</saml2:AttributeValue></saml2:Attribute>`;
  }

  // Multi-value: Role
  if (a.roles && a.roles.length > 0) {
    xml += `<saml2:Attribute FriendlyName="Role" Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">`;
    for (const role of a.roles) {
      xml += `<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">${escapeXml(role)}</saml2:AttributeValue>`;
    }
    xml += `</saml2:Attribute>`;
  }

  // Multi-value: memberOf
  if (a.memberOf && a.memberOf.length > 0) {
    xml += `<saml2:Attribute FriendlyName="memberOf" Name="http://schemas.xmlsoap.org/claims/memberOf" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">`;
    for (const m of a.memberOf) {
      xml += `<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">${escapeXml(m)}</saml2:AttributeValue>`;
    }
    xml += `</saml2:Attribute>`;
  }

  return xml;
}

function buildLoginPage(sessionId, error) {
  const errorHtml = error
    ? `<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:10px;margin-bottom:16px;color:#856404;font-size:13px;"><strong>Error:</strong> ${escapeHtml(error)}</div>`
    : '';
  return `<!DOCTYPE html>
<html><head><title>Partner ID — Login (Mock)</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 400px; margin: 60px auto; padding: 20px; background: #f8f9fa; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 24px; }
  h2 { margin-top: 0; color: #003087; border-bottom: 2px solid #003087; padding-bottom: 8px; }
  .badge { display: inline-block; background: #2e7d32; color: #fff; padding: 3px 10px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-bottom: 12px; }
  input { width: 100%; padding: 10px; margin: 6px 0 12px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
  button { width: 100%; padding: 12px; background: #2e7d32; color: #fff; border: none; border-radius: 4px; font-size: 15px; font-weight: 600; cursor: pointer; }
  button:hover { background: #1b5e20; }
  .users { margin-top: 16px; font-size: 12px; color: #666; }
  .users code { background: #e9ecef; padding: 1px 5px; border-radius: 3px; }
</style></head>
<body>
  <div class="card">
    <span class="badge">MOCK PID</span>
    <h2>Partner ID Login</h2>
    <p style="font-size:13px;color:#666;">Emulates <code>stg-partner.hmg-corp.io/auth/login</code></p>
    ${errorHtml}
    <form method="post" action="${PID_PUBLIC_URL}/auth/login">
      <input type="hidden" name="session" value="${escapeHtml(sessionId)}">
      <label style="font-size:13px;font-weight:600;">Username</label>
      <input name="username" placeholder="e.g. test0901, dealer.ca01, corp.hq01" required autofocus>
      <label style="font-size:13px;font-weight:600;">Password</label>
      <input name="password" type="password" placeholder="any password" value="Test1234!">
      <button type="submit">Sign In via PID</button>
    </form>
    <div class="users">
      <strong>Test users:</strong><br>
      <code>test0901</code> — SAML trace baseline (HAEA, CMS, Perf Academy)<br>
      <code>dealer.ca01</code> — Dealer with full attributes (ON-1234)<br>
      <code>corp.hq01</code> — Corporate HQ admin
    </div>
  </div>
</body></html>`;
}

function escapeXml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function generateSelfSignedCert() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certObj = forge.pki.createCertificate();
  certObj.publicKey = keys.publicKey;
  certObj.serialNumber = '01';
  certObj.validity.notBefore = new Date();
  certObj.validity.notAfter = new Date();
  certObj.validity.notAfter.setFullYear(certObj.validity.notBefore.getFullYear() + 30);

  const attrs = [
    { name: 'countryName', value: 'KR' },
    { name: 'stateOrProvinceName', value: 'Seoul' },
    { name: 'localityName', value: 'Gangnam' },
    { name: 'organizationName', value: 'HMG' },
    { shortName: 'CN', value: 'partner.hmg-corp.io' },
  ];
  certObj.setSubject(attrs);
  certObj.setIssuer(attrs);
  certObj.sign(keys.privateKey, forge.md.sha256.create());

  return {
    cert: forge.pki.certificateToPem(certObj),
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

// ─── OIDC Mode Endpoints ─────────────────────────────────────────────
// When the broker sends ?protocol=oidc, PID acts as an OIDC provider instead of SAML.
// This simulates PID returning an id_token + access_token via authorization code flow.

const oidcPendingCodes = new Map();

// OIDC Authorization endpoint
app.get('/auth/oidc/authorize', (req, res) => {
  const { client_id, redirect_uri, state, nonce, scope } = req.query;
  const sessionId = crypto.randomUUID();

  oidcPendingCodes.set(sessionId, { client_id, redirect_uri, state, nonce, scope });

  res.setHeader('Set-Cookie', `PID_OIDC_SESSION=${sessionId}; Path=/; HttpOnly`);
  res.redirect(`${PID_PUBLIC_URL}/auth/oidc/login?session=${sessionId}`);
});

// OIDC Login page
app.get('/auth/oidc/login', (req, res) => {
  const sessionId = req.query.session || '';
  const error = req.query.error || '';
  const errorHtml = error
    ? `<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:10px;margin-bottom:16px;color:#856404;font-size:13px;"><strong>Error:</strong> ${escapeHtml(error)}</div>`
    : '';
  res.send(`<!DOCTYPE html>
<html><head><title>Partner ID — OIDC Login (Mock)</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 400px; margin: 60px auto; padding: 20px; background: #f8f9fa; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 24px; }
  h2 { margin-top: 0; color: #003087; border-bottom: 2px solid #003087; padding-bottom: 8px; }
  .badge { display: inline-block; background: #1976d2; color: #fff; padding: 3px 10px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-bottom: 12px; }
  input { width: 100%; padding: 10px; margin: 6px 0 12px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
  button { width: 100%; padding: 12px; background: #1976d2; color: #fff; border: none; border-radius: 4px; font-size: 15px; font-weight: 600; cursor: pointer; }
  button:hover { background: #1565c0; }
  .users { margin-top: 16px; font-size: 12px; color: #666; }
  .users code { background: #e9ecef; padding: 1px 5px; border-radius: 3px; }
</style></head>
<body>
  <div class="card">
    <span class="badge">MOCK PID — OIDC MODE</span>
    <h2>Partner ID Login</h2>
    <p style="font-size:13px;color:#666;">OIDC authorization code flow</p>
    ${errorHtml}
    <form method="post" action="${PID_PUBLIC_URL}/auth/oidc/login">
      <input type="hidden" name="session" value="${escapeHtml(sessionId)}">
      <label style="font-size:13px;font-weight:600;">Username</label>
      <input name="username" placeholder="e.g. dealer.ca01" required autofocus>
      <label style="font-size:13px;font-weight:600;">Password</label>
      <input name="password" type="password" placeholder="any password" value="Test1234!">
      <button type="submit">Sign In (OIDC)</button>
    </form>
    <div class="users">
      <strong>Test users:</strong><br>
      <code>test0901</code> — HAEA, CMS, Perf Academy<br>
      <code>dealer.ca01</code> — Dealer with full attributes<br>
      <code>corp.hq01</code> — Corporate HQ admin
    </div>
  </div>
</body></html>`);
});

// OIDC Login submit — generates auth code and redirects back to broker
app.post('/auth/oidc/login', (req, res) => {
  const { username, session } = req.body;

  if (!session || !oidcPendingCodes.has(session)) {
    return res.redirect(`${PID_PUBLIC_URL}/auth/oidc/login?error=invalid_session`);
  }

  const user = TEST_USERS[username];
  if (!user) {
    return res.redirect(`${PID_PUBLIC_URL}/auth/oidc/login?session=${session}&error=user_not_found`);
  }

  const pending = oidcPendingCodes.get(session);
  const code = crypto.randomUUID();

  // Store the code → user mapping for the token exchange
  oidcPendingCodes.set(code, { ...pending, user, username });
  oidcPendingCodes.delete(session);

  // Report to dashboard
  const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://flow-dashboard:3007';
  try {
    const http = require('http');
    const dashBody = JSON.stringify({
      flowId: pending.state,
      flowType: 'idp-initiated',
      step: 4,
      stepName: 'PID_AUTHENTICATES_USER_OIDC',
      service: 'pid',
      description: `User "${username}" authenticated at PID (OIDC mode). PID verified identity and generated authorization code. Redirecting back to Broker callback with code + state.`,
      detail: { username, pid: user.pid, protocol: 'oidc', code: code.substring(0, 8) + '...' },
    });
    const dUrl = new URL(DASHBOARD_URL + '/api/event');
    const dr = http.request({ hostname: dUrl.hostname, port: dUrl.port, path: dUrl.pathname, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(dashBody) } });
    dr.on('error', () => {});
    dr.write(dashBody);
    dr.end();
  } catch (_) {}

  // Redirect back to broker with auth code
  const redirectUrl = `${pending.redirect_uri}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(pending.state)}`;
  res.redirect(redirectUrl);
});

// OIDC Token endpoint — exchanges auth code for id_token + access_token
app.post('/auth/oidc/token', (req, res) => {
  const { code, grant_type } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const pending = oidcPendingCodes.get(code);
  if (!pending || !pending.user) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired code' });
  }

  oidcPendingCodes.delete(code);
  const user = pending.user;
  const a = user.attributes || {};

  // Build a JWT id_token (unsigned for POC)
  const now = Math.floor(Date.now() / 1000);
  const idTokenPayload = {
    iss: PID_ISSUER,
    sub: user.pid,
    aud: pending.client_id,
    exp: now + 3600,
    iat: now,
    nonce: pending.nonce,
    preferred_username: user.pid,
    name: a.fullName || user.pid,
    email: a.email || '',
    given_name: a.firstName || '',
    family_name: a.lastName || '',
    // PID-specific claims
    pid: user.pid,
    hmgpid: a.hmgpid || '',
    dealer_code: a.dealerCode || '',
    roles: a.roles || [],
    member_of: a.memberOf || [],
    zone: a.zone || '',
    company: a.company || '',
    department: a.department || '',
  };

  // Simple base64 JWT (no signature — POC)
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(idTokenPayload)).toString('base64url');
  const idToken = `${header}.${payload}.`;

  res.json({
    access_token: 'pid-access-' + crypto.randomUUID(),
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken,
    scope: pending.scope || 'openid profile email',
  });
});

// OIDC Discovery endpoint
app.get('/auth/oidc/.well-known/openid-configuration', (_req, res) => {
  res.json({
    issuer: PID_ISSUER,
    authorization_endpoint: `${PID_PUBLIC_URL}/auth/oidc/authorize`,
    token_endpoint: `${PID_PUBLIC_URL}/auth/oidc/token`,
    jwks_uri: `${PID_PUBLIC_URL}/auth/oidc/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['none'],
    scopes_supported: ['openid', 'profile', 'email'],
    claims_supported: ['sub', 'preferred_username', 'name', 'email', 'pid', 'hmgpid', 'dealer_code', 'roles'],
  });
});

app.get('/auth/oidc/jwks', (_req, res) => {
  res.json({ keys: [] }); // No signing in POC
});

// ─── Portal Login via PID ─────────────────────────────────────────────
// The Dealers Portal redirects here for initial login. PID authenticates
// the user and creates a PID session, then redirects back to the portal.
const pidSessions = new Map(); // cookie → { user, username, loginTime }

app.get('/auth/portal-login', (req, res) => {
  const returnUrl = req.query.return_url || 'http://portal.sso.test:8000';
  const dashboard = req.query.dashboard || '';
  const flowId = req.query.flowId || '';

  // Check if user already has a PID session
  const sessionId = req.headers.cookie?.match(/PID_SESSION=([^;]+)/)?.[1];
  if (sessionId && pidSessions.has(sessionId)) {
    return res.redirect(returnUrl + (dashboard ? '?dashboard=1' : ''));
  }

  res.send(`<!DOCTYPE html>
<html><head><title>Partner ID — Portal Login</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 400px; margin: 60px auto; padding: 20px; background: #f8f9fa; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 24px; }
  h2 { margin-top: 0; color: #003087; border-bottom: 2px solid #003087; padding-bottom: 8px; }
  .badge { display: inline-block; background: #2e7d32; color: #fff; padding: 3px 10px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-bottom: 12px; }
  input { width: 100%; padding: 10px; margin: 6px 0 12px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
  button { width: 100%; padding: 12px; background: #2e7d32; color: #fff; border: none; border-radius: 4px; font-size: 15px; font-weight: 600; cursor: pointer; }
  button:hover { background: #1b5e20; }
  .users { margin-top: 16px; font-size: 12px; color: #666; }
  .users code { background: #e9ecef; padding: 1px 5px; border-radius: 3px; }
</style></head>
<body>
  <div class="card">
    <span class="badge">PID — PORTAL LOGIN</span>
    <h2>Partner ID Login</h2>
    <p style="font-size:13px;color:#666;">Authenticate to access the Dealers Portal</p>
    <form method="post" action="${PID_PUBLIC_URL}/auth/portal-login">
      <input type="hidden" name="return_url" value="${escapeHtml(returnUrl)}">
      <input type="hidden" name="dashboard" value="${escapeHtml(dashboard)}">
      <input type="hidden" name="flowId" value="${escapeHtml(flowId)}">
      <label style="font-size:13px;font-weight:600;">Username</label>
      <input name="username" placeholder="e.g. dealer.ca01" required autofocus>
      <label style="font-size:13px;font-weight:600;">Password</label>
      <input name="password" type="password" placeholder="any password" value="Test1234!">
      <button type="submit">Sign In via PID</button>
    </form>
    <div class="users">
      <strong>Test users:</strong><br>
      <code>test0901</code> — HAEA, CMS, Perf Academy<br>
      <code>dealer.ca01</code> — Dealer with full attributes (ON-1234)<br>
      <code>corp.hq01</code> — Corporate HQ admin
    </div>
  </div>
</body></html>`);
});

app.post('/auth/portal-login', (req, res) => {
  const { username, return_url, dashboard, flowId: formFlowId } = req.body;
  const returnUrl = return_url || 'http://portal.sso.test:8000';

  const user = TEST_USERS[username];
  if (!user) {
    return res.redirect(`${PID_PUBLIC_URL}/auth/portal-login?return_url=${encodeURIComponent(returnUrl)}&dashboard=${dashboard || ''}&error=user_not_found`);
  }

  // Create PID session
  const sessionId = crypto.randomUUID();
  pidSessions.set(sessionId, { user, username, loginTime: Date.now() });

  // Use the portal's flowId so login appears as one flow
  const flowId = formFlowId || 'login-' + sessionId.substring(0, 8);

  // Emit to dashboard
  const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://flow-dashboard:3007';
  try {
    const http = require('http');
    const dashBody = JSON.stringify({
      flowId,
      flowType: 'idp-initiated', flowName: 'Dealer Portal Login',
      step: 2, stepName: 'PID_AUTHENTICATES_USER', service: 'pid',
      description: `User "${username}" authenticated at PID. PID created session and is redirecting back to Dealers Portal.`,
      detail: { username, pid: user.pid, sessionId: sessionId.substring(0, 8) },
    });
    const dUrl = new URL(DASHBOARD_URL + '/api/event');
    const dr = http.request({ hostname: dUrl.hostname, port: dUrl.port, path: dUrl.pathname, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(dashBody) } });
    dr.on('error', () => {});
    dr.write(dashBody);
    dr.end();
  } catch (_) {}

  // Set PID session cookie and redirect back to portal
  const dashParam = dashboard === '1' ? '?dashboard=1&flowId=' + encodeURIComponent(flowId) : '';
  res.setHeader('Set-Cookie', `PID_SESSION=${sessionId}; Path=/; HttpOnly; Domain=.sso.test`);
  res.redirect(returnUrl + dashParam);
});

// ─── Launch Token Endpoints (PDF: IdP-Initiated SSO Design) ─────────
// Two endpoints implement the PDF flow:
//   POST /api/launch-token        — Steps 2-4: server-to-server, Dealers → PID
//   GET  /auth/launch-validate    — Steps 6-8: browser → PID → Broker
//
// In production, swap the in-memory map for Redis and the unsigned token
// for a real signed JWT (RS256, with kid pointing at PID's JWKS).
const launchTokens = new Map(); // jti → { user_id, target_vendor, source_system, iat, exp, jti, pid_claims }

const DEALERS_API_KEY = process.env.DEALERS_API_KEY || 'poc-dealers-api-key';
const ALLOWED_CLIENTS = new Set(['hmg-admin-partner']);
const ALLOWED_SOURCES = new Set(['dealers']);
const LAUNCH_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 min — short-lived per OAuth BCP RFC 9700 §4.10
const BROKER_PUBLIC_URL_FOR_PID = process.env.BROKER_PUBLIC_URL || 'http://broker.sso.test:8000';
const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://flow-dashboard:3007';

// Cleanup expired launch tokens
setInterval(() => {
  const now = Date.now();
  for (const [jti, data] of launchTokens) {
    if (now > data.exp) launchTokens.delete(jti);
  }
}, 30_000).unref();

function emitDashboardEvent(payload) {
  try {
    const http = require('http');
    const body = JSON.stringify(payload);
    const u = new URL(DASHBOARD_URL + '/api/event');
    const r = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    });
    r.on('error', () => {});
    r.write(body);
    r.end();
  } catch (_) {}
}

function encodeLaunchToken(claims) {
  // Unsigned JWT-shaped token for POC. Production: sign RS256 with kid header
  // and publish key via /auth/oidc/jwks so broker can verify locally.
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${header}.${payload}.`;
}

// ─── PDF Steps 2-4: Dealers → PID server-to-server launch token issuance
// Headers required: X-Client-Id, X-Source-System, X-Api-Key
// Body: { target_vendor, user_id, request_id, flow_id? }
app.post('/api/launch-token', express.json(), (req, res) => {
  const clientId = req.headers['x-client-id'];
  const sourceSystem = req.headers['x-source-system'];
  const apiKey = req.headers['x-api-key'];
  const { target_vendor, user_id, request_id, flow_id } = req.body || {};
  const flowId = flow_id || ('sso-' + (request_id ? String(request_id).substring(0, 8) : crypto.randomUUID().substring(0, 8)));

  // Step 3: validate API key + policy
  if (apiKey !== DEALERS_API_KEY) {
    emitDashboardEvent({
      flowId, flowType: 'idp-initiated', step: 3,
      stepName: 'PID_REJECTS_API_KEY', service: 'pid',
      description: `PID rejected the launch-token request: invalid X-Api-Key from client "${clientId || 'missing'}".`,
      detail: { reason: 'INVALID_API_KEY', clientId, sourceSystem },
    });
    return res.status(401).json({ error: 'INVALID_API_KEY' });
  }
  if (!ALLOWED_CLIENTS.has(clientId)) {
    emitDashboardEvent({
      flowId, flowType: 'idp-initiated', step: 3,
      stepName: 'PID_REJECTS_CLIENT', service: 'pid',
      description: `PID rejected the launch-token request: client "${clientId}" not in allowlist.`,
      detail: { reason: 'CLIENT_NOT_ALLOWED', clientId },
    });
    return res.status(403).json({ error: 'CLIENT_NOT_ALLOWED' });
  }
  if (!ALLOWED_SOURCES.has(sourceSystem)) {
    emitDashboardEvent({
      flowId, flowType: 'idp-initiated', step: 3,
      stepName: 'PID_REJECTS_SOURCE', service: 'pid',
      description: `PID rejected the launch-token request: source system "${sourceSystem}" not in allowlist.`,
      detail: { reason: 'SOURCE_NOT_ALLOWED', sourceSystem },
    });
    return res.status(403).json({ error: 'SOURCE_NOT_ALLOWED' });
  }
  if (!target_vendor || !user_id || !request_id) {
    return res.status(400).json({ error: 'MISSING_FIELDS', required: ['target_vendor', 'user_id', 'request_id'] });
  }

  // Lookup the user so we can attach PID base claims to the token
  const user = TEST_USERS[user_id];
  if (!user) {
    emitDashboardEvent({
      flowId, flowType: 'idp-initiated', step: 3,
      stepName: 'PID_REJECTS_USER_UNKNOWN', service: 'pid',
      description: `PID rejected the launch-token request: user "${user_id}" not known to PID.`,
      detail: { reason: 'USER_NOT_FOUND', user_id },
    });
    return res.status(404).json({ error: 'USER_NOT_FOUND' });
  }

  emitDashboardEvent({
    flowId, flowType: 'idp-initiated', flowName: `SSO → ${target_vendor}`, step: 3,
    stepName: 'PID_VALIDATES_API_KEY', service: 'pid',
    description: `PID validated the launch-token request from "${clientId}" / "${sourceSystem}" for user "${user_id}" → vendor "${target_vendor}". Request authorized.`,
    httpRequest: {
      method: 'POST', url: '/api/launch-token',
      headers: { 'X-Client-Id': clientId, 'X-Source-System': sourceSystem, 'X-Api-Key': '[REDACTED]' },
      body: { target_vendor, user_id, request_id },
    },
    detail: { clientId, sourceSystem, target_vendor, user_id, request_id },
  });

  // Step 4: issue one-time launch token
  const jti = crypto.randomUUID();
  const iat = Date.now();
  const exp = iat + LAUNCH_TOKEN_TTL_MS;
  const claims = {
    jti, iat, exp,
    iss: PID_PUBLIC_URL,
    aud: BROKER_PUBLIC_URL_FOR_PID,
    user_id,
    target_vendor,
    source_system: sourceSystem,
    request_id,
    pid_claims: {
      pid: user.pid,
      hmgpid: user.attributes?.hmgpid || '',
      dealer_code: user.attributes?.dealerCode || '',
      roles: user.attributes?.roles || [],
    },
  };
  launchTokens.set(jti, { ...claims, consumed: false });
  const launchToken = encodeLaunchToken(claims);

  emitDashboardEvent({
    flowId, flowType: 'idp-initiated', step: 4,
    stepName: 'PID_ISSUES_LAUNCH_TOKEN', service: 'pid',
    description: `PID issued a one-time launch token (jti=${jti.substring(0, 8)}..., TTL ${LAUNCH_TOKEN_TTL_MS / 60000} min). Returned to Dealers; Dealers will now redirect the browser to PID's launch endpoint.`,
    tokenPayload: {
      jti: jti.substring(0, 12) + '...', user_id, target_vendor, source_system: sourceSystem,
      iss: claims.iss, aud: claims.aud,
      exp: new Date(exp).toISOString(), pid_claims: claims.pid_claims,
    },
    detail: { jti: jti.substring(0, 12) + '...', ttl_minutes: LAUNCH_TOKEN_TTL_MS / 60000 },
  });

  return res.json({ launch_token: launchToken, jti, iat, exp, flow_id: flowId });
});

// ─── PDF Steps 6-8: Browser → PID launch endpoint → Broker
// Validates the launch token (expiry + one-time use + claim shape) and
// redirects the browser to the Broker. The same token rides along.
app.get('/auth/launch-validate', (req, res) => {
  const tokenString = req.query.token || '';
  const dashboard = req.query.dashboard || '';
  const queryFlowId = req.query.flow_id || '';

  if (!tokenString) return res.status(400).send('Missing token');

  // Decode (POC: alg=none). Production: jwt.verify against PID's signing key.
  let claims;
  try {
    const parts = String(tokenString).split('.');
    if (parts.length < 2) throw new Error('bad token format');
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch (err) {
    return res.status(400).send('Invalid token: ' + err.message);
  }

  const flowId = queryFlowId || ('sso-' + (claims.jti ? claims.jti.substring(0, 8) : crypto.randomUUID().substring(0, 8)));

  // Step 6: browser hit PID's launch endpoint
  emitDashboardEvent({
    flowId, flowType: 'idp-initiated', step: 6,
    stepName: 'BROWSER_HITS_PID_LAUNCH', service: 'pid',
    description: 'Browser arrived at PID launch endpoint with the launch token issued in step 4. PID will validate it.',
    httpRequest: { method: 'GET', url: '/auth/launch-validate', query: { token: tokenString.substring(0, 30) + '...' } },
  });

  // Step 7: validate the token (expiry, one-time use, required claims)
  const stored = launchTokens.get(claims.jti);
  if (!stored) {
    emitDashboardEvent({
      flowId, flowType: 'idp-initiated', step: 7,
      stepName: 'LAUNCH_TOKEN_INVALID', service: 'pid',
      description: `PID rejected the launch token: jti not found (forged or already validated by PID).`,
      detail: { reason: 'JTI_NOT_FOUND' },
    });
    return res.status(401).send('Launch token invalid: jti not found');
  }
  if (stored.consumed) {
    emitDashboardEvent({
      flowId, flowType: 'idp-initiated', step: 7,
      stepName: 'LAUNCH_TOKEN_REPLAYED', service: 'pid',
      description: `PID rejected the launch token: jti=${claims.jti.substring(0, 8)}... already consumed (replay attempt blocked).`,
      detail: { reason: 'TOKEN_REPLAYED' },
    });
    return res.status(401).send('Launch token already used');
  }
  if (Date.now() > stored.exp) {
    launchTokens.delete(claims.jti);
    emitDashboardEvent({
      flowId, flowType: 'idp-initiated', step: 7,
      stepName: 'LAUNCH_TOKEN_EXPIRED', service: 'pid',
      description: `PID rejected the launch token: expired (exp ${new Date(stored.exp).toISOString()}).`,
    });
    return res.status(401).send('Launch token expired');
  }
  if (!stored.user_id || !stored.target_vendor) {
    emitDashboardEvent({
      flowId, flowType: 'idp-initiated', step: 7,
      stepName: 'LAUNCH_TOKEN_MALFORMED', service: 'pid',
      description: `PID rejected the launch token: missing user_id or target_vendor claim.`,
    });
    return res.status(401).send('Launch token missing required claims');
  }

  // Mark consumed (one-time use). Broker will also call /auth/validate-launch-token
  // for defense in depth; either gate is sufficient.
  stored.consumed = true;
  launchTokens.set(claims.jti, stored);

  emitDashboardEvent({
    flowId, flowType: 'idp-initiated', step: 7,
    stepName: 'LAUNCH_TOKEN_VALIDATED', service: 'pid',
    description: `PID validated the launch token: signature OK, not expired, not previously consumed, user_id and target_vendor present. Marked consumed.`,
    tokenPayload: {
      jti: stored.jti.substring(0, 12) + '...', user_id: stored.user_id, target_vendor: stored.target_vendor,
      source_system: stored.source_system, exp: new Date(stored.exp).toISOString(),
    },
  });

  // Step 8: redirect browser to Broker with the launch token
  const dashParam = dashboard === '1' ? '&dashboard=1' : '';
  const brokerUrl = `${BROKER_PUBLIC_URL_FOR_PID}/sso/receive?launch_token=${encodeURIComponent(tokenString)}&flow_id=${encodeURIComponent(flowId)}${dashParam}`;

  emitDashboardEvent({
    flowId, flowType: 'idp-initiated', step: 8,
    stepName: 'PID_REDIRECTS_TO_BROKER', service: 'pid',
    description: 'PID redirecting the browser to the Broker Service with the launch token.',
    redirect: { description: 'Browser → Broker /sso/receive', url: BROKER_PUBLIC_URL_FOR_PID + '/sso/receive' },
  });

  if (dashboard === '1') {
    return res.send(`<!DOCTYPE html><html><head><title>PID → Broker</title>
<style>body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;max-width:500px;text-align:center}h2{margin-top:0;color:#81c784}.step-badge{display:inline-block;background:#2e7d32;color:#fff;padding:2px 10px;border-radius:3px;font-size:12px;font-weight:700;margin-bottom:12px}.url{font-family:monospace;font-size:11px;color:#8b949e;background:#1c2128;padding:8px 12px;border-radius:6px;margin:12px 0;word-break:break-all}.countdown{font-size:48px;font-weight:700;color:#81c784;margin:16px 0}.btn{display:inline-block;padding:12px 32px;background:#2e7d32;color:#fff;border:none;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;text-decoration:none}.btn-secondary{background:transparent;border:1px solid #30363d;color:#8b949e;font-size:13px;padding:8px 16px;margin-top:12px;display:inline-block;text-decoration:none}</style></head><body>
<div class="card"><div class="step-badge">STEP 8 — PID → BROKER</div><h2>Redirecting to Broker Service</h2><p>PID validated the launch token for "${escapeHtml(stored.user_id)}" → "${escapeHtml(stored.target_vendor)}". Redirecting browser to Broker.</p><div class="url">→ broker.sso.test:8000/sso/receive?launch_token=...</div><div class="countdown" id="cd">5</div><a class="btn" href="${brokerUrl}">Continue to Broker →</a><br><a class="btn-secondary" href="http://dashboard.sso.test:8000">← Dashboard</a></div>
<script>let s=5;const c=document.getElementById('cd');const t=setInterval(()=>{s--;c.textContent=s;if(s<=0){clearInterval(t);window.location.href='${brokerUrl}';}},1000);</script></body></html>`);
  }

  return res.redirect(brokerUrl);
});

// Session info endpoint — portal calls this to get the logged-in user
app.get('/auth/session-info', (req, res) => {
  const sessionId = req.headers.cookie?.match(/PID_SESSION=([^;]+)/)?.[1];
  if (!sessionId || !pidSessions.has(sessionId)) {
    return res.status(401).json({ error: 'NO_SESSION' });
  }
  const session = pidSessions.get(sessionId);
  res.json({ username: session.username, pid: session.user.pid, loginTime: session.loginTime });
});

// Launch token validation endpoint (called by Broker internally)
app.post('/auth/validate-launch-token', (req, res) => {
  const { jti } = req.body;
  if (!jti || !launchTokens.has(jti)) {
    return res.status(401).json({ valid: false, error: 'INVALID_OR_EXPIRED_TOKEN' });
  }
  const token = launchTokens.get(jti);
  if (Date.now() > token.exp) {
    launchTokens.delete(jti);
    return res.status(401).json({ valid: false, error: 'TOKEN_EXPIRED' });
  }
  // One-time use — delete after validation
  launchTokens.delete(jti);
  return res.json({ valid: true, ...token });
});

app.listen(PORT, () => console.log(`mock-pid (Partner ID) :${PORT}`));
