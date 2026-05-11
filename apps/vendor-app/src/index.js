const crypto = require('crypto');
const express = require('express');
const { emit } = require('./dashboard');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const BROKER_URL = process.env.BROKER_URL || 'http://iam-broker:3003';
const BROKER_PUBLIC_URL = process.env.BROKER_PUBLIC_URL || 'http://broker.sso.test:8000';
const VENDOR_PUBLIC_URL = process.env.VENDOR_PUBLIC_URL || 'http://vendor.sso.test:8000';
const AES_KEY = process.env.AES256_SHARED_KEY || 'poc-aes256-key-must-be-32bytes!';
const RC4_KEY = process.env.RC4_SHARED_KEY || 'poc-rc4-shared-key';

// Extract flowId from the token if it was embedded, or generate one
function getFlowId(body) {
  return body._flowId || 'vendor-' + crypto.randomUUID().substring(0, 8);
}

function renderResult(res, format, status, data, opts = {}) {
  const statusColor = status === 'success' ? '#2e7d32' : '#c62828';
  const html = `<!DOCTYPE html>
<html><head><title>Vendor App — ${format} SSO</title>
<style>
  body { font-family: sans-serif; max-width: 700px; margin: 40px auto; padding: 20px; }
  .card { border: 1px solid #ddd; border-radius: 6px; padding: 20px; margin: 16px 0; }
  .status { display: inline-block; padding: 4px 12px; border-radius: 3px; color: #fff; background: ${statusColor}; font-weight: bold; }
  pre { background: #f5f5f5; padding: 12px; border-radius: 4px; overflow: auto; font-size: 12px; }
  h1 { border-bottom: 2px solid #e50000; padding-bottom: 10px; }
</style></head><body>
<h1>Vendor App — ${format.toUpperCase()} SSO Result</h1>
<div class="card">
  <p>Token Format: <strong>${format}</strong></p>
  <p>Validation: <span class="status">${status}</span></p>
  ${opts.sourceSystem ? '<p>Source: <strong>' + opts.sourceSystem + '</strong></p>' : ''}
</div>
<div class="card">
  <h3>Decoded User Info</h3>
  <pre>${JSON.stringify(data, null, 2)}</pre>
</div>
<p><a href="/">Back to info page</a> | <a href="http://portal.sso.test">Back to Portal</a></p>
</body></html>`;
  res.send(html);
}

// CSRF validation — consumes nonce via broker /token/consume
async function validateCsrf(nonce) {
  if (!nonce) return false;
  try {
    const fetch = (await import('node-fetch')).default;
    const res = await fetch(`${BROKER_URL}/token/consume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: nonce }),
    });
    return res.ok;
  } catch (_) {
    return false;
  }
}

// Health check
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── SP-Initiated Direct Access Routes ───────────────────────────────
// These simulate "App direct access → redirect to IdP broker" (Andy's directive)
// When a user hits a vendor app URL directly without a session/token,
// the vendor redirects them to the IAM Broker's SAML login endpoint.

app.get('/app/haea', (req, res) => {
  const isDashboard = req.query.dashboard === '1';
  res.send(buildRedirectPage('HAEA Portal', 'vendor-igtk', 'The HAEA Dealer Portal', isDashboard));
});

app.get('/app/dealer-cms', (req, res) => {
  const isDashboard = req.query.dashboard === '1';
  res.send(buildRedirectPage('Dealer CMS', 'vendor-saml', 'Dealer Content Management System', isDashboard));
});

app.get('/app/parts', (req, res) => {
  const isDashboard = req.query.dashboard === '1';
  res.send(buildRedirectPage('MOBIS Parts', 'vendor-wpc', 'WPC MOBIS Parts Ordering', isDashboard));
});

function buildRedirectPage(appName, targetSystem, description, isDashboard) {
  const dashParam = isDashboard ? '&dashboard=1' : '';
  const loginUrl = `${BROKER_PUBLIC_URL}/saml/login?target=${encodeURIComponent(targetSystem)}&return_url=${encodeURIComponent(VENDOR_PUBLIC_URL)}${dashParam}`;

  // Emit SP-Initiated Step 1 to dashboard
  const flowId = 'sp-' + Date.now();
  emit({
    flowId, flowType: 'sp-initiated', step: 1,
    stepName: 'VENDOR_NO_SESSION', service: 'vendor',
    description: `User navigated directly to "${appName}" (${VENDOR_PUBLIC_URL}/app/...) without an active session. The vendor app detected no authentication and will redirect to the IAM Broker for PID authentication. This is the SP-Initiated flow.`,
    detail: { appName, targetSystem, vendorUrl: VENDOR_PUBLIC_URL },
    redirect: { description: 'Vendor redirects to Broker /saml/login', url: loginUrl },
  });

  // If from dashboard, show redirect gate with delay
  if (isDashboard) {
    return `<!DOCTYPE html>
<html><head><title>${appName} — Redirecting...</title>
<style>
  body { font-family: -apple-system, sans-serif; background: #0d1117; color: #e6edf3; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; max-width: 500px; text-align: center; }
  h2 { margin-top: 0; color: #64b5f6; }
  .step-badge { display: inline-block; background: #7b1fa2; color: #fff; padding: 2px 10px; border-radius: 3px; font-size: 12px; font-weight: 700; margin-bottom: 12px; }
  .url { font-family: monospace; font-size: 11px; color: #8b949e; background: #1c2128; padding: 8px 12px; border-radius: 6px; margin: 12px 0; word-break: break-all; }
  .countdown { font-size: 48px; font-weight: 700; color: #64b5f6; margin: 16px 0; }
  .btn { display: inline-block; padding: 12px 32px; background: #1976d2; color: #fff; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; text-decoration: none; }
  .btn:hover { background: #1565c0; }
  .btn-secondary { background: transparent; border: 1px solid #30363d; color: #8b949e; font-size: 13px; padding: 8px 16px; margin-top: 12px; }
</style></head><body>
<div class="card">
  <div class="step-badge">SP-INITIATED — STEP 1</div>
  <h2>${appName}</h2>
  <p>${description}</p>
  <p style="color:#f57c00;font-weight:600;">⚠️ No active session detected</p>
  <p style="font-size:13px;color:#8b949e;">Redirecting to IAM Broker for PID authentication...</p>
  <div class="url">→ broker.sso.test/saml/login?target=${targetSystem}</div>
  <div class="countdown" id="cd">5</div>
  <a class="btn" href="${loginUrl}">Redirect Now →</a>
  <br>
  <a class="btn btn-secondary" href="http://dashboard.sso.test:8000">← Back to Dashboard</a>
</div>
<script>
  let sec = 5;
  const cd = document.getElementById('cd');
  const timer = setInterval(() => {
    sec--;
    cd.textContent = sec;
    if (sec <= 0) { clearInterval(timer); window.location.href = '${loginUrl}'; }
  }, 1000);
</script>
</body></html>`;
  }

  // Original non-dashboard redirect page
  return `<!DOCTYPE html>
<html><head><title>${appName} — Redirecting...</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 500px; margin: 60px auto; padding: 20px; background: #f8f9fa; text-align: center; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 24px; }
  h2 { color: #003087; margin-top: 0; }
  .spinner { display: inline-block; width: 20px; height: 20px; border: 3px solid #ddd; border-top-color: #003087; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 8px; vertical-align: middle; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .tag { display: inline-block; padding: 3px 8px; background: #e50000; color: #fff; border-radius: 3px; font-size: 12px; font-weight: bold; }
  .step { text-align: left; padding: 6px 0; font-size: 13px; color: #666; }
  .step strong { color: #333; }
  code { background: #e9ecef; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
  .manual { margin-top: 16px; font-size: 12px; }
  .manual a { color: #003087; }
</style></head>
<body>
  <div class="card">
    <p><span class="tag">STEP 1</span></p>
    <h2>${appName}</h2>
    <p>${description}</p>
    <p><span class="spinner"></span> <strong>No active session detected.</strong></p>
    <p>Redirecting to IAM Broker for PID authentication...</p>
    <div class="step"><strong>From:</strong> <code>${VENDOR_PUBLIC_URL}/app/...</code></div>
    <div class="step"><strong>To:</strong> <code>broker.sso.test/saml/login?target=${targetSystem}</code></div>
    <div class="manual">
      Not redirecting? <a href="${loginUrl}">Click here</a> |
      <a href="http://dashboard.sso.test:8000">View flow dashboard</a>
    </div>
  </div>
<script>
// Auto-redirect to broker after a brief pause so user can see step 1
setTimeout(() => { window.location.href = '${loginUrl}'; }, 1500);
</script>
</body></html>`;
}

// Info page
app.get('/', (_req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Vendor App</title>
<style>body{font-family:sans-serif;max-width:600px;margin:40px auto;padding:20px;}h1{border-bottom:2px solid #e50000;padding-bottom:10px;}</style>
</head><body><h1>Vendor App :3005</h1>
<p>This simulates a 3rd party vendor application. Access via Portal SSO links.</p>
<h3>SSO Endpoints</h3>
<ul>
<li>POST /sso/igtk — IGTK JWT token (callback validation)</li>
<li>POST /sso/saml-acs — SAML 2.0 assertion</li>
<li>POST /sso/aes256 — AES-256-CBC encrypted token</li>
<li>POST /sso/rc4 — RC4 encrypted token (legacy)</li>
<li>POST /sso/wpc — WPC MOBIS OTP</li>
</ul></body></html>`);
});

// Helper: validate IGTK token and render result
async function handleIgtk(req, res, systemId) {
  const token = req.body.htxtToken;
  const csrfNonce = req.body.csrf_nonce;
  const flowId = req.body._flowId || 'igtk-' + Date.now();

  if (!token) return renderResult(res, 'igtk', 'error', { error: 'No htxtToken received' });

  // Step 10: Vendor validates CSRF nonce
  emit({
    flowId, flowType: 'idp-initiated', step: 15,
    stepName: 'VENDOR_VALIDATES_CSRF', service: 'vendor',
    description: `Vendor app "${systemId}" received POST with IGTK token + CSRF nonce. First validating the CSRF nonce by calling Broker POST /token/consume. This is a one-time check — the nonce is deleted after first use.`,
    httpRequest: { method: 'POST', url: `${BROKER_URL}/token/consume`, body: { id: csrfNonce } },
    detail: { systemId, csrf_nonce: csrfNonce, token_length: token.length },
  });

  if (!await validateCsrf(csrfNonce)) {
    emit({
      flowId, flowType: 'idp-initiated', step: 13.1,
      stepName: 'CSRF_VALIDATION_FAILED', service: 'vendor',
      description: 'CSRF nonce validation failed. The nonce was either invalid, expired (5-min TTL), or already consumed (replay attempt). SSO rejected.',
      httpResponse: { status: 'error', body: { error: 'CSRF validation failed' } },
    });
    return renderResult(res, 'igtk', 'error', { error: 'CSRF validation failed' });
  }

  emit({
    flowId, flowType: 'idp-initiated', step: 13.5,
    stepName: 'CSRF_VALIDATED', service: 'vendor',
    description: 'CSRF nonce consumed successfully. Nonce was valid and has been deleted from the registry (one-time use). Now validating the IGTK JWT token via callback.',
  });

  // Step 11: Vendor validates IGTK token via callback
  emit({
    flowId, flowType: 'idp-initiated', step: 16,
    stepName: 'VENDOR_VALIDATES_TOKEN', service: 'vendor',
    description: `Vendor calling Broker POST /token/validate with the IGTK JWT. Broker will verify signature (key: igtk-v1), check JTI in registry, check revocation status, and return decoded claims.`,
    httpRequest: { method: 'POST', url: `${BROKER_URL}/token/validate`, body: { token: token.substring(0, 50) + '...' } },
  });

  try {
    const fetch = (await import('node-fetch')).default;
    const valRes = await fetch(`${BROKER_URL}/token/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const data = await valRes.json();

    // Step 12: Token validation result
    emit({
      flowId, flowType: 'idp-initiated', step: 15,
      stepName: data.valid ? 'TOKEN_VALID' : 'TOKEN_INVALID', service: 'vendor',
      description: data.valid
        ? `Token validated successfully! User "${data.uid}" (role: ${data.role}, brand: ${data.brand}) is now authenticated at vendor "${systemId}". Creating vendor session.`
        : `Token validation FAILED: ${JSON.stringify(data)}`,
      httpResponse: { status: valRes.status, body: data },
      detail: { systemId, valid: data.valid, uid: data.uid, role: data.role, brand: data.brand },
    });

    if (data.valid) {
      emit({
        flowId, flowType: 'idp-initiated', step: 16,
        stepName: 'VENDOR_SESSION_CREATED', service: 'vendor',
        description: `Vendor app "${systemId}" created a local session for user "${data.uid}". SSO flow complete. User can now use the vendor application.`,
        sessionData: { uid: data.uid, role: data.role, brand: data.brand, dealer_code: data.dealer_code, source: systemId },
      });
    }

    renderResult(res, 'igtk', data.valid ? 'success' : 'error', data, {
      sourceSystem: systemId,
    });
  } catch (err) {
    renderResult(res, 'igtk', 'error', { error: err.message });
  }
}

// IGTK Vendor — callback validation
app.post('/sso/igtk', (req, res) => handleIgtk(req, res, 'vendor-igtk'));

// 2. SAML — parse base64 assertion, extract attributes
app.post('/sso/saml-acs', async (req, res) => {
  const samlResponse = req.body.SAMLResponse;
  const csrfNonce = req.body.csrf_nonce;
  const flowId = req.body._flowId || 'saml-' + Date.now();

  if (!samlResponse) return renderResult(res, 'saml', 'error', { error: 'No SAMLResponse received' });

  emit({
    flowId, flowType: 'idp-initiated', step: 15,
    stepName: 'VENDOR_VALIDATES_CSRF', service: 'vendor',
    description: `SAML Vendor received POST with SAMLResponse (${samlResponse.length} chars base64) + CSRF nonce. Validating CSRF nonce first via Broker /token/consume.`,
    detail: { saml_response_length: samlResponse.length, csrf_nonce: csrfNonce },
  });

  if (!await validateCsrf(csrfNonce)) {
    emit({ flowId, flowType: 'idp-initiated', step: 13.1, stepName: 'CSRF_FAILED', service: 'vendor', description: 'CSRF nonce validation failed.' });
    return renderResult(res, 'saml', 'error', { error: 'CSRF validation failed' });
  }

  try {
    const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
    const attrs = {};
    const attrRegex = /<saml:Attribute Name="([^"]+)"><saml:AttributeValue>([^<]*)<\/saml:AttributeValue><\/saml:Attribute>/g;
    let match;
    while ((match = attrRegex.exec(xml)) !== null) {
      attrs[match[1]] = match[2];
    }
    const nameIdMatch = xml.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
    const nameId = nameIdMatch ? nameIdMatch[1] : 'unknown';

    emit({
      flowId, flowType: 'idp-initiated', step: 16,
      stepName: 'SAML_ASSERTION_PARSED', service: 'vendor',
      description: `Vendor parsed SAML assertion locally. NameID: "${nameId}", ${Object.keys(attrs).length} attributes extracted. No signature verification in POC (real system uses RSA-SHA256).`,
      detail: { nameId, attributeCount: Object.keys(attrs).length, attributes: attrs },
    });
    emit({
      flowId, flowType: 'idp-initiated', step: 15,
      stepName: 'VENDOR_SESSION_CREATED', service: 'vendor',
      description: `SAML Vendor created session for "${nameId}". SSO flow complete.`,
      sessionData: { nameId, attributes: attrs },
    });

    renderResult(res, 'saml', 'success', { nameId, attributes: attrs, raw_xml_length: xml.length });
  } catch (err) {
    renderResult(res, 'saml', 'error', { error: err.message });
  }
});

// 3. AES256 — decrypt with shared key (handles kid:ciphertext format)
app.post('/sso/aes256', async (req, res) => {
  const rawToken = req.body.htxtToken;
  const csrfNonce = req.body.csrf_nonce;
  const flowId = req.body._flowId || 'aes-' + Date.now();

  if (!rawToken) return renderResult(res, 'aes256', 'error', { error: 'No htxtToken received' });

  emit({
    flowId, flowType: 'idp-initiated', step: 15,
    stepName: 'VENDOR_VALIDATES_CSRF', service: 'vendor',
    description: `AES-256 Vendor received encrypted token (${rawToken.length} chars) + CSRF nonce. Validating CSRF first.`,
    detail: { token_length: rawToken.length },
  });

  if (!await validateCsrf(csrfNonce)) {
    emit({ flowId, flowType: 'idp-initiated', step: 13.1, stepName: 'CSRF_FAILED', service: 'vendor', description: 'CSRF nonce validation failed.' });
    return renderResult(res, 'aes256', 'error', { error: 'CSRF validation failed' });
  }

  try {
    let ciphertext = rawToken;
    if (rawToken.includes(':')) ciphertext = rawToken.split(':')[1];
    const buf = Buffer.from(ciphertext, 'base64url');
    const iv = buf.slice(0, 16);
    const encrypted = buf.slice(16);
    const key = Buffer.from(AES_KEY, 'utf8').slice(0, 32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, null, 'utf8');
    decrypted += decipher.final('utf8');
    const data = JSON.parse(decrypted);

    emit({
      flowId, flowType: 'idp-initiated', step: 16,
      stepName: 'AES256_DECRYPTED', service: 'vendor',
      description: `Vendor decrypted AES-256-CBC token with shared key. Extracted IV (16 bytes) + ciphertext. Decrypted payload contains user data. Checking 60-second freshness window.`,
      tokenPayload: { decrypted: data, encryption: 'AES-256-CBC', iv_length: 16 },
      detail: { uid: data.uid, role: data.role, brand: data.brand, timestamp: data.timestamp },
    });

    if (Date.now() - data.timestamp > 60000) {
      emit({ flowId, flowType: 'idp-initiated', step: 13, stepName: 'TOKEN_EXPIRED', service: 'vendor', description: `Token expired. Timestamp ${data.timestamp} is more than 60 seconds old.` });
      return renderResult(res, 'aes256', 'error', { error: 'Token expired', data });
    }

    emit({
      flowId, flowType: 'idp-initiated', step: 15,
      stepName: 'VENDOR_SESSION_CREATED', service: 'vendor',
      description: `AES-256 Vendor created session for "${data.uid}". Token is fresh (within 60s window). SSO flow complete.`,
      sessionData: data,
    });

    renderResult(res, 'aes256', 'success', data);
  } catch (err) {
    renderResult(res, 'aes256', 'error', { error: err.message });
  }
});

// 4. RC4 — decrypt with shared key (handles kid:ciphertext.hmac format)
app.post('/sso/rc4', async (req, res) => {
  const rawToken = req.body.htxtToken;
  const csrfNonce = req.body.csrf_nonce;
  const flowId = req.body._flowId || 'rc4-' + Date.now();

  if (!rawToken) return renderResult(res, 'rc4', 'error', { error: 'No htxtToken received' });

  emit({
    flowId, flowType: 'idp-initiated', step: 15,
    stepName: 'VENDOR_VALIDATES_CSRF', service: 'vendor',
    description: `⚠️ RC4 Vendor (DEPRECATED) received encrypted token + CSRF nonce. Validating CSRF first.`,
    detail: { token_length: rawToken.length, deprecated: true },
  });

  if (!await validateCsrf(csrfNonce)) {
    emit({ flowId, flowType: 'idp-initiated', step: 13.1, stepName: 'CSRF_FAILED', service: 'vendor', description: 'CSRF nonce validation failed.' });
    return renderResult(res, 'rc4', 'error', { error: 'CSRF validation failed' });
  }

  try {
    let ciphertext = rawToken;
    if (rawToken.includes(':')) {
      const [_kid, rest] = rawToken.split(':');
      ciphertext = rest.split('.')[0];
    }
    const encrypted = Buffer.from(ciphertext, 'base64url');
    const key = Buffer.from(RC4_KEY, 'utf8');
    const S = new Uint8Array(256);
    for (let i = 0; i < 256; i++) S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % key.length]) & 255;
      [S[i], S[j]] = [S[j], S[i]];
    }
    const out = Buffer.alloc(encrypted.length);
    let x = 0; j = 0;
    for (let k = 0; k < encrypted.length; k++) {
      x = (x + 1) & 255;
      j = (j + S[x]) & 255;
      [S[x], S[j]] = [S[j], S[x]];
      out[k] = encrypted[k] ^ S[(S[x] + S[j]) & 255];
    }
    const data = JSON.parse(out.toString('utf8'));

    emit({
      flowId, flowType: 'idp-initiated', step: 16,
      stepName: 'RC4_DECRYPTED', service: 'vendor',
      description: `⚠️ Vendor decrypted RC4 token (DEPRECATED cipher). Stripped kid prefix and HMAC suffix. Decrypted with shared RC4 key. Checking 60-second freshness window.`,
      tokenPayload: { decrypted: data, encryption: 'RC4 (deprecated)', hmac: 'SHA-256' },
      detail: { uid: data.uid, deprecated: true },
    });

    if (Date.now() - data.timestamp > 60000) {
      emit({ flowId, flowType: 'idp-initiated', step: 13, stepName: 'TOKEN_EXPIRED', service: 'vendor', description: 'RC4 token expired.' });
      return renderResult(res, 'rc4', 'error', { error: 'Token expired', data });
    }

    emit({
      flowId, flowType: 'idp-initiated', step: 15,
      stepName: 'VENDOR_SESSION_CREATED', service: 'vendor',
      description: `RC4 Vendor created session for "${data.uid}". ⚠️ RC4 is deprecated — vendor should migrate to AES-256.`,
      sessionData: data,
    });

    renderResult(res, 'rc4', 'success', data);
  } catch (err) {
    renderResult(res, 'rc4', 'error', { error: err.message });
  }
});

// 5. WPC — validate OTP via broker
app.post('/sso/wpc', async (req, res) => {
  const { userid, key: otp, cmd, group, reg, csrf_nonce: csrfNonce } = req.body;
  const flowId = req.body._flowId || 'wpc-' + Date.now();

  if (!userid || !otp) return renderResult(res, 'wpc-otp', 'error', { error: 'Missing userid or key (OTP)' });

  emit({
    flowId, flowType: 'idp-initiated', step: 15,
    stepName: 'VENDOR_VALIDATES_CSRF', service: 'vendor',
    description: `WPC MOBIS Parts received OTP fields (cmd, group, reg, userid, key) + CSRF nonce. Validating CSRF first.`,
    detail: { cmd, group, reg, userid_length: userid.length, otp_length: otp.length },
  });

  if (!await validateCsrf(csrfNonce)) {
    emit({ flowId, flowType: 'idp-initiated', step: 13.1, stepName: 'CSRF_FAILED', service: 'vendor', description: 'CSRF nonce validation failed.' });
    return renderResult(res, 'wpc-otp', 'error', { error: 'CSRF validation failed' });
  }

  emit({
    flowId, flowType: 'idp-initiated', step: 16,
    stepName: 'VENDOR_VALIDATES_OTP', service: 'vendor',
    description: `WPC Vendor calling Broker POST /otp/validate with encrypted userid + OTP. Broker will decrypt the userid, look up the OTP in its store, check expiry (60s), and verify. Max 3 attempts before 5-min lockout.`,
    httpRequest: { method: 'POST', url: `${BROKER_URL}/otp/validate`, body: { userid: '[encrypted]', otp: '[6 chars]' } },
  });

  try {
    const fetch = (await import('node-fetch')).default;
    const valRes = await fetch(`${BROKER_URL}/otp/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid, otp }),
    });
    const data = await valRes.json();

    emit({
      flowId, flowType: 'idp-initiated', step: 15,
      stepName: data.valid ? 'OTP_VALID' : 'OTP_INVALID', service: 'vendor',
      description: data.valid
        ? `OTP validated successfully for user "${data.uid}". WPC Vendor creating session.`
        : `OTP validation failed: ${JSON.stringify(data)}`,
      httpResponse: { status: valRes.status, body: data },
    });

    if (data.valid) {
      emit({
        flowId, flowType: 'idp-initiated', step: 16,
        stepName: 'VENDOR_SESSION_CREATED', service: 'vendor',
        description: `WPC MOBIS Parts created session for "${data.uid}". SSO flow complete.`,
        sessionData: { ...data, cmd, group, reg },
      });
    }

    renderResult(res, 'wpc-otp', data.valid ? 'success' : 'error', { ...data, cmd, group, reg });
  } catch (err) {
    renderResult(res, 'wpc-otp', 'error', { error: err.message });
  }
});

app.listen(3005, () => console.log('vendor-app :3005'));
