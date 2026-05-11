// poc/apps/portal/src/index.js
// Dealers Portal — matches the IdP Initiated SSO Design PDF exactly.
//
// PDF Flow:
// Step 1: User clicks vendor link (already logged into Dealers)
// Step 2: Dealers backend requests launch token from PID (server-to-server API call)
// Step 3: PID validates API key and policy
// Step 4: PID issues one-time launch token
// Step 5: Dealers redirects browser to PID launch endpoint
// Step 6: Browser accesses PID launch endpoint with token
// Step 7: PID validates launch token
// Step 8: PID redirects browser to Broker Service
// Steps 9-14: Broker fetches attributes, generates token, sends to vendor

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', true);

const PID_PUBLIC_URL = process.env.PID_PUBLIC_URL || 'http://pid.sso.test:8000';
const PID_INTERNAL_URL = process.env.PID_INTERNAL_URL || 'http://mock-pid:3006';
const ENA_URL = process.env.ENA_URL || 'http://role-api:3004';
const BROKER_PUBLIC_URL = process.env.BROKER_PUBLIC_URL || 'http://broker.sso.test:8000';
const PORTAL_PUBLIC_URL = 'http://portal.sso.test:8000';
const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://flow-dashboard:3007';

// Dealers API credentials for PID (from PDF: X-Client-Id, X-Source-System, X-Api-Key)
const PID_CLIENT_ID = 'hmg-admin-partner';
const PID_SOURCE_SYSTEM = 'dealers';
const PID_API_KEY = process.env.PID_API_KEY || 'poc-dealers-api-key';

function emitDashboard(event) {
  try {
    const body = JSON.stringify(event);
    const url = new URL(DASHBOARD_URL + '/api/event');
    const req = http.request({
      hostname: url.hostname, port: url.port, path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 2000,
    });
    req.on('error', () => {});
    req.write(body);
    req.end();
  } catch (_) {}
}

function parseCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return match ? match[1] : null;
}

// Landing page — user must be logged into Dealers already
app.get('/', async (req, res) => {
  const pidSessionId = parseCookie(req.headers.cookie, 'PID_SESSION');

  if (!pidSessionId) {
    const isDashboard = req.query.dashboard === '1';
    const loginFlowId = 'login-' + crypto.randomUUID().substring(0, 8);

    if (isDashboard) {
      emitDashboard({
        flowId: loginFlowId, flowType: 'idp-initiated', flowName: 'Dealer Portal Login', step: 1,
        stepName: 'USER_VISITS_PORTAL', service: 'portal',
        description: 'User navigated to the Dealers portal. Not logged in. Redirecting to PID for authentication. (This login step is outside the SSO flow scope — the PDF assumes the user is already logged in.)',
        redirect: { description: 'Portal redirects to PID for login', url: `${PID_PUBLIC_URL}/auth/portal-login` },
        detail: { loginFlowId },
      });

      return res.send(`<!DOCTYPE html><html><head><title>Portal — Not Logged In</title>
<style>
  body { font-family: -apple-system, sans-serif; background: #0d1117; color: #e6edf3; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; max-width: 500px; text-align: center; }
  h2 { margin-top: 0; color: #f57c00; }
  .step-badge { display: inline-block; background: #f57c00; color: #fff; padding: 2px 10px; border-radius: 3px; font-size: 12px; font-weight: 700; margin-bottom: 12px; }
  .url { font-family: monospace; font-size: 12px; color: #8b949e; background: #1c2128; padding: 8px 12px; border-radius: 6px; margin: 12px 0; word-break: break-all; }
  .countdown { font-size: 48px; font-weight: 700; color: #f57c00; margin: 16px 0; }
  .btn { display: inline-block; padding: 12px 32px; background: #f57c00; color: #fff; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; text-decoration: none; }
  .btn:hover { background: #e65100; }
  .btn-secondary { background: transparent; border: 1px solid #30363d; color: #8b949e; font-size: 13px; padding: 8px 16px; margin-top: 12px; display: inline-block; text-decoration: none; }
</style></head><body>
<div class="card">
  <div class="step-badge">PRE-REQUISITE — LOGIN</div>
  <h2>Dealers Portal</h2>
  <p>Not logged in. The PDF assumes the user is already authenticated. Redirecting to PID login.</p>
  <div class="url">→ pid.sso.test:8000/auth/portal-login</div>
  <div class="countdown" id="cd">5</div>
  <a class="btn" href="${PID_PUBLIC_URL}/auth/portal-login?return_url=${encodeURIComponent(PORTAL_PUBLIC_URL + '?dashboard=1')}&dashboard=1&flowId=${loginFlowId}">Login via PID →</a>
  <br><a class="btn-secondary" href="http://dashboard.sso.test:8000">← Dashboard</a>
</div>
<script>let s=5;const c=document.getElementById('cd');const t=setInterval(()=>{s--;c.textContent=s;if(s<=0){clearInterval(t);window.location.href='${PID_PUBLIC_URL}/auth/portal-login?return_url=${encodeURIComponent(PORTAL_PUBLIC_URL+'?dashboard=1')}&dashboard=1&flowId=${loginFlowId}';}},1000);</script>
</body></html>`);
    }

    return res.redirect(`${PID_PUBLIC_URL}/auth/portal-login?return_url=${encodeURIComponent(PORTAL_PUBLIC_URL)}`);
  }

  // User is logged in — show portal with vendor links
  try {
    const fetch = (await import('node-fetch')).default;
    const pidRes = await fetch(`${PID_INTERNAL_URL}/auth/session-info`, {
      headers: { cookie: req.headers.cookie || '' },
    });

    let user = { uid: 'unknown', role: 'N/A', brand: 'N/A', dealer_code: null, user_type: 'PID' };
    if (pidRes.ok) {
      const pidUser = await pidRes.json();
      try {
        const enaRes = await fetch(`${ENA_URL}/users/${encodeURIComponent(pidUser.username)}`);
        if (enaRes.ok) {
          const enaData = await enaRes.json();
          user = { uid: pidUser.username, role: enaData.role || 'UNKNOWN', brand: enaData.brand || 'H', dealer_code: enaData.dealer_code || null, user_type: 'PID' };
        } else { user.uid = pidUser.username; }
      } catch (_) { user.uid = pidUser.username; }
    }

    if (req.query.dashboard === '1') {
      emitDashboard({
        flowId: req.query.flowId || 'login-' + Date.now(),
        flowType: 'idp-initiated', flowName: 'Dealer Portal Login', step: 3,
        stepName: 'PORTAL_LOADED', service: 'portal',
        description: `Dealers portal loaded for "${user.uid}". User is logged in and can click vendor links. (PDF initial state: "The account is currently logged in to Dealers.")`,
        sessionData: user,
        detail: { uid: user.uid, role: user.role, brand: user.brand },
      });
    }

    const html = fs.readFileSync(path.join(__dirname, 'views/index.html'), 'utf8');
    const dashboardScript = req.query.dashboard === '1' ? `
<script>
document.querySelectorAll('a[href*="/launch/"]').forEach(a => {
  const url = new URL(a.href, window.location.origin);
  url.searchParams.set('dashboard', '1');
  a.href = url.toString();
});
</script>` : '';

    res.send(html
      .replace('{{USERNAME}}', user.uid || 'unknown')
      .replace('{{ROLE}}', user.role || 'N/A')
      .replace('{{BRAND}}', user.brand || 'N/A')
      .replace('{{DEALER_CODE}}', user.dealer_code || 'N/A')
      .replace('{{USER_TYPE}}', user.user_type || 'N/A')
      .replace('{{USER_JSON}}', JSON.stringify(user, null, 2))
      .replace('{{BROKER_URL}}', BROKER_PUBLIC_URL)
      .replace('</body>', dashboardScript + '</body>')
    );
  } catch (err) {
    return res.redirect(`${PID_PUBLIC_URL}/auth/portal-login?return_url=${encodeURIComponent(PORTAL_PUBLIC_URL)}`);
  }
});

app.get('/logout', (_req, res) => {
  res.setHeader('Set-Cookie', 'PID_SESSION=; Path=/; HttpOnly; Domain=.sso.test; Max-Age=0');
  res.redirect(`${BROKER_PUBLIC_URL}/logout`);
});

// ─── PDF Steps 1-5: Vendor link click → request launch token → redirect ──
app.get('/launch/:target', async (req, res) => {
  const target = req.params.target;
  const isDashboard = req.query.dashboard === '1';
  const requestId = crypto.randomUUID();
  const flowId = 'sso-' + requestId.substring(0, 8);

  // Get user_id from PID session (server-to-server call)
  let userId = 'unknown';
  try {
    const fetch = (await import('node-fetch')).default;
    const pidRes = await fetch(`${PID_INTERNAL_URL}/auth/session-info`, {
      headers: { cookie: req.headers.cookie || '' },
    });
    if (pidRes.ok) {
      const pidUser = await pidRes.json();
      userId = pidUser.username;
    }
  } catch (_) {}

  // PDF Step 1: User clicks a vendor link in Dealers
  emitDashboard({
    flowId, flowType: 'idp-initiated', flowName: `SSO → ${target}`,
    step: 1, stepName: 'USER_CLICKS_VENDOR_LINK', service: 'portal',
    description: `[PDF Step 1] User clicked vendor link "${target}" in Dealers. The account is already logged in. Dealers backend will now request a launch token from PID.`,
    detail: { target, user_id: userId, request_id: requestId },
  });

  // PDF Step 2: Dealers backend requests launch token from PID (server-to-server)
  emitDashboard({
    flowId, flowType: 'idp-initiated', step: 2,
    stepName: 'DEALERS_REQUESTS_LAUNCH_TOKEN', service: 'portal',
    description: `[PDF Step 2] Dealers backend is calling PID API (server-to-server) to request a launch token. Headers: X-Client-Id=${PID_CLIENT_ID}, X-Source-System=${PID_SOURCE_SYSTEM}, X-Api-Key=[DEALERS_API_KEY]. Body: target_vendor=${target}, user_id=${userId}, request_id=${requestId}.`,
    httpRequest: {
      method: 'POST', url: `${PID_INTERNAL_URL}/api/launch-token`,
      headers: { 'X-Client-Id': PID_CLIENT_ID, 'X-Source-System': PID_SOURCE_SYSTEM, 'X-Api-Key': '[DEALERS_API_KEY]' },
      body: { target_vendor: target, user_id: userId, request_id: requestId },
    },
    detail: { target, user_id: userId, request_id: requestId },
  });

  try {
    const fetch = (await import('node-fetch')).default;

    // Server-to-server call to PID to request launch token
    const pidRes = await fetch(`${PID_INTERNAL_URL}/api/launch-token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': PID_CLIENT_ID,
        'X-Source-System': PID_SOURCE_SYSTEM,
        'X-Api-Key': PID_API_KEY,
      },
      body: JSON.stringify({ target_vendor: target, user_id: userId, request_id: requestId, flow_id: flowId }),
    });

    const pidData = await pidRes.json();

    if (!pidRes.ok || !pidData.launch_token) {
      emitDashboard({
        flowId, flowType: 'idp-initiated', step: 3,
        stepName: 'PID_REJECTED', service: 'pid',
        description: `[PDF Step 3] PID rejected the request: ${pidData.error || 'unknown error'}`,
        httpResponse: { status: pidRes.status, body: pidData },
      });
      return res.status(403).send('PID rejected launch token request: ' + (pidData.error || 'unknown'));
    }

    // PDF Steps 3-4 are emitted by PID itself (server-side)
    // Portal just got the launch_token back

    // PDF Step 5: Dealers redirects the browser to PID launch endpoint
    const launchUrl = `${PID_PUBLIC_URL}/auth/launch-validate?token=${encodeURIComponent(pidData.launch_token)}&flow_id=${encodeURIComponent(flowId)}${isDashboard ? '&dashboard=1' : ''}`;

    emitDashboard({
      flowId, flowType: 'idp-initiated', step: 5,
      stepName: 'DEALERS_REDIRECTS_BROWSER_TO_PID', service: 'portal',
      description: `[PDF Step 5] Dealers redirects the browser to PID's launch endpoint with the launch token. The browser will carry the token to PID for validation.`,
      redirect: { description: 'Browser redirects to PID launch endpoint', url: `${PID_PUBLIC_URL}/auth/launch-validate` },
      detail: { launch_token_length: pidData.launch_token.length },
    });

    if (isDashboard) {
      return res.send(`<!DOCTYPE html><html><head><title>Redirect to PID</title>
<style>body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;max-width:500px;text-align:center}h2{margin-top:0;color:#81c784}.step-badge{display:inline-block;background:#2e7d32;color:#fff;padding:2px 10px;border-radius:3px;font-size:12px;font-weight:700;margin-bottom:12px}.url{font-family:monospace;font-size:11px;color:#8b949e;background:#1c2128;padding:8px 12px;border-radius:6px;margin:12px 0;word-break:break-all}.countdown{font-size:48px;font-weight:700;color:#81c784;margin:16px 0}.btn{display:inline-block;padding:12px 32px;background:#2e7d32;color:#fff;border:none;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;text-decoration:none}.btn-secondary{background:transparent;border:1px solid #30363d;color:#8b949e;font-size:13px;padding:8px 16px;margin-top:12px;display:inline-block;text-decoration:none}</style></head><body>
<div class="card"><div class="step-badge">PDF STEP 5 — REDIRECT TO PID</div><h2>Browser → PID Launch Endpoint</h2><p>Dealers got the launch token from PID (server-to-server). Now redirecting the browser to PID's launch endpoint with the token.</p><div class="url">→ pid.sso.test:8000/auth/launch-endpoint?launch_token=...</div><div class="countdown" id="cd">5</div><a class="btn" href="${launchUrl}">Redirect to PID →</a><br><a class="btn-secondary" href="http://dashboard.sso.test:8000">← Dashboard</a></div>
<script>let s=5;const c=document.getElementById('cd');const t=setInterval(()=>{s--;c.textContent=s;if(s<=0){clearInterval(t);window.location.href='${launchUrl}';}},1000);</script></body></html>`);
    }

    res.redirect(launchUrl);
  } catch (err) {
    return res.status(500).send('Error requesting launch token: ' + err.message);
  }
});

app.listen(3000, () => console.log('app-portal :3000'));
