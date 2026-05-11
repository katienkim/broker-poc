// Shared dashboard event emitter for vendor-app
const http = require('http');
const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://flow-dashboard:3007';

function emit(event) {
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

module.exports = { emit };
