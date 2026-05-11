// poc/apps/role-api/src/index.js
// ENA — User Attribute DB API
// Provides user attributes (role, brand, dealer_code, department, etc.)
// that the Broker uses to enrich tokens before sending to vendors.
const express = require('express');
const { users } = require('./fixtures');

const app = express();
app.use(express.json());

app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'ena-user-attributes' }));

// GET /users/:uid — full user attributes for enrichment
app.get('/users/:uid', (req, res) => {
  const data = users[req.params.uid];
  if (!data) {
    return res.status(404).json({ error: 'user not found', uid: req.params.uid });
  }
  res.json(data);
});

// Legacy endpoint — keep for backward compat
app.get('/roles/:uid', (req, res) => {
  const data = users[req.params.uid];
  if (!data) {
    return res.status(404).json({ error: 'user not found', uid: req.params.uid });
  }
  // Return just role/brand/dealer_code for legacy callers
  res.json({ role: data.role, brand: data.brand, dealer_code: data.dealer_code });
});

app.listen(3004, () => console.log('ena-user-attributes :3004'));
