// poc/apps/dashboard/src/index.js
// Unified Flow Dashboard — visualizes both SP-Initiated and IdP-Initiated SSO flows
const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());

const BROKER_URL = process.env.BROKER_URL || 'http://iam-broker:3003';

// ─── Flow Event Store ────────────────────────────────────────────────
// All services POST events here. Each event belongs to a flowId.
const flows = new Map();
const allEvents = [];

function addEvent(event) {
  const e = { ts: new Date().toISOString(), ...event };
  allEvents.push(e);
  if (allEvents.length > 500) allEvents.shift();

  if (e.flowId) {
    if (!flows.has(e.flowId)) {
      flows.set(e.flowId, {
        flowId: e.flowId,
        flowType: e.flowType || 'unknown',
        flowName: e.flowName || '',
        steps: [],
        startedAt: e.ts,
      });
    }
    const flow = flows.get(e.flowId);
    if (e.flowType && flow.flowType === 'unknown') flow.flowType = e.flowType;
    if (e.flowName && !flow.flowName) flow.flowName = e.flowName;
    flow.steps.push(e);
  }
  return e;
}

// Cleanup old flows every 5 min
setInterval(() => {
  const cutoff = Date.now() - 2 * 60 * 60 * 1000;
  for (const [id, flow] of flows) {
    if (new Date(flow.startedAt).getTime() < cutoff) flows.delete(id);
  }
}, 5 * 60 * 1000).unref();

// ─── API Routes ──────────────────────────────────────────────────────

// Receive events from any service
app.post('/api/event', (req, res) => {
  const e = addEvent(req.body);
  res.json({ ok: true, ts: e.ts });
});

// Get all flows (most recent first)
app.get('/api/flows', (_req, res) => {
  const arr = Array.from(flows.values()).slice(-50).reverse();
  res.json(arr);
});

// Get flows by type
app.get('/api/flows/:type', (req, res) => {
  const type = req.params.type;
  const arr = Array.from(flows.values())
    .filter(f => f.flowType === type)
    .slice(-30)
    .reverse();
  res.json(arr);
});

// Get single flow
app.get('/api/flow/:id', (req, res) => {
  const flow = flows.get(req.params.id);
  if (!flow) return res.status(404).json({ error: 'Flow not found' });
  res.json(flow);
});

// Reset all
app.delete('/api/reset', (_req, res) => {
  flows.clear();
  allEvents.length = 0;
  res.json({ ok: true });
});

// Delete a single flow
app.delete('/api/flow/:id', (req, res) => {
  const id = req.params.id;
  if (!flows.has(id)) return res.status(404).json({ error: 'Flow not found' });
  flows.delete(id);
  res.json({ ok: true, deleted: id });
});

// Health
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── Serve the dashboard HTML ────────────────────────────────────────
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'views/dashboard.html'));
});

app.listen(3007, () => console.log('flow-dashboard :3007'));
