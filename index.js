// index.js — MarketOS License Server
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const { getDB, run, get, all } = require('./db');

const app = express();
app.use(express.json());
app.use(cors());

const SIGNING_SECRET = process.env.SIGNING_SECRET || 'CHANGE_THIS_FOR_LOCAL_DEV';

function sign(payload) {
  return crypto.createHmac('sha256', SIGNING_SECRET).update(JSON.stringify(payload)).digest('hex');
}

function genKey() {
  return 'MPOS-' + crypto.randomBytes(8).toString('hex').toUpperCase();
}

async function log(db, key, fingerprint, ip, action, result, message) {
  run(db,
    `INSERT INTO activation_log (license_key, fingerprint, ip_address, action, result, message)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [key, fingerprint || null, ip || null, action, result, message]
  );
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── POST /activate ────────────────────────────────────────────────────────────
app.post('/activate', async (req, res) => {
  const { key, fingerprint } = req.body;
  if (!key || !fingerprint) return res.status(400).json({ success: false, message: 'Missing key or fingerprint' });

  const db = await getDB();
  const license = get(db, 'SELECT * FROM licenses WHERE key = ?', [key]);

  if (!license) {
    await log(db, key, fingerprint, req.ip, 'activate', 'fail', 'Key not found');
    return res.status(404).json({ success: false, message: 'License key not found' });
  }
  if (license.status === 'suspended') {
    await log(db, key, fingerprint, req.ip, 'activate', 'fail', 'Suspended');
    return res.status(403).json({ success: false, message: 'License is suspended. Contact support.' });
  }
  if (license.fingerprint && license.fingerprint !== fingerprint) {
    await log(db, key, fingerprint, req.ip, 'activate', 'fail', 'Fingerprint mismatch');
    return res.status(403).json({ success: false, message: 'License already activated on another machine. Contact support.' });
  }

  run(db, `UPDATE licenses SET fingerprint=?, status='active', activated_at=datetime('now') WHERE key=?`, [fingerprint, key]);
  await log(db, key, fingerprint, req.ip, 'activate', 'success', 'Activated');

  const payload = { success: true, key, plan: license.plan, client_name: license.client_name, expires_at: license.expires_at, activated_at: new Date().toISOString() };
  payload.signature = sign(payload);
  res.json(payload);
});

// ── POST /validate ────────────────────────────────────────────────────────────
app.post('/validate', async (req, res) => {
  const { key, fingerprint } = req.body;
  if (!key || !fingerprint) return res.status(400).json({ success: false, message: 'Missing key or fingerprint' });

  const db = await getDB();
  const license = get(db, 'SELECT * FROM licenses WHERE key = ?', [key]);

  if (!license) {
    await log(db, key, fingerprint, req.ip, 'validate', 'fail', 'Not found');
    return res.status(404).json({ success: false, message: 'License key not found' });
  }
  if (license.fingerprint !== fingerprint) {
    await log(db, key, fingerprint, req.ip, 'validate', 'fail', 'Fingerprint mismatch');
    return res.status(403).json({ success: false, message: 'Fingerprint mismatch' });
  }
  if (license.status === 'suspended') {
    await log(db, key, fingerprint, req.ip, 'validate', 'fail', 'Suspended');
    return res.status(403).json({ success: false, message: 'License suspended' });
  }

  await log(db, key, fingerprint, req.ip, 'validate', 'success', 'Validated');
  const payload = { success: true, key, plan: license.plan, client_name: license.client_name, expires_at: license.expires_at, status: license.status };
  payload.signature = sign(payload);
  res.json(payload);
});

// ── POST /deactivate ──────────────────────────────────────────────────────────
app.post('/deactivate', async (req, res) => {
  const { key, admin_secret } = req.body;
  if (admin_secret !== SIGNING_SECRET) return res.status(403).json({ success: false, message: 'Unauthorized' });

  const db = await getDB();
  run(db, `UPDATE licenses SET fingerprint=NULL, status='unused', activated_at=NULL WHERE key=?`, [key]);
  res.json({ success: true, message: 'License released. Can activate on new machine.' });
});

// ── POST /admin/generate ──────────────────────────────────────────────────────
app.post('/admin/generate', async (req, res) => {
  const { admin_secret, client_name, client_phone, plan, months } = req.body;
  if (admin_secret !== SIGNING_SECRET) return res.status(403).json({ success: false, message: 'Unauthorized' });

  const db   = await getDB();
  const key  = genKey();
  const exp  = new Date();
  exp.setMonth(exp.getMonth() + (parseInt(months) || 12));

  run(db,
    `INSERT INTO licenses (key, client_name, client_phone, plan, expires_at) VALUES (?, ?, ?, ?, ?)`,
    [key, client_name, client_phone || '', plan || 'single', exp.toISOString()]
  );
  res.json({ success: true, key, expires_at: exp.toISOString() });
});

// ── POST /admin/renew ─────────────────────────────────────────────────────────
app.post('/admin/renew', async (req, res) => {
  const { admin_secret, key, months } = req.body;
  if (admin_secret !== SIGNING_SECRET) return res.status(403).json({ success: false, message: 'Unauthorized' });

  const db      = await getDB();
  const license = get(db, 'SELECT * FROM licenses WHERE key = ?', [key]);
  if (!license) return res.status(404).json({ success: false, message: 'Not found' });

  const base = new Date(license.expires_at) > new Date() ? new Date(license.expires_at) : new Date();
  base.setMonth(base.getMonth() + (parseInt(months) || 12));

  run(db, `UPDATE licenses SET expires_at=?, status='active' WHERE key=?`, [base.toISOString(), key]);
  res.json({ success: true, key, new_expires_at: base.toISOString() });
});

// ── GET /admin/licenses ───────────────────────────────────────────────────────
app.get('/admin/licenses', async (req, res) => {
  const { admin_secret } = req.query;
  if (admin_secret !== SIGNING_SECRET) return res.status(403).json({ success: false, message: 'Unauthorized' });

  const db = await getDB();
  const licenses = all(db, 'SELECT * FROM licenses ORDER BY created_at DESC');
  res.json({ success: true, licenses });
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`✅ MarketOS License Server on port ${PORT}`));
