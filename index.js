// index.js — MarketOS License Server
// Deploy this on your VPS (Hetzner / DigitalOcean / etc.)

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(cors());

// ─── Secret for signing responses ────────────────────────────────────────────
// On Render: set this as an environment variable called SIGNING_SECRET
// Locally: replace the fallback string below
const SIGNING_SECRET = process.env.SIGNING_SECRET || 'CHANGE_THIS_FALLBACK_FOR_LOCAL_DEV';

function signPayload(payload) {
  return crypto
    .createHmac('sha256', SIGNING_SECRET)
    .update(JSON.stringify(payload))
    .digest('hex');
}

function logAction(key, fingerprint, ip, action, result, message) {
  db.prepare(`
    INSERT INTO activation_log (license_key, fingerprint, ip_address, action, result, message)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(key, fingerprint, ip, action, result, message);
}

// ─── POST /activate ───────────────────────────────────────────────────────────
// Called once on first install. Binds license key to machine fingerprint.
app.post('/activate', (req, res) => {
  const { key, fingerprint } = req.body;
  const ip = req.ip;

  if (!key || !fingerprint) {
    return res.status(400).json({ success: false, message: 'Missing key or fingerprint' });
  }

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);

  if (!license) {
    logAction(key, fingerprint, ip, 'activate', 'fail', 'Key not found');
    return res.status(404).json({ success: false, message: 'License key not found' });
  }

  if (license.status === 'suspended') {
    logAction(key, fingerprint, ip, 'activate', 'fail', 'License suspended');
    return res.status(403).json({ success: false, message: 'License is suspended' });
  }

  // Already activated on a different machine
  if (license.fingerprint && license.fingerprint !== fingerprint) {
    logAction(key, fingerprint, ip, 'activate', 'fail', 'Fingerprint mismatch');
    return res.status(403).json({ success: false, message: 'License already activated on another machine. Contact support.' });
  }

  // Activate it
  db.prepare(`
    UPDATE licenses
    SET fingerprint = ?, status = 'active', activated_at = datetime('now')
    WHERE key = ?
  `).run(fingerprint, key);

  const payload = {
    success: true,
    key,
    plan: license.plan,
    client_name: license.client_name,
    expires_at: license.expires_at,
    activated_at: new Date().toISOString(),
  };

  payload.signature = signPayload(payload);
  logAction(key, fingerprint, ip, 'activate', 'success', 'Activated');
  res.json(payload);
});

// ─── POST /validate ───────────────────────────────────────────────────────────
// Called on renewal or when client reconnects internet.
app.post('/validate', (req, res) => {
  const { key, fingerprint } = req.body;
  const ip = req.ip;

  if (!key || !fingerprint) {
    return res.status(400).json({ success: false, message: 'Missing key or fingerprint' });
  }

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);

  if (!license) {
    logAction(key, fingerprint, ip, 'validate', 'fail', 'Key not found');
    return res.status(404).json({ success: false, message: 'License key not found' });
  }

  if (license.fingerprint !== fingerprint) {
    logAction(key, fingerprint, ip, 'validate', 'fail', 'Fingerprint mismatch');
    return res.status(403).json({ success: false, message: 'Fingerprint mismatch' });
  }

  if (license.status === 'suspended') {
    logAction(key, fingerprint, ip, 'validate', 'fail', 'Suspended');
    return res.status(403).json({ success: false, message: 'License suspended' });
  }

  const payload = {
    success: true,
    key,
    plan: license.plan,
    client_name: license.client_name,
    expires_at: license.expires_at,
    status: license.status,
  };

  payload.signature = signPayload(payload);
  logAction(key, fingerprint, ip, 'validate', 'success', 'Validated');
  res.json(payload);
});

// ─── POST /deactivate ─────────────────────────────────────────────────────────
// Called when reinstalling on a new machine. Releases the fingerprint lock.
app.post('/deactivate', (req, res) => {
  const { key, admin_secret } = req.body;

  // Simple admin protection — only you can deactivate
  if (admin_secret !== SIGNING_SECRET) {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  db.prepare(`
    UPDATE licenses SET fingerprint = NULL, status = 'unused', activated_at = NULL WHERE key = ?
  `).run(key);

  res.json({ success: true, message: 'License released. Can be activated on new machine.' });
});

// ─── ADMIN ROUTES (only you use these) ───────────────────────────────────────

// Generate a new license key
app.post('/admin/generate', (req, res) => {
  const { admin_secret, client_name, client_phone, plan, months } = req.body;

  if (admin_secret !== SIGNING_SECRET) {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const key = 'MPOS-' + uuidv4().toUpperCase().replace(/-/g, '').substring(0, 16);
  const expires = new Date();
  expires.setMonth(expires.getMonth() + (months || 12));

  db.prepare(`
    INSERT INTO licenses (key, client_name, client_phone, plan, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(key, client_name, client_phone || '', plan || 'single', expires.toISOString());

  res.json({ success: true, key, expires_at: expires.toISOString() });
});

// Renew a license (extend expiry)
app.post('/admin/renew', (req, res) => {
  const { admin_secret, key, months } = req.body;

  if (admin_secret !== SIGNING_SECRET) {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);
  if (!license) return res.status(404).json({ success: false, message: 'Not found' });

  const current = new Date(license.expires_at) > new Date() ? new Date(license.expires_at) : new Date();
  current.setMonth(current.getMonth() + (months || 12));

  db.prepare(`UPDATE licenses SET expires_at = ?, status = 'active' WHERE key = ?`)
    .run(current.toISOString(), key);

  res.json({ success: true, key, new_expires_at: current.toISOString() });
});

// List all licenses
app.get('/admin/licenses', (req, res) => {
  const { admin_secret } = req.query;
  if (admin_secret !== SIGNING_SECRET) {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const licenses = db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all();
  res.json({ success: true, licenses });
});

// ─── Health check (keeps Render free tier alive via UptimeRobot) ─────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ MarketOS License Server running on port ${PORT}`);
});
