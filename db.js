// db.js — License Server Database
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'licenses.db'));

// Create tables on first run
db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT UNIQUE NOT NULL,
    client_name TEXT NOT NULL,
    client_phone TEXT,
    plan        TEXT DEFAULT 'single',   -- single | multi | unlimited
    fingerprint TEXT,                    -- set on first activation
    activated_at TEXT,
    expires_at  TEXT NOT NULL,
    status      TEXT DEFAULT 'unused',   -- unused | active | expired | suspended
    notes       TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS activation_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key  TEXT NOT NULL,
    fingerprint  TEXT,
    ip_address   TEXT,
    action       TEXT,   -- activate | validate | renew | deactivate
    result       TEXT,   -- success | fail
    message      TEXT,
    created_at   TEXT DEFAULT (datetime('now'))
  );
`);

module.exports = db;
