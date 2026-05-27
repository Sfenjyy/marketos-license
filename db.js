// db.js — License Server Database (using sql.js, pure JS, works on Render free tier)
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');

const DB_PATH = path.join(__dirname, 'licenses.db');

let _db = null;

// Save DB to disk after every write
function persist(db) {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

async function getDB() {
  if (_db) return _db;

  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    _db = new SQL.Database(fileBuffer);
  } else {
    _db = new SQL.Database();
  }

  // Create tables
  _db.run(`
    CREATE TABLE IF NOT EXISTS licenses (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      key         TEXT UNIQUE NOT NULL,
      client_name TEXT NOT NULL,
      client_phone TEXT DEFAULT '',
      plan        TEXT DEFAULT 'single',
      fingerprint TEXT DEFAULT NULL,
      activated_at TEXT DEFAULT NULL,
      expires_at  TEXT NOT NULL,
      status      TEXT DEFAULT 'unused',
      notes       TEXT DEFAULT '',
      created_at  TEXT DEFAULT (datetime('now'))
    );
  `);

  _db.run(`
    CREATE TABLE IF NOT EXISTS activation_log (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      license_key  TEXT NOT NULL,
      fingerprint  TEXT DEFAULT NULL,
      ip_address   TEXT DEFAULT NULL,
      action       TEXT,
      result       TEXT,
      message      TEXT,
      created_at   TEXT DEFAULT (datetime('now'))
    );
  `);

  persist(_db);
  return _db;
}

// Helper: run a write statement and persist
function run(db, sql, params = []) {
  db.run(sql, params);
  persist(db);
}

// Helper: get one row
function get(db, sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

// Helper: get all rows
function all(db, sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

module.exports = { getDB, run, get, all, persist };
