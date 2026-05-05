const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'data', 'salon.db'));

// SEC[CWE-89]: All database access in this app uses prepared statements
// (db.prepare with bound parameters). User input is NEVER concatenated
// into SQL strings. This is the only SQL injection defense the app needs
// because there is no other path to the database.

// SEC[CWE-359]: Data minimization. v0.0.1 collects a username and a
// password hash and nothing else. No email, no real name, no institution.
// Reduces blast radius of any future data exposure to the smallest set
// of fields that still allows the application to function.
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS intentions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

module.exports = db;