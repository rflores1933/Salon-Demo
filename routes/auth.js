const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');

const router = express.Router();

// ===== Security configuration =====

// SEC[CWE-916]: bcrypt cost factor of 12. bcrypt is a deliberately slow,
// salted, adaptive password hash. Cost 12 keeps login response under
// ~250ms on commodity hardware while making offline brute-force prohibitive.
// Increase as hardware improves; bcrypt's design lets cost rise over time.
const BCRYPT_COST = 12;

// SEC[CWE-521]: Password length policy follows NIST SP 800-63B (2017+).
// Minimum 8 characters, no enforced complexity, max 128 to bound bcrypt
// input. Length > complexity for resistance to guessing — modern guidance
// rejects character-class rules as counterproductive (they push users
// toward predictable substitution patterns).
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

const USERNAME_PATTERN = /^[a-zA-Z0-9_-]{3,30}$/;

// SEC[CWE-208]: Precomputed dummy bcrypt hash. Used during login when the
// supplied username does not exist, so the response time is identical to
// a real-but-failed login. Defeats username enumeration via timing analysis.
const DUMMY_HASH = bcrypt.hashSync('dummy_password_for_timing_safety', BCRYPT_COST);

// ===== Validation helpers =====

// SEC[CWE-20]: Centralized server-side input validation. Client-side
// validation in the form (HTML pattern attribute, etc.) is a UX courtesy,
// not a security control — anything from the client is untrusted.
function validateUsername(username) {
  if (typeof username !== 'string') return 'Username is required.';
  const trimmed = username.trim();
  if (!USERNAME_PATTERN.test(trimmed)) {
    return 'Username must be 3-30 characters: letters, numbers, underscore, or hyphen.';
  }
  return null;
}

function validatePassword(password) {
  if (typeof password !== 'string') return 'Password is required.';
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return `Password must be no more than ${MAX_PASSWORD_LENGTH} characters.`;
  }
  return null;
}

// ===== Prepared statements =====

// SEC[CWE-89]: All queries below use parameter binding via prepared
// statements. User input never reaches SQL as a string. Compiled once
// at module load for performance and clarity.
const insertUser = db.prepare(
  'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)'
);
const findUserByUsername = db.prepare('SELECT * FROM users WHERE username = ?');

// ===== Registration =====

router.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/gymnasium');
  res.render('register', { error: null, username: '' });
});

router.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const usernameError = validateUsername(username);
    if (usernameError) {
      return res.status(400).render('register', { error: usernameError, username: username || '' });
    }
    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).render('register', { error: passwordError, username: username.trim() });
    }

    const trimmedUsername = username.trim();

    const existing = findUserByUsername.get(trimmedUsername);
    if (existing) {
      // Note: registration deliberately reveals whether a username is taken,
      // because the user must be able to pick a different one. Login does
      // NOT reveal this — see the generic error message there.
      return res.status(409).render('register', {
        error: 'That username is taken.',
        username: trimmedUsername
      });
    }

    // SEC[CWE-916]: Password hashed with bcrypt + per-user salt (the salt
    // is generated and embedded in the hash automatically). Plaintext
    // password is never persisted, never logged, and goes out of scope
    // after this line.
    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    const result = insertUser.run(trimmedUsername, passwordHash, Date.now());

    // SEC[CWE-384]: Regenerate session ID after authentication state change.
    // Prevents session fixation — if an attacker planted a known session
    // ID before login, that ID is invalidated when a new one is issued.
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = result.lastInsertRowid;
      req.session.username = trimmedUsername;
      // Explicit save before redirect to avoid a race where the redirect
      // fires before the session is persisted.
      req.session.save((err) => {
        if (err) return next(err);
        res.redirect('/gymnasium');
      });
    });
  } catch (err) {
    next(err);
  }
});

// ===== Login =====

router.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/gymnasium');
  res.render('login', { error: null, username: '' });
});

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).render('login', { error: 'Invalid input.', username: '' });
    }

    const trimmedUsername = username.trim();
    const user = findUserByUsername.get(trimmedUsername);

    // SEC[CWE-208]: Even if the user does not exist, run bcrypt against
    // the dummy hash so response time is constant. Without this, an
    // attacker can detect valid usernames by measuring response latency.
    const hashToCheck = user ? user.password_hash : DUMMY_HASH;
    const passwordOk = await bcrypt.compare(password, hashToCheck);

    // SEC[CWE-204]: Generic error message — does not distinguish between
    // "username not found" and "password incorrect". Prevents user
    // enumeration via response content.
    if (!user || !passwordOk) {
      return res.status(401).render('login', {
        error: 'Invalid username or password.',
        username: trimmedUsername
      });
    }

    // SEC[CWE-384]: Regenerate session ID on successful login.
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.save((err) => {
        if (err) return next(err);
        res.redirect('/gymnasium');
      });
    });
  } catch (err) {
    next(err);
  }
});

// ===== Logout =====

router.post('/logout', (req, res, next) => {
  // SEC[CWE-613]: Server-side session destruction on logout. Just clearing
  // the cookie client-side is insufficient — an attacker who captured the
  // cookie could still use it until the session expires. Destroying the
  // session record on the server invalidates it immediately.
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

module.exports = router;