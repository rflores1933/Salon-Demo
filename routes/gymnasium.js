const express = require('express');
const { requireAuth } = require('../middleware/auth');
const db = require('../db');

const router = express.Router();

// SEC[CWE-862]: All gymnasium routes require authentication. The
// requireAuth middleware runs before any route handler in this router,
// so there is no way to add a new gymnasium route that accidentally
// skips the auth check.
router.use(requireAuth);

// SEC[CWE-89]: Prepared statements only. User input is bound, never
// concatenated into SQL.
const insertIntention = db.prepare(
  'INSERT INTO intentions (user_id, body, created_at) VALUES (?, ?, ?)'
);
const clearUserIntentions = db.prepare(
  'DELETE FROM intentions WHERE user_id = ?'
);
const getMyIntention = db.prepare(`
  SELECT body, created_at FROM intentions
  WHERE user_id = ?
  ORDER BY id DESC
  LIMIT 1
`);

const MIN_INTENTION_LENGTH = 1;
const MAX_INTENTION_LENGTH = 140;
const MAX_WHITEBOARD_LENGTH = 5000;

// SEC[CWE-20]: Server-side validation. Bounded length defends against
// storage abuse and unbounded rendering.
function validateIntention(body) {
  if (typeof body !== 'string') return 'Intention is required.';
  const trimmed = body.trim();
  if (trimmed.length < MIN_INTENTION_LENGTH) return 'Intention cannot be empty.';
  if (trimmed.length > MAX_INTENTION_LENGTH) {
    return `Intention must be ${MAX_INTENTION_LENGTH} characters or fewer.`;
  }
  return null;
}

router.get('/', (req, res) => {
  const myIntention = getMyIntention.get(req.session.userId);
  res.render('gymnasium', {
    username: req.session.username,
    myIntention: myIntention || null,
    whiteboard: req.session.whiteboard || '',
    error: null
  });
});

router.post('/intentions', (req, res, next) => {
  try {
    const error = validateIntention(req.body.body);
    if (error) {
      const myIntention = getMyIntention.get(req.session.userId);
      return res.status(400).render('gymnasium', {
        username: req.session.username,
        myIntention: myIntention || null,
        whiteboard: req.session.whiteboard || '',
        error
      });
    }

    const trimmed = req.body.body.trim();

    // SEC[CWE-639]: The user_id used for both clear and insert comes from
    // req.session.userId, which is set server-side at login. The client
    // never sends a user_id. This makes Insecure Direct Object Reference
    // (IDOR) structurally impossible — there is no parameter for an
    // attacker to manipulate.
    //
    // The transaction wraps clear+insert so the gymnasium never sees a
    // half-applied state where a user's old intention is gone but their
    // new one isn't yet recorded.
    const replace = db.transaction((userId, body) => {
      clearUserIntentions.run(userId);
      insertIntention.run(userId, body, Date.now());
    });
    replace(req.session.userId, trimmed);

    res.redirect('/gymnasium');
  } catch (err) {
    next(err);
  }
});

router.post('/intentions/clear', (req, res, next) => {
  try {
    // SEC[CWE-639]: Same defense as above — user_id sourced from session,
    // not from any client input. A user can only ever clear their own
    // intentions; the WHERE clause guarantees it.
    clearUserIntentions.run(req.session.userId);

    // SEC[CWE-359]: When the user clears their intention, the session
    // whiteboard is cleared with it. No user-generated scratch content
    // outlives the active session focus.
    req.session.whiteboard = '';

    res.redirect('/gymnasium');
  } catch (err) {
    next(err);
  }
});

router.post('/whiteboard', (req, res, next) => {
  try {
    const body = typeof req.body.body === 'string' ? req.body.body : '';

    // SEC[CWE-20]: Server-side length validation. Prevents unbounded
    // session memory growth from a single malicious or buggy client.
    if (body.length > MAX_WHITEBOARD_LENGTH) {
      return res.status(400).redirect('/gymnasium');
    }

    // SEC[CWE-359]: Whiteboard contents are stored in session memory
    // only — never written to disk, never persisted to the database.
    // When the session ends (logout, expiry, server restart), the
    // contents are destroyed. v0.0.1 deliberately stores no
    // user-generated content beyond the active session.
    req.session.whiteboard = body;

    res.redirect('/gymnasium');
  } catch (err) {
    next(err);
  }
});

module.exports = router;