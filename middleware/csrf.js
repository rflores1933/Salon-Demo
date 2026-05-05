const crypto = require('crypto');

// SEC[CWE-352]: CSRF tokens are generated per-session, kept server-side
// in req.session.csrfToken, and exposed to views via res.locals.csrfToken
// so every form can include them in a hidden _csrf field. State-changing
// requests (POST, PUT, PATCH, DELETE) must submit a matching token or
// they are rejected with HTTP 403.

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// SEC[CWE-208]: timingSafeEqual is used instead of === to prevent
// timing-based information leaks about the token's value. Standard ===
// short-circuits on the first differing character, which is observable
// over the network and lets an attacker brute-force tokens one byte at
// a time. timingSafeEqual always compares all bytes.
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function csrfMiddleware(req, res, next) {
  if (!req.session) {
    return next(new Error('Session middleware required before CSRF middleware'));
  }

  if (!req.session.csrfToken) {
    req.session.csrfToken = generateToken();
  }

  res.locals.csrfToken = req.session.csrfToken;

  const stateChanging = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!stateChanging.includes(req.method)) {
    return next();
  }

  const submitted = req.body && req.body._csrf;
  if (!safeCompare(submitted, req.session.csrfToken)) {
    const err = new Error('Invalid CSRF token');
    err.status = 403;
    err.expose = true;
    return next(err);
  }

  next();
}

module.exports = { csrfMiddleware };