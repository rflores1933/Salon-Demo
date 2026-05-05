const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const { csrfMiddleware } = require('./middleware/csrf');
const authRoutes = require('./routes/auth');
const gymnasiumRoutes = require('./routes/gymnasium');

const app = express();
const PORT = process.env.PORT || 3000;

// SEC[CWE-693]: Helmet sets a baseline of security HTTP headers — CSP,
// X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security.
// Defends against clickjacking, MIME sniffing, and a class of XSS.
app.use(helmet());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// SEC[CWE-79]: EJS auto-escapes output rendered with <%= %>, encoding HTML
// special characters. Primary defense against stored and reflected XSS.
// Templates must NEVER use <%- %> for user-supplied content.

// SEC[CWE-400]: Body size capped at 10kb to prevent memory exhaustion
// from oversized POST payloads.
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use(express.static(path.join(__dirname, 'public')));

// SEC[CWE-384, CWE-614, CWE-1004]: Session hardening. httpOnly blocks
// JS access to the cookie (XSS containment). sameSite 'lax' blocks the
// cookie from being sent on cross-site state-changing requests (CSRF
// defense in depth). secret loaded from env, never hardcoded.
// secure flag on in production so the cookie only travels over HTTPS.
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 2
  }
}));

// SEC[CWE-352]: Per-session CSRF token middleware. Generates token,
// exposes it to views via res.locals, validates on state-changing
// requests. Implementation in middleware/csrf.js.
app.use(csrfMiddleware);

app.use('/', authRoutes);
app.use('/gymnasium', gymnasiumRoutes);

app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/gymnasium');
  res.redirect('/login');
});

app.use((err, req, res, next) => {
  console.error(err);
  const status = err.status || 500;
  // SEC[CWE-209]: Never expose stack traces or internal error messages
  // to the client. Full error logged server-side; client gets generic text.
  res.status(status).send(err.expose ? err.message : 'Something went wrong.');
});

app.listen(PORT, () => {
  console.log(`Salon running on http://localhost:${PORT}`);
});