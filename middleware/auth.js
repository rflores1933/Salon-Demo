// SEC[CWE-285, CWE-862]: Authorization gate for any route that requires
// a logged-in user. Routes import requireAuth and place it before their
// handler. Unauthenticated requests are redirected to /login rather than
// returning a 401, which is appropriate for a session-cookie browser app.
// Authorization checks happen at the route level (not the controller),
// which makes it impossible to accidentally ship a protected route
// without a gate — a missing gate is visible at a glance in the routes file.

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

module.exports = { requireAuth };