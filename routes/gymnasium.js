const express = require('express');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

// SEC[CWE-862]: All gymnasium routes require authentication. The
// requireAuth middleware runs before any route handler in this router,
// so there is no way to add a new gymnasium route that accidentally
// skips the auth check.
router.use(requireAuth);

// Route handlers (view gymnasium, create intention, clear intention)
// added in next pass.

module.exports = router;