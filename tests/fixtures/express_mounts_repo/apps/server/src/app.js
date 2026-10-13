const express = require('express');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { requireAuth, requireRole } = require('./middleware/auth');
const users = require('./routes/users');
const items = require('./routes/items');
const publicRouter = require('./routes/public');
const status = require('./routes/status');

const app = express();
app.use(express.json());

// Cross-file mount with mount-level middleware.
app.use('/api/users', requireAuth, users);
// Inline require, with a role check at mount time.
app.use('/api/admin', requireAuth, requireRole('admin'), require('./routes/admin'));
// One router at two prefixes: each path gets its own auth.
app.use('/v1/items', items);
app.use('/v2/items', requireAuth, items);
// Rate limiters, CORS and body parsers are not guards.
app.use('/public', rateLimit({ windowMs: 60000 }), cors(), express.json(), publicRouter);

app.use(requireAuth);
// A route function called with the app inherits its earlier middleware.
require('./routes/legacy')(app);
status(app);

module.exports = app;
