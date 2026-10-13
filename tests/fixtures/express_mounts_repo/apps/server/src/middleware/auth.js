exports.requireAuth = (req, res, next) => (req.user ? next() : res.sendStatus(401));
exports.requireRole = (role) => (req, res, next) => (req.user.role === role ? next() : res.sendStatus(403));
