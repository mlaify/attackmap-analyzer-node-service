module.exports = function legacyRoutes(app) {
  app.post('/legacy/import', (req, res) => res.sendStatus(202));
};
