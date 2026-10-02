// Untyped JS: the app is passed in under its conventional name.
module.exports = (app) => {
  app.post("/legacy/import", (_req, res) => res.sendStatus(202));
  app.all("*", (_req, res) => res.sendStatus(404));
};
