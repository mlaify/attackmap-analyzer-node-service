module.exports = (router) => {
  router.get('/status/deep', (req, res) => res.json({ ok: true }));
};
