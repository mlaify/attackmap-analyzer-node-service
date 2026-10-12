const fp = require('fastify-plugin');

module.exports = fp(async function sharedRoutes(instance) {
  instance.get('/health', async () => ({ ok: true }));
});
