async function adminRoutes(fastify) {
  fastify.addHook('onRequest', fastify.authenticate);
  fastify.delete('/users/:id', async () => null);
}

module.exports = adminRoutes;
