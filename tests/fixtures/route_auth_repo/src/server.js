const Fastify = require('fastify');

const app = Fastify({ logger: true });

app.post('/orders', { preHandler: [app.authenticate] }, createOrder);

app.register(async (fastify) => {
  fastify.addHook('onRequest', async (request) => {
    await request.jwtVerify();
  });
  fastify.post('/payments', pay);
}, { prefix: '/v1' });

app.post('/webhooks', receiveWebhook);

app.listen({ port: 3000 });
