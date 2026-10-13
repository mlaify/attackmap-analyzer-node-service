const Fastify = require('fastify');
const usersRoutes = require('./routes/users');

const app = Fastify();

// The full declaration form.
app.route({
  method: ['GET', 'HEAD'],
  url: '/status',
  handler: async () => ({ ok: true }),
});
app.route({
  method: 'DELETE',
  url: '/sessions/:id',
  preHandler: [app.authenticate],
  handler: async () => null,
});

// Plugins in other files, under a prefix.
app.register(usersRoutes, { prefix: '/users' });
app.register(require('./routes/admin'), { prefix: '/admin' });
// fastify-plugin breaks encapsulation: `prefix` doesn't apply.
app.register(require('./routes/shared'), { prefix: '/ignored' });

app.listen({ port: 3000 });
