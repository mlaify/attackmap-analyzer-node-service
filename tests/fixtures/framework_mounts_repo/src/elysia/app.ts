import { Elysia } from 'elysia';

const users = new Elysia({ prefix: '/users' })
  .get('/', () => [])
  .post('/', () => ({ ok: true }));

export const app = new Elysia()
  .use(users)
  .group('/v1', (v1) => v1.get('/ping', () => 'pong').delete('/cache', () => null))
  .guard({ beforeHandle: requireAuth }, (guarded) => guarded.post('/orders', () => ({ ok: true })));
