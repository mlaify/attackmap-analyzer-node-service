import { Hono } from 'hono';

// Chained calls: one statement per route in effect.
export const postsRoute = new Hono()
  .get('/', (c) => c.json([]))
  .post('/', (c) => c.json({ ok: true }, 201))
  .delete('/:id', (c) => c.body(null, 204));
