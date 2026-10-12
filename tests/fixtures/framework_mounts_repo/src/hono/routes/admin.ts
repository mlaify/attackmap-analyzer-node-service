import { Hono } from 'hono';

const admin = new Hono();

admin.put('/settings', (c) => c.json({ ok: true }));

export default admin;
