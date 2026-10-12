import { Hono } from 'hono';
import { bearerAuth } from 'hono/bearer-auth';
import { postsRoute } from './routes/posts';
import admin from './routes/admin';

const app = new Hono().basePath('/api');

app.use('/admin/*', bearerAuth({ token: process.env.ADMIN_TOKEN! }));
app.route('/posts', postsRoute);
app.route('/admin', admin);

export default app;
