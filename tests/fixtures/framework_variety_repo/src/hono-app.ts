import { Hono } from "hono";

const app = new Hono();

app.get("/hello", (c) => c.text("hi"));
app.post("/hello", (c) => c.json({ ok: true }));

export default app;
