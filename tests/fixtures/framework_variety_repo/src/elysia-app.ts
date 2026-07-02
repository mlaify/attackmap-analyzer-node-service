import { Elysia } from "elysia";

const app = new Elysia();
app.get("/elysia/ping", () => "pong");
app.post("/elysia/events", () => ({ ok: true }));

export default app;
