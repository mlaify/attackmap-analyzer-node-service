import Koa from "koa";
import Router from "@koa/router";

const app = new Koa();
const router = new Router();

router.get("/koa-hello", (ctx) => { ctx.body = "hi"; });
router.post("/koa-items", (ctx) => { ctx.body = { ok: true }; });

app.use(router.routes());
export default app;
