import { createServer } from "@atproto/xrpc-server";
import { LEXICONS } from "./lexicons";

const server = createServer(LEXICONS);

server.method("com.atproto.server.createSession", async (ctx) => {
  return { encoding: "application/json", body: { token: "xxx" } };
});

server.method("app.bsky.feed.getFeed", async (ctx) => {
  return { encoding: "application/json", body: { feed: [] } };
});

// Object-literal handler map form (also used by some AT-Proto services).
const handlers = {
  "com.atproto.repo.putRecord": async (_ctx: unknown) => ({ ok: true }),
  "chat.bsky.convo.getConvo": async (_ctx: unknown) => ({ ok: true }),
};

export { server, handlers };
