import { initTRPC } from "@trpc/server";
import { createHTTPServer } from "@trpc/server/adapters/standalone";

const t = initTRPC.create();
const publicProcedure = t.procedure;

export const appRouter = t.router({
  listUsers: publicProcedure.query(() => []),
  createUser: publicProcedure.mutation(() => ({ ok: true })),
  streamEvents: publicProcedure.subscription(() => null),
});

createHTTPServer({ router: appRouter });
