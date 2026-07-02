# Changelog

All notable changes to `attackmap-analyzer-node-service` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-25

### Added — closes AttackMap#17

- **NestJS decorator routing.** `@Controller(prefix)` combines with `@Get/@Post/@Put/@Patch/@Delete/@Options/@Head/@All` to emit full route paths. `entrypoint:nestjs_bootstrap`, `entrypoint:nestjs_module`, and `nestjs_guard` hints for `NestFactory.create`, `@Module(...)`, and `@UseGuards(...)`.
- **NextJS file-based routing.** App Router `app/**/route.ts` with `export async function GET/POST/…` emits method-specific routes; dynamic segments (`[id]`, `[...slug]`) become `:id` / `*slug`. Pages Router `pages/api/**/*.ts` emits `ANY` routes.
- **Express improvements.** `app.use('/prefix', router)` propagates prefixes through nested mounts (fixed-point iteration; three-level chains like `/api/v1/orgs/:orgId/members` resolve correctly). `router.route('/x').get().post()` chained syntax is now recognized. `.all()` maps to the `ANY` method sentinel.
- **Hono / Koa / Elysia** entrypoints (`new Hono()`, `new Koa()`, `new Elysia()`) plus their route decorators, which share the Express regex shape.
- **tRPC procedures.** `publicProcedure.query(...)` / `.mutation(...)` / `.subscription(...)` on named router keys emit `trpc:<name>` routes with method GET/POST/STREAM. `entrypoint:trpc_http_server` hint for `createHTTPServer`.
- **AT Protocol / XRPC handlers.** `server.method('com.atproto.foo', handler)`, `xrpc.method(...)`, and object-literal handler-map keys emit `/xrpc/<NSID>` routes plus `atproto_lexicon:<NSID>` hints. Progresses AttackMap#19.
- **`EXPO_PUBLIC_*` client-bundled secret rule.** From the Bluesky FINDINGS §3 — any secret named `process.env.EXPO_PUBLIC_*` is inlined into the client bundle at build time. Emitted with an `expo_public:` name prefix so downstream findings can elevate it.
- **Workspace topology.** `package.json` `workspaces` (npm/yarn form, and `{ packages: [...] }` object form) plus `pnpm-workspace.yaml` are parsed. Each workspace package with its own `package.json` emits `service_name:<pkg>` and `workspace_package:<pkg-name>` hints.
- **Async workers.** BullMQ (`new Worker`, `new Queue`) and Kafka (`kafka.consumer`, `consumer.subscribe`, `producer.send`) get their own entrypoint hints. Queue and topic names become outbound targets (`queue://bullmq/<name>`, `queue://kafka/<topic>`) plus per-service edges.
- **Additional data-store patterns.** Drizzle (SQL), better-sqlite3.
- **New fixture repos.** `nestjs_repo`, `nextjs_repo`, `framework_variety_repo`, `express_advanced_repo`, `xrpc_repo`, `expo_secrets_repo`, `pnpm_workspace_repo`, `async_workers_repo`.

### Changed

- Detect() now recognizes `pnpm-workspace.yaml`, `apps/*` (Nx/Turborepo convention), `nx.json`, `turbo.json`, and NestJS / Hono / tRPC bootstrap patterns.
- Route path normalization: prefixes without a leading slash (NestJS convention or Express `app.use("api", router)`) are rooted at `/` in the emitted path.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Broad Node.js/TypeScript service analyzer plugin for AttackMap
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-node-service/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mlaify/attackmap-analyzer-node-service/releases/tag/v0.2.0
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-node-service/releases/tag/v0.1.0
