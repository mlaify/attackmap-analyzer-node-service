# Changelog

All notable changes to `attackmap-analyzer-node-service` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — typed signals instead of overloaded `AuthHint`s (AttackMap#258)

- **`auth_hints` now carries only auth signals** (`authorization_header`, `bearer_token`, `jwt`, `signature_verify`, `signature_sign`, `oauth`, `dpop`, `passport_authenticate`, `nestjs_guard`). Everything else moved to the typed SDK hint lists, with the same hint strings, so core's service-chain, topology and AT Protocol chain builders still pick them up:
  - `service_name:*`, `service_role:*`, `workspace_package:*` → `ServiceHint` (`service_hints`)
  - `edge:*` (HTTP, env-URL, BullMQ queue and Kafka topic edges) → `EdgeHint` (`edge_hints`)
  - `entrypoint:*` → `EntrypointHint` (`entrypoint_hints`)
  - `atproto_lexicon:*` → `ProtocolHint` (`protocol_hints`)
- **Every signal now cites a line and quotes it.** Routes, external calls, databases, auth/service/edge/entrypoint/protocol hints and secret hints carry `line` and (where the model has it) `evidence_text` from `attackmap.sdk.line_of` / `line_snippet`. Path-derived service hints are anchored at line 1 with `evidence_text: "inferred from path <file>"`; workspace service hints point at the package's `"name"` line. Typed hints set `confidence` (0.9 workspace packages, 0.8 entrypoints/lexicons/queue edges, 0.6 path-inferred service names and HTTP edges, 0.5 env-URL edges and service roles).
- **Breaking for direct consumers of `ScanResult.auth_hints`:** code that looked for `service_name:`/`edge:`/`entrypoint:`/`atproto_lexicon:` in `auth_hints` must read the typed lists instead. AttackMap core already does.
- New `tests/test_signal_conformance.py` asserts every emitted `AuthHint.hint` is in an explicit auth allow-list and every signal has an in-range `line` and evidence.

### Fixed — AttackMap#253

- **Repo walking now uses `attackmap.sdk.fs`.** `detect()` and `analyze()` walk with `iter_repo_files` and read with `read_source`. Skip dirs are matched by repo-relative name and pruned, so a repo checked out under a `build/`, `dist/` or `out/` directory is analyzed instead of yielding nothing, and `node_modules` is never descended.
- **`detect()` no longer walks `node_modules`.** The `**/package.json` / `**/tsconfig.json` probes used unpruned `root.glob()`; they now use the pruned walker and stop at the first match.
- **Workspace globs** (`workspaces`, `pnpm-workspace.yaml`) are matched against the pruned walk instead of `root.glob()`, so they can't follow symlinks out of the repo or pick up `node_modules` packages.
- **Symlinked files pointing outside the repo are not analyzed**, unreadable files no longer raise out of `analyze()`, and cp1252/latin-1 sources are decoded instead of dropped. AttackMap's own report directories are skipped.

### Changed

- Skip list is now the SDK's `DEFAULT_SKIP_DIRS` plus `.svelte-kit` (adds `vendor`, `target`, `venv`, `.venv`, `.tox`, `bower_components` and caches).
- Files are visited in sorted, depth-first order, so signal order is deterministic across filesystems. The set of signals is unchanged.
- Requires an AttackMap core that ships `attackmap.sdk.fs`.

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
