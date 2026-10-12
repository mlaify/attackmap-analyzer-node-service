# AttackMap Node Service Analyzer

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

`attackmap-analyzer-node-service` is a broad Node.js/TypeScript backend analyzer module for AttackMap.

It is designed for distributed service repositories and emits structured scan signals for:
- service identity and role hints
- route and handler registration hints
- outbound HTTP and env-configured service URLs
- datastore and storage usage hints
- auth/signing/token hints
- lightweight inter-service edge hints

This analyzer is intentionally heuristic and incremental. It is not Bluesky-specific.

### Mount paths (#4)

Routes carry the prefixes of every router mount above them, across files:

- Express / Koa `X.use('/prefix', [mw...,] router)`, Hono `X.route('/prefix', sub)` and `X.basePath('/prefix')`, Elysia `new Elysia({ prefix })` and `X.group('/prefix', (g) => ...)`, Koa `new Router({ prefix })`, and Fastify `X.register(plugin, { prefix })` (ignored for `fastify-plugin` wrapped plugins, as Fastify does);
- a router mounted at two prefixes gives one route per path, each with its own auth;
- route functions called with the app (`require('./routes/users')(app)`, `usersRoutes(app)`) register on it;
- chained calls count like separate statements: `new Hono().use(mw).get('/x', h).route('/y', sub)`;
- Fastify's full form `X.route({ method, url })` and NestJS `@Controller({ path })` are routes too.

Imports are followed through `require(...)` (including inline `app.use('/x', require('./x'))`), default / named / namespace `import`s, barrel re-exports (`export { x } from './x'`, `export * from`), `index` files, `compilerOptions.paths` / `baseUrl` from the nearest `tsconfig.json` / `jsconfig.json` (and relative `extends`), and workspace packages by their `package.json` name. Nothing outside the repo is read. Mounts made in test files are ignored. A router that no visible code mounts keeps its file-local path.

### Route auth (AttackMap#256)

Express, Koa, Hono, Elysia, Fastify and NestJS routes carry `auth` (`required` / `anonymous` / `unknown`), `guards` and `guard_evidence`:

- **`required`**:
  - route-local auth middleware: `router.post('/x', requireAuth, h)`, arrays, `router.route('/x').post(mw, h)`, and route options `{ preHandler | onRequest | beforeHandle: [...] }`; a registration made only of guards (`app.get('/x', isAuthorized())`) guards that path;
  - an earlier `X.use([path,] mw)`, `X.all('*', mw)`, Fastify `addHook('onRequest' | 'preHandler', mw)` or Elysia `onBeforeHandle(mw)` / `guard({ beforeHandle }, ...)` on the route's router, or on any router that mounts it (with the mount's own middleware);
  - NestJS `@UseGuards(...)` on the method or controller, or a global `useGlobalGuards(...)` / `APP_GUARD`. A metadata-driven role guard (`RolesGuard`, `PermissionsGuard`) counts only next to its `@Roles(...)` / `@Permissions(...)` metadata.
- **`anonymous`**:
  - a route whose full path is listed in a guard's `.unless({ path: ['/login', ...] })`;
  - a NestJS `@Public()` / `@SkipAuth()` / `@AllowAnonymous()` / `@SetMetadata('isPublic', true)` route, unless a guard is Passport's own `AuthGuard('...')`, which ignores that metadata.
- **`unknown`**: everything else. That includes `optionalAuth`-style middleware and NestJS `Optional...` guards, `.unless` lists with regexes or other keys, routers mounted somewhere the analyzer can't see, and middleware registered after the route.

Middleware counts as a guard by name: authentication (`requireAuth`, `authenticate`, `isAuthenticated`, `ensureLoggedIn`, `passport.authenticate(...)`, `expressjwt(...)`, `jwt(...)`, `verifyToken`, `bearerAuth(...)`, `fastify.authenticate`) or a role / permission check (`requireRole('admin')`, `isAdmin`, `authorize('admin')`, `checkPermissions`, `guard.check([...])`), which stays visible in `guards` for AttackMap's function-level authorization check. An inline hook that calls `request.jwtVerify()` counts too. Rate limiters, body parsers, CORS / CSRF / helmet, `optional` / `skip` / `public` variants and trackers such as `updateAuthenticatedUsers` don't.

**Not handled yet:** Next.js `middleware.ts` matchers, NestJS `RouterModule` / `setGlobalPrefix`, and dynamic mount paths (`app.use(prefix, router)` with a variable).

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-node-service.git
```

## Usage

```bash
attackmap analyze /path/to/repo --module node-service
```
