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

### Route auth (AttackMap#256)

Express, Koa, Hono, Fastify and NestJS routes carry `auth` (`required` / `anonymous` / `unknown`), `guards` and `guard_evidence`:

- **`required`**:
  - route-local auth middleware: `router.post('/x', requireAuth, h)`, arrays, `router.route('/x').post(mw, h)`, and Fastify `{ preHandler | onRequest: [...] }`;
  - an earlier `X.use([path,] mw)`, `X.all('*', mw)` or Fastify `addHook('onRequest' | 'preHandler', mw)` on the route's router, or on the router that mounts it via `use([path,] mw..., router)` / `use(router.routes())` / `route(path, sub)`. Mounted routers imported from another file (`require('./routes/x')` / `import x from './routes/x'`, then `module.exports` / `export default`) are followed;
  - Fastify `register(async (fastify) => {...})` plugins inherit their parent's hooks;
  - NestJS `@UseGuards(...)` on the method or controller, or a global `useGlobalGuards(...)` / `APP_GUARD`.
- **`anonymous`**:
  - a route whose full path is listed in a guard's `.unless({ path: ['/login', ...] })`;
  - a NestJS `@Public()` / `@SkipAuth()` / `@AllowAnonymous()` / `@SetMetadata('isPublic', true)` route, unless a guard is Passport's own `AuthGuard('...')`, which ignores that metadata.
- **`unknown`**: everything else. That includes `optionalAuth`-style middleware, `.unless` lists with regexes or other keys, routers mounted somewhere this file can't see, and middleware registered after the route.

Middleware counts as a guard by name (`requireAuth`, `isAuthenticated`, `passport.authenticate(...)`, `expressjwt(...)`, `jwt(...)`, `bearerAuth(...)`, `fastify.authenticate`), or as an inline hook that calls `request.jwtVerify()`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-node-service.git
```

## Usage

```bash
attackmap analyze /path/to/repo --module node-service
```
