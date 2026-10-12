"""Cross-file mounts, chained routers and per-route guards (#4)."""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from attackmap_analyzer_node_service import NodeServiceAnalyzer
from attackmap_analyzer_node_service import route_auth as ra
from attackmap_analyzer_node_service.modules import ModuleResolver, load_jsonc, parse_imports, parse_reexports

FIXTURES = Path(__file__).parent / "fixtures"


def _routes(path: Path) -> dict:
    return {f"{r.method} {r.path}": r for r in NodeServiceAnalyzer().analyze(path).routes}


@pytest.fixture(scope="module")
def express() -> dict:
    return _routes(FIXTURES / "express_mounts_repo")


@pytest.fixture(scope="module")
def frameworks() -> dict:
    return _routes(FIXTURES / "framework_mounts_repo")


# ---------- Express: cross-file mounts ----------


def test_router_mounted_from_another_file_gets_prefix_and_guard(express: dict) -> None:
    route = express["GET /api/users/:id"]
    assert route.file == "apps/server/src/routes/users.js"
    assert route.auth == "required"
    assert route.guards == ["requireAuth"]
    assert route.guard_evidence == "app.use('/api/users', requireAuth, users)"
    assert express["POST /api/users"].guards == ["requireAuth"]
    # The file-local paths are gone.
    assert "GET /:id" not in express and "POST /" not in express


def test_inline_require_mount_with_role_check(express: dict) -> None:
    route = express["DELETE /api/admin/users/:id"]
    assert route.auth == "required"
    # The role check stays distinguishable, so core's BFLA check sees it.
    assert route.guards == ["requireAuth", "requireRole"]
    assert "requireRole('admin')" in route.guard_evidence


def test_router_mounted_twice_gets_a_route_per_prefix(express: dict) -> None:
    assert express["PUT /v1/items/:id"].auth == "unknown"
    assert express["PUT /v2/items/:id"].auth == "required"
    assert express["PUT /v2/items/:id"].guards == ["requireAuth"]


def test_rate_limit_cors_and_body_parsers_are_not_guards(express: dict) -> None:
    assert express["POST /public/contact"].auth == "unknown"


def test_route_function_called_with_the_app_inherits_its_middleware(express: dict) -> None:
    # `app.use(requireAuth); require('./routes/legacy')(app);`
    route = express["POST /legacy/import"]
    assert route.auth == "required"
    assert route.guards == ["requireAuth"]
    # `const status = require('./routes/status'); status(app);`
    assert express["GET /status/deep"].guards == ["requireAuth"]


def test_function_definitions_are_not_calls(tmp_path: Path) -> None:
    # `setup(app) {` (a method) and `function setup(app) {` define, not call.
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "function setup(app) {\n  app.post('/a', h);\n}\n"
        "const plugin = { setup(app) { return app; } };\n"
        "app.use(requireAuth);\n"
        "setup(app);\n",
        encoding="utf-8",
    )
    assert _routes(tmp_path)["POST /a"].guards == ["requireAuth"]


def test_unmounted_router_and_test_mounts(express: dict) -> None:
    assert express["PATCH /orphan/:id"].auth == "unknown"
    # __tests__/users.test.js mounts users at /test-users: not a production path.
    assert not [key for key in express if "test-users" in key]


def test_barrel_reexport_tsconfig_paths_and_workspace_package(express: dict) -> None:
    # `import { ordersRouter } from './routes/v2'` -> routes/v2/index.ts re-export.
    orders = express["POST /v2/orders"]
    assert orders.file == "apps/server/src/routes/v2/orders.ts"
    assert orders.guards == ["authenticate"]
    # `@/routes/reports` via compilerOptions.paths in an `extends`ed tsconfig.
    assert express["GET /reports/daily"].file == "apps/server/src/routes/reports.ts"
    # `@acme/billing` -> packages/billing (package.json "main" is build output).
    billing = express["GET /billing/invoices/:id"]
    assert billing.file == "packages/billing/src/index.ts"
    assert billing.auth == "required"


# ---------- Fastify / Hono / Elysia / NestJS ----------


def test_fastify_route_object_and_register_prefixes(frameworks: dict) -> None:
    assert frameworks["GET /status"].auth == "unknown"
    assert frameworks["HEAD /status"].file == "src/fastify/server.js"
    sessions = frameworks["DELETE /sessions/:id"]
    assert sessions.auth == "required"
    assert sessions.guards == ["app.authenticate"]
    # register(importedPlugin, { prefix: '/users' })
    assert frameworks["GET /users/:id"].file == "src/fastify/routes/users.js"
    # register(require('./routes/admin'), { prefix }) and the plugin's own hook.
    admin = frameworks["DELETE /admin/users/:id"]
    assert admin.auth == "required"
    assert admin.guards == ["fastify.authenticate"]
    # A fastify-plugin wrapped plugin ignores `prefix`.
    assert frameworks["GET /health"].file == "src/fastify/routes/shared.js"
    assert not [key for key in frameworks if "/ignored" in key]


def test_hono_base_path_chained_routes_and_route_mounts(frameworks: dict) -> None:
    for key in ("GET /api/posts", "POST /api/posts", "DELETE /api/posts/:id"):
        assert frameworks[key].file == "src/hono/routes/posts.ts"
        assert frameworks[key].auth == "unknown"
    settings = frameworks["PUT /api/admin/settings"]
    assert settings.auth == "required"
    assert settings.guards == ["bearerAuth"]


def test_chain_starting_on_its_own_line(tmp_path: Path) -> None:
    (tmp_path / "api.ts").write_text(
        "import { Hono } from 'hono';\n"
        "export const api = new Hono();\n"
        "api\n  .get('/openapi', h)\n  .get('/me', h);\n"
        "const app = new Hono();\napp.route('/v1', api);\n",
        encoding="utf-8",
    )
    routes = _routes(tmp_path)
    assert "GET /v1/openapi" in routes and "GET /v1/me" in routes


def test_elysia_prefix_group_and_guard(frameworks: dict) -> None:
    assert frameworks["GET /users"].file == "src/elysia/app.ts"
    assert frameworks["POST /users"].auth == "unknown"
    assert frameworks["GET /v1/ping"].auth == "unknown"
    assert frameworks["DELETE /v1/cache"].file == "src/elysia/app.ts"
    orders = frameworks["POST /orders"]
    assert orders.auth == "required"
    assert orders.guards == ["requireAuth"]


def test_nestjs_class_guard_public_opt_out_and_role_guards(frameworks: dict) -> None:
    # `@Controller({ path: 'accounts' })` + `@UseGuards(AuthGuard)` on the class.
    assert frameworks["GET /accounts"].auth == "required"
    assert frameworks["GET /accounts"].guards == ["AuthGuard"]
    # `@Public()` on one method opts out (a bare AuthGuard class reads it).
    signup = frameworks["POST /accounts/signup"]
    assert signup.auth == "anonymous"
    assert signup.guard_evidence == "@Public()"
    remove = frameworks["DELETE /accounts/:id"]
    assert remove.guards == ["AuthGuard", "RolesGuard"]
    assert "@Roles('admin')" in remove.guard_evidence
    # Second controller in the file: its own prefix; RolesGuard without
    # @Roles and an Optional guard don't make a route required.
    assert frameworks["GET /lookups"].auth == "unknown"
    assert frameworks["POST /lookups"].auth == "unknown"


# ---------- Guard names ----------


@pytest.mark.parametrize(
    "name",
    [
        "requireAuth", "authenticate", "passport.authenticate", "isAuthenticated", "ensureLoggedIn",
        "ensureAuthenticated", "jwt", "expressjwt", "expressJwt", "verifyToken", "verifyJWT", "checkJwt",
        "authMiddleware", "authGuard", "requireLogin", "requireUser", "requireSession", "isLoggedIn",
        "security.isAuthorized", "bearerAuth", "basicAuth", "webhookAuth", "auth.required", "keycloak.protect",
        "protect", "withAuth", "validateToken", "apiKeyAuth", "requiresAuth", "authenticateJWT",
    ],
)
def test_authn_middleware_names(name: str) -> None:
    assert ra.guard_kind(name) == ra.AUTHN


@pytest.mark.parametrize(
    "name",
    [
        "requireRole", "requireRoles", "requireAdmin", "isAdmin", "hasRole", "hasAnyRole", "checkRole",
        "checkPermissions", "requirePermission", "authorize", "authorizeRoles", "adminOnly", "restrictTo",
        "permit", "guard.check", "requireScopes", "isSuperuser", "security.isAdmin",
    ],
)
def test_role_middleware_names(name: str) -> None:
    assert ra.guard_kind(name) == ra.ROLE


@pytest.mark.parametrize(
    "name",
    [
        "rateLimit", "limiter", "apiLimiter", "cors", "helmet", "bodyParser.json", "express.json",
        "express.urlencoded", "cookieParser", "session", "csrfProtection", "optionalAuth", "maybeAuth",
        "softAuth", "skipAuth", "security.updateAuthenticatedUsers", "verify.jwtChallenges", "oauth",
        "passport.initialize", "passport.session", "validate", "validateUser", "validateLogin", "logger",
        "compression", "authorRouter", "getAuthor", "clerkMiddleware", "ClerkExpressWithAuth", "upload.single",
        "admin", "decodeToken", "loadUser", "requireUnauthenticated",
    ],
)
def test_names_that_are_not_guards(name: str) -> None:
    assert ra.guard_kind(name) is None


def test_guard_only_registration_is_path_middleware(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/api/Users', security.isAuthorized());\n"
        "app.route('/api/Users/:id').get(security.isAuthorized());\n"
        "app.post('/login', passport.authenticate('local', { successRedirect: '/' }));\n"
        "app.post('/token', authenticate);\n",
        encoding="utf-8",
    )
    routes = _routes(tmp_path)
    assert routes["GET /api/Users"].guards == ["security.isAuthorized"]
    assert routes["GET /api/Users/:id"].auth == "required"
    # Passport's local strategy *is* the login handler, not a guard in front of one.
    assert routes["POST /login"].auth == "unknown"
    assert routes["POST /token"].auth == "required"


def test_same_file_plugin_whose_parameter_shadows_the_app(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const fastify = require('fastify')();\n"
        "const Fastify = require('fastify');\n"
        "const app = Fastify();\n"
        "async function routes(app) {\n  app.addHook('preHandler', app.verifyJwt);\n  app.get('/me', me);\n}\n"
        "app.get('/health', health);\n"
        "app.register(routes, { prefix: '/v1' });\n",
        encoding="utf-8",
    )
    routes = _routes(tmp_path)
    assert routes["GET /v1/me"].guards == ["app.verifyJwt"]
    assert routes["GET /health"].auth == "unknown"
    assert "GET /me" not in routes


def test_unknown_receivers_need_a_mount_to_become_routes(tmp_path: Path) -> None:
    (tmp_path / "cache.js").write_text(
        "module.exports = function warm(cache) {\n  cache.get('/config');\n};\n", encoding="utf-8"
    )
    (tmp_path / "plugin.js").write_text(
        "module.exports = async function (instance) {\n  instance.post('/jobs', run);\n};\n", encoding="utf-8"
    )
    (tmp_path / "server.js").write_text(
        "const fastify = require('fastify')();\n"
        "fastify.register(require('./plugin'), { prefix: '/queue' });\n",
        encoding="utf-8",
    )
    routes = _routes(tmp_path)
    assert "POST /queue/jobs" in routes
    assert not [key for key in routes if "config" in key]


def test_mount_cycles_and_self_mounts_terminate(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text(
        "const router = require('express').Router();\nconst b = require('./b');\n"
        "router.use('/b', b);\nrouter.use('/self', router);\nrouter.get('/x', h);\nmodule.exports = router;\n",
        encoding="utf-8",
    )
    (tmp_path / "b.js").write_text(
        "const router = require('express').Router();\nconst a = require('./a');\n"
        "router.use('/a', a);\nrouter.get('/y', h);\nmodule.exports = router;\n",
        encoding="utf-8",
    )
    routes = NodeServiceAnalyzer().analyze(tmp_path).routes
    assert routes and len(routes) <= 2 * ra._MAX_VARIANTS


# ---------- Modules ----------


def test_tsconfig_with_comments_and_trailing_commas() -> None:
    data = load_jsonc('{\n  // c\n  "a": "http://x/*not a comment*/", /* b */\n  "p": ["x",],\n}\n')
    assert data == {"a": "http://x/*not a comment*/", "p": ["x"]}
    assert load_jsonc("{ unterminated /* ") is None


def test_import_and_reexport_forms() -> None:
    imports = parse_imports(
        "const a = require('./a');\nconst { b, c: d } = require('./bc');\n"
        "const e = require('./e').default;\nconst f = require('./f').router;\n"
        "import g, { h as i, type J } from './g';\nimport * as ns from './ns';\n"
    )
    assert imports["a"].name == "*" and imports["d"].name == "c" and imports["b"].spec == "./bc"
    assert imports["e"].name == "*" and imports["f"].name == "router"
    assert imports["g"].name == "default" and imports["i"].name == "h" and imports["J"].spec == "./g"
    assert imports["ns"].name == "*"
    reexports = parse_reexports(
        "export { default as users, admin } from './users';\nexport * from './misc';\n"
        "exports.legacy = require('./legacy');\n"
    )
    assert reexports.named["users"].name == "default" and reexports.named["admin"].name == "admin"
    assert reexports.named["legacy"].spec == "./legacy" and reexports.star == ["./misc"]


def test_specifiers_never_leave_the_repo(tmp_path: Path) -> None:
    resolver = ModuleResolver(tmp_path)
    assert resolver.bases("src/a.js", "../../../etc/passwd") == []
    assert resolver.bases("src/a.js", "./b") == ["src/b"]
    (tmp_path / "tsconfig.json").write_text('{"extends": "../../outside.json", "compilerOptions": {"paths": {"#/*": ["../*"]}}}')
    assert resolver.bases("src/a.js", "#/x") == []


# ---------- Robustness ----------

_SNIPPETS = [
    "const app = express();", "app.use('/api', requireAuth, users);", "router.get('/:id', h);",
    "new Hono().basePath('/x').get('/a', h).route('/b', sub)", ".group('/v1', (g) => g.post('/p', h))",
    "fastify.register(require('./p'), { prefix: '/q' })", "module.exports = fp(async function (f) {",
    "export { default as r } from './r';", "import x, { y as z } from '@/q';", "require('./r')(app);",
    "@Controller({ path: 'c' })", "@UseGuards(RolesGuard)", "@Roles('admin')", "app.route({ method: ['GET'], url: '/r' })",
    "(", ")", "{", "}", "[", "]", "'", '"', "`", "/*", "*/", "//", "\n", "=>", ",", ".", "export default ",
]


def test_fuzzed_sources_never_raise(tmp_path: Path) -> None:
    rng = random.Random(4)
    for index in range(40):
        text = "".join(rng.choice(_SNIPPETS) + rng.choice(["", " ", "\n"]) for _ in range(rng.randint(1, 120)))
        for cut in (text, text[: len(text) // 2], text[1:]):
            ra.bracket_pairs.cache_clear()
            routers = ra.FileRouters(cut, f"f{index}.ts")
            routers.names()
            parse_imports(cut)
            parse_reexports(cut)
            load_jsonc(cut)
            ra.function_at(cut, 0, len(cut))
            ra.NestFile(cut)
        (tmp_path / f"f{index}.ts").write_text(text, encoding="utf-8")
    (tmp_path / "tsconfig.json").write_text("{ /* broken", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": 1, "main": []}', encoding="utf-8")
    NodeServiceAnalyzer().analyze(tmp_path)


@pytest.mark.parametrize(
    "text",
    [
        "const app = new Hono()" + "\n  .get('/a', (c) => c.text('x'))" * 20000,
        "app.use(" * 20000 + ")" * 20000,
        "f(app);\n" * 30000,
        "/* " * 60000,
        "import a from './a';\n" * 20000 + "app.use('/x', a);\n" * 2000,
        "@Controller({ path: " + "'x'" * 20000,
        "module.exports = fp(" * 5000,
    ],
    ids=["long-chain", "nested-use", "many-calls", "open-comments", "many-imports", "controller", "nested-fp"],
)
def test_adversarial_sources_stay_fast(tmp_path: Path, text: str) -> None:
    (tmp_path / "app.ts").write_text(text, encoding="utf-8")
    (tmp_path / "tsconfig.json").write_text(text[:200_000], encoding="utf-8")
    started = time.monotonic()
    NodeServiceAnalyzer().analyze(tmp_path)
    assert time.monotonic() - started < 20
