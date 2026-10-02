from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, line_snippet, read_source, rel

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EdgeHint,
    EntrypointHint,
    ExternalCall,
    ProtocolHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx"}
# Pruned by repo-relative directory name (attackmap.sdk.fs, AttackMap#253).
SKIP_DIRS = DEFAULT_SKIP_DIRS | {".svelte-kit"}

# ---- Route extraction ---------------------------------------------------------

# Express / Hono / Koa / Elysia / Fastify share this shape:
# `<var>.<verb>('/path', ...)`. So does every `map.get('k')`,
# `req.get('Authorization')` and HTTP-client call (`axios.get('/x')`), so a
# match only becomes a route when the receiver is a known router (see
# ROUTER_ASSIGN_PATTERN / ROUTER_PARAM_PATTERN / CONVENTIONAL_ROUTER_NAMES) and
# the path literal is rooted (`/...`) or the `*` wildcard. Verbs are lower-case
# in every framework, so the match is case-sensitive.
EXPRESS_ROUTE_PATTERN = re.compile(
    r"\b([A-Za-z_$][A-Za-z0-9_$]*)\.(get|post|put|patch|delete|options|head|all)\(\s*['\"`]([^'\"`]+)['\"`]",
)

# Names that hold a router/app: `const app = express()`, `express.Router()`,
# `Router()`, `new Router()`, `new Hono()`, `new Koa()`, `new Elysia()`,
# `fastify(...)`, `Fastify(...)`, `polka()`.
ROUTER_ASSIGN_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[^=;\n]+)?=\s*(?:await\s+)?"
    r"(?:express(?:\.Router)?\s*\(|Router\s*\(|fastify\s*\(|Fastify\s*\(|polka\s*\(|"
    r"new\s+(?:Hono|OpenAPIHono|Koa|Router|KoaRouter|Elysia)\b)",
)
# Function parameters typed as a router/app: `(router: Router)`,
# `(app: express.Express)`, `(fastify: FastifyInstance)`, `(app: Hono)`.
ROUTER_PARAM_PATTERN = re.compile(
    r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\??\s*:\s*(?:express\.)?"
    r"(?:Router|IRouter|Express|Application|FastifyInstance|Hono|Elysia|KoaRouter)\b",
)
# Untyped JS routinely receives the app as a bare parameter
# (`module.exports = (app) => { app.get('/x', ...) }`); these conventional
# names are trusted as routers without a visible assignment.
CONVENTIONAL_ROUTER_NAMES = frozenset({"app", "router", "server", "fastify"})

# HTTP-client receivers. `<client>.<verb>('/path' | 'https://...')` is an
# *outbound* call, recorded as an ExternalCall with its method, never a route.
# Instances made with `axios.create(...)` / `got.extend(...)` / `ky.create(...)`
# are tracked too (CLIENT_ASSIGN_PATTERN).
KNOWN_CLIENT_NAMES = frozenset(
    {"axios", "got", "ky", "api", "http", "https", "client", "fetcher", "superagent", "request", "httpClient", "apiClient"}
)
CLIENT_ASSIGN_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[^=;\n]+)?=\s*"
    r"(?:axios\.create|got\.extend|ky\.(?:create|extend))\s*\(",
)
CLIENT_VERBS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})

# `app.use('/prefix', router)` — subsequent routes on `router` inherit the prefix
# in the same file. Captures (owner_var, prefix, mounted_var).
EXPRESS_USE_MOUNT_PATTERN = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
)

# Chained `router.route('/path').get(...).post(...)` shape. Handler bodies
# often contain their own parens (`res.status(200).end()`), so a single
# balanced-paren regex won't hold. Match the `.route(...)` opener alone
# and scan forward from its end with CHAIN_VERB_PATTERN for the chained
# verbs, terminating at the first line that doesn't start with `.`.
EXPRESS_ROUTE_OPENER_PATTERN = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*route\(\s*['\"]([^'\"]+)['\"]\s*\)",
)
CHAIN_VERB_PATTERN = re.compile(
    r"\.\s*(get|post|put|patch|delete|options|head|all)\s*\(",
    re.IGNORECASE,
)
CHAIN_WINDOW = 800  # chars scanned after `.route(...)` for chained verbs

# NestJS decorators. `@Controller('users')` above a class binds a prefix;
# `@Get('active')` / `@Post()` / `@All('*')` on methods declare routes.
# The class itself is detected via `NESTJS_CONTROLLER_PATTERN`; per-method
# routes via `NESTJS_METHOD_PATTERN`.
NESTJS_CONTROLLER_PATTERN = re.compile(
    r"@Controller\(\s*(?:['\"]([^'\"]*)['\"]\s*)?\)",
)
NESTJS_METHOD_PATTERN = re.compile(
    r"@(Get|Post|Put|Patch|Delete|Options|Head|All)\(\s*(?:['\"]([^'\"]*)['\"]\s*)?\)",
    re.IGNORECASE,
)

# tRPC: `t.procedure.query(...)`, `t.procedure.mutation(...)`, etc. Also
# `router({ foo: publicProcedure.query(...) })`. Emit the procedure name
# as the route "path" prefixed with `trpc:` so downstream consumers know
# it's not a URL.
TRPC_PROCEDURE_PATTERN = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:publicProcedure|protectedProcedure|t\.procedure|procedure)\s*\.\s*(query|mutation|subscription)\s*\(",
)

# AT Protocol / XRPC handler registration. The Bluesky server registers
# handlers per NSID via `server.method('com.atproto.foo', handler)` or
# `xrpc.method('app.bsky.feed.getFeed', handler)`. Also captures the
# `createServer({ 'com.atproto.foo': handler })` object-literal form.
XRPC_HANDLER_PATTERN = re.compile(
    r"\b(?:server|xrpc)\.method\(\s*['\"]((?:com|app|tools|chat)\.[A-Za-z0-9_.]+)['\"]",
)
XRPC_LEXICON_KEY_PATTERN = re.compile(
    r"['\"]((?:com|app|tools|chat)\.[A-Za-z0-9_.]{3,})['\"]\s*:\s*(?:async\s*)?(?:\([^)]*\)|function|handler)",
)

# NextJS App-Router file-based routes: `app/**/route.ts` where each HTTP
# method is a named export (`export async function GET(...)`). Detected
# by combining file path + exported function name.
NEXTJS_APP_ROUTE_EXPORT_PATTERN = re.compile(
    r"^\s*export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*\(",
    re.MULTILINE,
)

# ---- Entrypoints --------------------------------------------------------------

ENTRYPOINT_PATTERNS = [
    (re.compile(r"\bapp\.listen\s*\(", re.IGNORECASE), "entrypoint:express_listen"),
    (re.compile(r"\bcreateServer\s*\(", re.IGNORECASE), "entrypoint:create_server"),
    (re.compile(r"\bfastify\s*\(", re.IGNORECASE), "entrypoint:fastify_server"),
    (re.compile(r"\bnew\s+Hono\s*\("), "entrypoint:hono_app"),
    (re.compile(r"\bnew\s+Elysia\s*\("), "entrypoint:elysia_app"),
    (re.compile(r"\bnew\s+Koa\s*\("), "entrypoint:koa_app"),
    (re.compile(r"\bregisterHandler\b|\bregisterRoute\b", re.IGNORECASE), "entrypoint:handler_registration"),
    # NestJS. `NestFactory.create(AppModule)` is the canonical bootstrap.
    (re.compile(r"\bNestFactory\.create\s*\("), "entrypoint:nestjs_bootstrap"),
    (re.compile(r"@Module\s*\(\s*\{"), "entrypoint:nestjs_module"),
    # tRPC server bootstrap
    (re.compile(r"\bcreateHTTPServer\s*\(\s*\{"), "entrypoint:trpc_http_server"),
    # XRPC / AT Protocol server
    (re.compile(r"\bcreateServer\s*\(\s*(?:LEXICONS|lexicons|schemas)"), "entrypoint:xrpc_server"),
    # Async workers
    (re.compile(r"\bnew\s+Worker\s*\(\s*['\"]"), "entrypoint:bullmq_worker"),
    (re.compile(r"\bnew\s+Queue\s*\(\s*['\"]"), "entrypoint:bullmq_queue"),
    (re.compile(r"\bconsumer\.subscribe\s*\("), "entrypoint:kafka_consumer"),
    (re.compile(r"\bkafka\.consumer\s*\("), "entrypoint:kafka_consumer"),
    (re.compile(r"\bproducer\.send\s*\("), "entrypoint:kafka_producer"),
]

# BullMQ worker/queue name lets us cite the async edge target.
BULLMQ_QUEUE_NAME_PATTERN = re.compile(
    r"\bnew\s+(?:Worker|Queue)\s*\(\s*['\"]([A-Za-z0-9_.-]+)['\"]",
)
# Kafka topic edges — `consumer.subscribe({ topic: 'foo' })` or `topics: ['a','b']`.
KAFKA_TOPIC_PATTERN = re.compile(
    r"\btopics?\s*:\s*(?:['\"]([A-Za-z0-9_.-]+)['\"]|\[\s*['\"]([A-Za-z0-9_.-]+)['\"])",
)

# ---- Outbound HTTP / env-driven edges ----------------------------------------

OUTBOUND_PATTERNS = [
    re.compile(r"\bfetch\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    # `axios.get(url)` / `got.post(url)` carry a method; they're handled by
    # the client-receiver branch of _extract_routes instead.
    re.compile(r"\bgot\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\bundici\.(?:request|fetch)\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\bofetch\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
]
ENV_URL_PATTERN = re.compile(r"process\.env\.([A-Z0-9_]+_URL)\b")

# ---- Data stores --------------------------------------------------------------

DB_PATTERNS = [
    (re.compile(r"\bnew\s+PrismaClient\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bPool\s*\(\s*\{", re.IGNORECASE), "postgresql"),
    # The `pg` driver by import/require only; a bare `pg` word matched
    # comments, class names (`pg-header`) and loop variables.
    (
        re.compile(
            r"\bfrom\s+['\"](?:pg|pg-pool|pg-promise|postgres)['\"]"
            r"|\brequire\(\s*['\"](?:pg|pg-pool|pg-promise|postgres)['\"]\s*\)"
            r"|\bnode-postgres\b"
        ),
        "postgresql",
    ),
    (re.compile(r"\bknex\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bdrizzle\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bmongoose\.connect\s*\(", re.IGNORECASE), "mongodb"),
    (re.compile(r"\bMongoClient\s*\(", re.IGNORECASE), "mongodb"),
    (re.compile(r"\bredis\.createClient\s*\(", re.IGNORECASE), "redis"),
    (re.compile(r"\bioredis\b|\bnew\s+Redis\s*\(", re.IGNORECASE), "redis"),
    (re.compile(r"\bS3Client\b|\bPutObjectCommand\b|\bGetObjectCommand\b"), "object_storage"),
    (re.compile(r"\bnew\s+SQLite3?\b|\bbetter-sqlite3\b", re.IGNORECASE), "sqlite"),
]

# ---- Auth signals -------------------------------------------------------------

AUTH_PATTERNS = [
    (re.compile(r"\bAuthorization\b"), "authorization_header"),
    (re.compile(r"\bBearer\b"), "bearer_token"),
    (re.compile(r"\bjwt\b|\bjsonwebtoken\b", re.IGNORECASE), "jwt"),
    # Crypto/JWT verify and sign only: a bare `verify(` / `sign(` matched
    # test helpers, form validators and nearly every JS repo.
    (
        re.compile(
            r"\b(?:jwt|JWT|jsonwebtoken|jose|crypto(?:\.subtle)?)\.verify\s*\("
            r"|\bjwtVerify\s*\(|\bcrypto\.createVerify\s*\("
        ),
        "signature_verify",
    ),
    (
        re.compile(
            r"\b(?:jwt|JWT|jsonwebtoken|jose|crypto(?:\.subtle)?)\.sign\s*\("
            r"|\bnew\s+SignJWT\s*\(|\bcrypto\.createSign\s*\("
        ),
        "signature_sign",
    ),
    (re.compile(r"\boauth\b|\boidc\b", re.IGNORECASE), "oauth"),
    (re.compile(r"\bDPoP\b|\bdpop\b"), "dpop"),
    (re.compile(r"\bpassport\.authenticate\b", re.IGNORECASE), "passport_authenticate"),
    (re.compile(r"@UseGuards\("), "nestjs_guard"),
]

# ---- Secrets ------------------------------------------------------------------

SECRET_PATTERNS = [
    re.compile(r"process\.env\.([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*)"),
]
# EXPO_PUBLIC_* vars are inlined into the client bundle at build time —
# any secret named this way is effectively public. Emitted as a normal
# secret hint with the "expo_public:" name prefix so downstream findings
# can elevate them.
EXPO_PUBLIC_PATTERN = re.compile(r"process\.env\.(EXPO_PUBLIC_[A-Z0-9_]+)")


class NodeServiceAnalyzer:
    metadata = AnalyzerMetadata(
        name="node-service",
        display_name="Node Service Analyzer",
        version="0.2.0",
        description="Broad Node.js/TypeScript service analyzer covering Express/Fastify/NestJS/Hono/Koa/Elysia/tRPC + NextJS routes, XRPC handlers, workspaces, async workers.",
        scope="Node/TypeScript backend and monorepo repositories with service boundaries, framework handlers, RPC handlers, and inter-service/async messaging.",
        targets=["node-service", "node", "typescript-service"],
        languages=["javascript", "typescript"],
        priority=25,
        experimental=True,
        enabled_by_default=False,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False

        has_package = (root / "package.json").exists() or self._has_file(root, "package.json")
        has_typescript = (root / "tsconfig.json").exists() or self._has_file(root, "tsconfig.json")
        has_service_dirs = (root / "services").is_dir() or (root / "packages").is_dir() or (root / "apps").is_dir()
        has_pnpm_workspace = (root / "pnpm-workspace.yaml").exists()
        has_nx_or_turbo = (root / "nx.json").exists() or (root / "turbo.json").exists()

        if has_package and (has_typescript or has_service_dirs or has_pnpm_workspace or has_nx_or_turbo):
            return True

        for file_path in iter_repo_files(root, suffixes=CODE_SUFFIXES, skip_dirs=SKIP_DIRS):
            content = read_source(file_path)
            if not content:
                continue
            if re.search(
                r"\bapp\.listen\b|\bfastify\b|\bcreateServer\b|\bNestFactory\b|\bnew\s+Hono\b|\bcreateHTTPServer\b|services?/|packages?/",
                content,
            ):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        root_package_name = self._package_name_from(root / "package.json", root)

        # Workspaces contribute service topology hints (one per workspace
        # package). Done once, up front, then per-file walk fills in the rest.
        self._emit_workspace_service_hints(root, result)

        for file_path in iter_repo_files(root, suffixes=CODE_SUFFIXES, skip_dirs=SKIP_DIRS):
            result.files_scanned += 1
            language = "typescript" if file_path.suffix.lower() in {".ts", ".tsx"} else "javascript"
            if language not in result.languages:
                result.languages.append(language)

            content = read_source(file_path)
            if content is None:
                continue

            relative = rel(file_path, root)
            service_name = self._infer_service_name(relative, root_package_name)
            service_role = self._infer_service_role(service_name, relative)

            # Service identity is inferred from the file's path (or the root
            # package name), not from a source line: anchor it at line 1.
            derived = f"inferred from path {relative}"
            self._append_unique_hint(
                result.service_hints, ServiceHint, f"service_name:{service_name}", relative,
                evidence=derived, confidence=0.6,
            )
            self._append_unique_hint(
                result.service_hints, ServiceHint, f"service_role:{service_role}", relative,
                evidence=derived, confidence=0.5,
            )

            self._extract_routes(content, relative, result)
            self._extract_nestjs_routes(content, relative, result)
            self._extract_trpc_procedures(content, relative, result)
            self._extract_xrpc_handlers(content, relative, result)
            self._extract_nextjs_file_routes(file_path, root, content, result)
            self._extract_entrypoint_hints(content, relative, result)
            self._extract_outbound_and_edges(content, relative, service_name, result)
            self._extract_async_worker_edges(content, relative, service_name, result)
            self._extract_datastore_hints(content, relative, result)
            self._extract_auth_hints(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    # ---- Route extractors ----

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        prefixes = self._collect_express_prefixes(content)
        routers = self._router_names(content, prefixes)

        for match in EXPRESS_ROUTE_PATTERN.finditer(content):
            owner, method, path = match.group(1), match.group(2).upper(), match.group(3)
            if owner not in routers or not self._is_route_path(path):
                continue
            prefix = prefixes.get(owner, "")
            full_path = self._join_route(prefix, path)
            # Express `.all()` matches every verb: core's sentinel is ANY.
            method = "ANY" if method == "ALL" else method
            self._append_unique_route(result, full_path, method, relative, line_of(content, match.start()))

        # `router.route('/x').get(...).post(...)`
        for match in EXPRESS_ROUTE_OPENER_PATTERN.finditer(content):
            owner, path = match.group(1), match.group(2)
            if owner not in routers or not self._is_route_path(path):
                continue
            prefix = prefixes.get(owner, "")
            full_path = self._join_route(prefix, path)
            # Scan forward from the opener for a short window; grab every
            # chained verb until the trail visibly ends (statement-ending
            # semicolon or a non-chain identifier at line start).
            window = content[match.end() : match.end() + CHAIN_WINDOW]
            terminator = window.find(";")
            if terminator != -1:
                window = window[:terminator]
            for verb_match in CHAIN_VERB_PATTERN.finditer(window):
                verb_line = line_of(content, match.end() + verb_match.start())
                verb = verb_match.group(1).upper()
                self._append_unique_route(result, full_path, "ANY" if verb == "ALL" else verb, relative, verb_line)

    @staticmethod
    def _router_names(content: str, prefixes: dict[str, str]) -> set[str]:
        """Receivers whose `.get('/x')` etc. declare inbound routes in this file."""
        names = set(CONVENTIONAL_ROUTER_NAMES)
        names.update(m.group(1) for m in ROUTER_ASSIGN_PATTERN.finditer(content))
        names.update(m.group(1) for m in ROUTER_PARAM_PATTERN.finditer(content))
        # `app.use('/api', v1)`: both sides of a prefix mount are routers.
        names.update(prefixes)
        names.update(owner for owner, _prefix, _mounted in EXPRESS_USE_MOUNT_PATTERN.findall(content))
        return names

    @staticmethod
    def _client_names(content: str, routers: set[str]) -> set[str]:
        """HTTP-client receivers in this file (never ones also bound as routers)."""
        names = set(KNOWN_CLIENT_NAMES)
        names.update(m.group(1) for m in CLIENT_ASSIGN_PATTERN.finditer(content))
        return names - routers

    @staticmethod
    def _is_route_path(path: str) -> bool:
        return path.startswith("/") or path == "*"

    def _collect_express_prefixes(self, content: str) -> dict[str, str]:
        """Walk `app.use('/prefix', router)` mounts to build per-owner prefixes.

        Chained mounts collapse: if `app.use('/api', v1)` and `v1.use('/orgs', orgs)`
        both appear in the file, `orgs` inherits `/api/orgs`. Fixed-point
        iteration keeps this simple; the graph is tiny in practice.
        """
        prefixes: dict[str, str] = {}
        pairs = [
            (owner, prefix, mounted)
            for owner, prefix, mounted in EXPRESS_USE_MOUNT_PATTERN.findall(content)
        ]
        # Iterate until no more prefix propagation happens.
        for _ in range(5):
            changed = False
            for owner, prefix, mounted in pairs:
                parent_prefix = prefixes.get(owner, "")
                new_prefix = self._join_route(parent_prefix, prefix)
                if prefixes.get(mounted) != new_prefix:
                    prefixes[mounted] = new_prefix
                    changed = True
            if not changed:
                break
        return prefixes

    @staticmethod
    def _join_route(prefix: str, path: str) -> str:
        base = prefix.rstrip("/") if prefix else ""
        # Prefixes may be declared without a leading slash (NestJS
        # `@Controller("users")`, Express `app.use("api", ...)`) — normalize
        # so the emitted path is always rooted at "/".
        if base and not base.startswith("/"):
            base = f"/{base}"
        if path == "":
            combined = base or "/"
        else:
            suffix = path if path.startswith("/") else f"/{path}"
            combined = f"{base}{suffix}"
        while "//" in combined:
            combined = combined.replace("//", "/")
        if combined != "/":
            combined = combined.rstrip("/") or "/"
        return combined

    def _extract_nestjs_routes(self, content: str, relative: str, result: ScanResult) -> None:
        # A file's @Controller() (there's typically one per file) sets the
        # prefix; each @Get/@Post/etc. below it is a route.
        controller_match = NESTJS_CONTROLLER_PATTERN.search(content)
        if controller_match:
            prefix = controller_match.group(1) or ""
        else:
            # No controller decorator on this file; nothing to do.
            if not NESTJS_METHOD_PATTERN.search(content):
                return
            prefix = ""
        for match in NESTJS_METHOD_PATTERN.finditer(content):
            verb, sub_path = match.group(1).upper(), (match.group(2) or "")
            full_path = self._join_route(prefix, sub_path)
            method = "ANY" if verb == "ALL" else verb
            self._append_unique_route(result, full_path, method, relative, line_of(content, match.start()))

    def _extract_trpc_procedures(self, content: str, relative: str, result: ScanResult) -> None:
        for match in TRPC_PROCEDURE_PATTERN.finditer(content):
            name, kind = match.group(1), match.group(2).lower()
            method = "POST" if kind in {"mutation"} else "GET" if kind == "query" else "STREAM"
            self._append_unique_route(result, f"trpc:{name}", method, relative, line_of(content, match.start()))

    def _extract_xrpc_handlers(self, content: str, relative: str, result: ScanResult) -> None:
        seen: set[str] = set()
        for match in XRPC_HANDLER_PATTERN.finditer(content):
            nsid = match.group(1)
            if nsid in seen:
                continue
            seen.add(nsid)
            self._append_unique_route(result, f"/xrpc/{nsid}", "ANY", relative, line_of(content, match.start()))
            self._append_unique_hint(
                result.protocol_hints, ProtocolHint, f"atproto_lexicon:{nsid}", relative,
                content=content, offset=match.start(), confidence=0.8,
            )
        for match in XRPC_LEXICON_KEY_PATTERN.finditer(content):
            nsid = match.group(1)
            if nsid in seen:
                continue
            seen.add(nsid)
            self._append_unique_route(result, f"/xrpc/{nsid}", "ANY", relative, line_of(content, match.start()))
            self._append_unique_hint(
                result.protocol_hints, ProtocolHint, f"atproto_lexicon:{nsid}", relative,
                content=content, offset=match.start(), confidence=0.8,
            )

    def _extract_nextjs_file_routes(
        self, file_path: Path, root: Path, content: str, result: ScanResult
    ) -> None:
        relative = rel(file_path, root)
        parts = relative.split("/")

        # App Router: `app/**/route.ts` where each HTTP verb is a named export.
        if file_path.name in {"route.ts", "route.tsx", "route.js", "route.mjs"} and "app" in parts:
            app_idx = parts.index("app")
            segments = parts[app_idx + 1 : -1]  # everything between `app/` and `route.ts`
            url_path = "/" + "/".join(self._nextjs_segment(s) for s in segments)
            url_path = url_path.rstrip("/") or "/"
            for match in NEXTJS_APP_ROUTE_EXPORT_PATTERN.finditer(content):
                # group(1), not start(): `^\s*` in MULTILINE also swallows blank lines above.
                self._append_unique_route(
                    result, url_path, match.group(1).upper(), relative, line_of(content, match.start(1))
                )
            return

        # Pages Router: `pages/api/**/*.ts`. Every file under `pages/api/` is
        # a route; the default export is the handler. We don't know the
        # method(s) without deeper parsing, so we emit "ANY".
        if "pages" in parts:
            pages_idx = parts.index("pages")
            if len(parts) > pages_idx + 1 and parts[pages_idx + 1] == "api":
                segments = parts[pages_idx + 2 :]
                # drop extension from the final segment
                last = segments[-1].rsplit(".", 1)[0] if segments else ""
                if last == "index":
                    segments = segments[:-1]
                else:
                    segments = segments[:-1] + [last]
                url_path = "/api/" + "/".join(self._nextjs_segment(s) for s in segments)
                url_path = url_path.rstrip("/") or "/api"
                # The default export is the handler; fall back to line 1.
                default_export = re.search(r"^[ \t]*export\s+default\b", content, re.MULTILINE)
                line = line_of(content, default_export.start()) if default_export else 1
                self._append_unique_route(result, url_path, "ANY", relative, line)

    @staticmethod
    def _nextjs_segment(segment: str) -> str:
        # NextJS dynamic segment: `[id]` → `:id`, `[...slug]` → `*slug`.
        if segment.startswith("[...") and segment.endswith("]"):
            return f"*{segment[4:-1]}"
        if segment.startswith("[") and segment.endswith("]"):
            return f":{segment[1:-1]}"
        return segment

    def _extract_entrypoint_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_unique_hint(
                    result.entrypoint_hints, EntrypointHint, hint, relative,
                    content=content, offset=match.start(), confidence=0.8,
                )

    def _extract_outbound_and_edges(
        self, content: str, relative: str, service_name: str, result: ScanResult
    ) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                target = match.group(1)
                self._append_unique_external(result, target, relative, content, match.start())
                target_service = self._service_from_url(target)
                if target_service:
                    self._append_unique_hint(
                        result.edge_hints, EdgeHint, f"edge:{service_name}->{target_service}", relative,
                        content=content, offset=match.start(), confidence=0.6,
                    )

        # `axios.get('/internal/health')`, `api.post('https://...')`: outbound
        # calls with a known verb, so the method is recorded for cross-repo
        # contract linking.
        clients = self._client_names(content, self._router_names(content, self._collect_express_prefixes(content)))
        for match in EXPRESS_ROUTE_PATTERN.finditer(content):
            owner, verb, target = match.group(1), match.group(2), match.group(3)
            if owner not in clients or verb not in CLIENT_VERBS:
                continue
            # A template literal's interpolation is the dynamic tail:
            # `/users/${id}` -> `/users/` (core treats a trailing `/` as `*`).
            target = target.split("${", 1)[0]
            if not (target.startswith("/") or re.match(r"https?://", target, re.IGNORECASE)):
                continue
            self._append_unique_external(result, target, relative, content, match.start(), method=verb.upper())
            target_service = self._service_from_url(target)
            if target_service:
                self._append_unique_hint(
                    result.edge_hints, EdgeHint, f"edge:{service_name}->{target_service}", relative,
                    content=content, offset=match.start(), confidence=0.6,
                )

        for match in ENV_URL_PATTERN.finditer(content):
            env_name = match.group(1)
            self._append_unique_external(result, f"env://{env_name}", relative, content, match.start())
            target_service = self._service_from_env_name(env_name)
            if target_service:
                self._append_unique_hint(
                    result.edge_hints, EdgeHint, f"edge:{service_name}->{target_service}", relative,
                    content=content, offset=match.start(), confidence=0.5,
                )

    def _extract_async_worker_edges(
        self, content: str, relative: str, service_name: str, result: ScanResult
    ) -> None:
        for match in BULLMQ_QUEUE_NAME_PATTERN.finditer(content):
            queue = match.group(1)
            self._append_unique_external(result, f"queue://bullmq/{queue}", relative, content, match.start())
            self._append_unique_hint(
                result.edge_hints, EdgeHint, f"edge:{service_name}->queue:{queue}", relative,
                content=content, offset=match.start(), confidence=0.8,
            )
        for match in KAFKA_TOPIC_PATTERN.finditer(content):
            topic = match.group(1) or match.group(2)
            if not topic:
                continue
            self._append_unique_external(result, f"queue://kafka/{topic}", relative, content, match.start())
            self._append_unique_hint(
                result.edge_hints, EdgeHint, f"edge:{service_name}->topic:{topic}", relative,
                content=content, offset=match.start(), confidence=0.8,
            )

    def _extract_datastore_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_unique_database(result, kind, relative, content, match.start())

    def _extract_auth_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in AUTH_PATTERNS:
            match = pattern.search(content)
            if match:
                self._append_unique_hint(
                    result.auth_hints, AuthHint, hint, relative, content=content, offset=match.start()
                )

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative, content, match.start())
        for match in EXPO_PUBLIC_PATTERN.finditer(content):
            # Expo prefix means the value is inlined into the client
            # bundle at build time — an important distinction downstream
            # findings should elevate. Tag it with an "expo_public:" prefix
            # so the finder can recognize it.
            self._append_unique_secret(result, f"expo_public:{match.group(1)}", relative, content, match.start())

    def _emit_workspace_service_hints(self, root: Path, result: ScanResult) -> None:
        """Read package.json `workspaces` (npm/yarn) and pnpm-workspace.yaml.

        For each workspace package, emit a `service_name:<pkg>` service hint
        anchored at the package's package.json `"name"` line. This gives downstream
        threat-model chain builders visibility into repos where services
        live outside `services/*` / `packages/*`.
        """
        seen: set[str] = set()
        # One pruned walk for every nested package.json; workspace globs are
        # matched against these repo-relative paths instead of `root.glob()`,
        # which descended node_modules and followed symlinks out of the repo.
        package_jsons: list[str] | None = None

        def matching(pattern: str) -> list[Path]:
            nonlocal package_jsons
            if package_jsons is None:
                package_jsons = [
                    rel(path, root) for path in iter_repo_files(root, names={"package.json"}, skip_dirs=SKIP_DIRS)
                ]
            wanted = [seg for seg in pattern.strip().strip("/").split("/") if seg not in {"", "."}]
            return [
                root / relative
                for relative in package_jsons
                if self._workspace_glob_match(wanted, relative.split("/")[:-1])
            ]

        root_pkg_text = read_source(root / "package.json", root=root)
        if root_pkg_text is not None:
            try:
                data = json.loads(root_pkg_text)
            except json.JSONDecodeError:
                data = None
            patterns = data.get("workspaces") if isinstance(data, dict) else None
            if isinstance(patterns, dict):
                patterns = patterns.get("packages", [])
            if isinstance(patterns, list):
                for pattern in patterns:
                    if not isinstance(pattern, str):
                        continue
                    for pkg_json in matching(pattern):
                        self._record_workspace_service(pkg_json, root, seen, result)

        text = read_source(root / "pnpm-workspace.yaml", root=root)
        if text is not None:
            # Lightweight yaml: pull quoted `packages:` list entries
            for pattern_match in re.finditer(r"-\s*['\"]?([^'\"\n]+)['\"]?", text):
                pattern = pattern_match.group(1).strip()
                if not pattern or pattern.startswith("#"):
                    continue
                for pkg_json in matching(pattern):
                    self._record_workspace_service(pkg_json, root, seen, result)

    @staticmethod
    def _workspace_glob_match(pattern: list[str], parts: list[str]) -> bool:
        """Match a workspace glob (``packages/*``, ``apps/**``) against dir parts."""
        if not pattern:
            return not parts
        head, rest = pattern[0], pattern[1:]
        if head == "**":
            return any(
                NodeServiceAnalyzer._workspace_glob_match(rest, parts[i:]) for i in range(len(parts) + 1)
            )
        return bool(parts) and fnmatch.fnmatchcase(parts[0], head) and NodeServiceAnalyzer._workspace_glob_match(
            rest, parts[1:]
        )

    def _record_workspace_service(
        self, pkg_json: Path, root: Path, seen: set[str], result: ScanResult
    ) -> None:
        pkg_name = self._package_name_from(pkg_json, root)
        if not pkg_name:
            return
        short = pkg_name.split("/")[-1].lower()
        if short in seen:
            return
        seen.add(short)
        relative = rel(pkg_json, root)
        text = read_source(pkg_json, root=root) or ""
        name_match = re.search(r'"name"\s*:', text)
        offset = name_match.start() if name_match else None
        for hint in (f"service_name:{short}", f"workspace_package:{pkg_name}"):
            self._append_unique_hint(
                result.service_hints, ServiceHint, hint, relative,
                content=text, offset=offset, confidence=0.9,
            )

    def _infer_service_name(self, relative: str, root_package_name: str | None) -> str:
        normalized = relative.replace("\\", "/")
        parts = normalized.split("/")
        if len(parts) >= 2 and parts[0] in {"services", "packages", "apps"}:
            return parts[1].lower()
        if root_package_name:
            return root_package_name.lower().split("/")[-1]
        return "repo-service"

    @staticmethod
    def _infer_service_role(service_name: str, relative: str) -> str:
        name = f"{service_name} {relative}".lower()
        if any(token in name for token in {"api", "server", "gateway", "http"}):
            return "api"
        if any(token in name for token in {"worker", "queue", "job", "consumer"}):
            return "worker"
        if any(token in name for token in {"store", "db", "cache", "redis"}):
            return "storage"
        return "service"

    @staticmethod
    def _service_from_url(target: str) -> str | None:
        try:
            host = urlparse(target).hostname or ""
        except ValueError:
            return None
        if not host:
            return None
        if host in {"localhost", "127.0.0.1"}:
            return "local-service"
        return host.split(".")[0].split("-")[0].lower()

    @staticmethod
    def _service_from_env_name(env_name: str) -> str | None:
        token = env_name.upper().removesuffix("_URL")
        if token.endswith("_SERVICE"):
            token = token.removesuffix("_SERVICE")
        token = token.replace("__", "_").strip("_")
        if not token:
            return None
        return token.lower().replace("_", "-")

    @staticmethod
    def _package_name_from(path: Path, root: Path) -> str | None:
        text = read_source(path, root=root)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        name = data.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        return None

    @staticmethod
    def _has_file(root: Path, name: str) -> bool:
        # Stops at the first match; never enters node_modules et al.
        return next(iter_repo_files(root, names={name}, skip_dirs=SKIP_DIRS), None) is not None

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_external(
        result: ScanResult, target: str, file: str, content: str, offset: int, *, method: str | None = None
    ) -> None:
        key = (target, method, file)
        if any((item.target, item.method, item.file) == key for item in result.external_calls):
            return
        line = line_of(content, offset)
        result.external_calls.append(
            ExternalCall(
                target=target, file=file, line=line, method=method,
                evidence_text=line_snippet(content, line) or target,
            )
        )

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, content: str, offset: int) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        line = line_of(content, offset)
        result.databases.append(
            DatabaseHint(kind=kind, file=file, line=line, evidence_text=line_snippet(content, line) or kind)
        )

    @staticmethod
    def _append_unique_hint(
        bucket: list,
        model: type,
        hint: str,
        file: str,
        *,
        content: str | None = None,
        offset: int | None = None,
        evidence: str | None = None,
        confidence: float | None = None,
    ) -> None:
        """Append a typed hint (Auth/Service/Edge/Entrypoint/Protocol) once per (hint, file).

        With ``content`` + ``offset`` the hint is located at that line and
        quotes it; without (path-derived hints) it is anchored at line 1 and
        ``evidence`` explains where it came from.
        """
        if any((item.hint, item.file) == (hint, file) for item in bucket):
            return
        if content is not None and offset is not None:
            line = line_of(content, offset)
            evidence_text = line_snippet(content, line) or evidence or hint
        else:
            line = 1
            evidence_text = evidence or hint
        extra = {"confidence": confidence} if confidence is not None else {}
        bucket.append(model(hint=hint, file=file, line=line, evidence_text=evidence_text, **extra))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, content: str, offset: int) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        line = line_of(content, offset)
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=line_snippet(content, line) or name)
        )
