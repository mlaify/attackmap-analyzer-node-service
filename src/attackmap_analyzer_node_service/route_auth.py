"""Route-level auth and mount paths for the AttackMap#256 contract (#4).

Each emitted ``Route`` carries ``auth`` (``required`` / ``anonymous`` /
``unknown``), the ``guards`` that apply and the ``guard_evidence`` source text
that established the state. Core trusts a declared state over its own
same-file resolution, so this only declares what the source verifiably says.
Routes also get the prefixes of every router mount above them, across files.

**Express / Koa / Hono / Elysia / Fastify** — routers are tracked by variable:

- roots (``express()``, ``new Koa()``, ``new Hono()``, ``new Elysia()``,
  ``fastify()``) and routers (``express.Router()``, ``new Router({ prefix })``,
  ``new Elysia({ prefix })``, Hono ``app.basePath('/api')``);
- ``X.use([path,] mw...)``, ``X.all('*', mw...)``, Fastify
  ``X.addHook('onRequest' | 'preHandler' | ..., mw)`` and Elysia
  ``X.onBeforeHandle(mw)`` / ``X.guard({ beforeHandle })`` guard the routes
  registered on ``X`` *after* them (in order, as the frameworks run them),
  under ``path`` when one is given;
- ``X.use([path,] mw..., router)`` / ``X.use(router.routes())`` /
  ``X.route(path, sub)`` mount a router, Fastify ``X.register(plugin,
  { prefix })`` a plugin (``fastify-plugin`` wrapped plugins ignore
  ``prefix``), Elysia ``X.group(path, (g) => ...)`` a callback, and
  ``plugin(X)`` / ``require('./routes')(X)`` an exported route function: the
  mount's prefix and middleware, and ``X``'s earlier middleware, apply to
  every route below it;
- calls chain: ``new Hono().use(mw).get('/x', h).route('/y', sub)`` is the
  same as one statement per call;
- a router, plugin or route function imported from another file is followed
  to that file's export (see ``modules``);
- route-local middleware: ``router.post('/x', requireAuth, h)`` (arrays
  flattened), ``router.route('/x').post(mw, h)``, and route options
  ``{ preHandler | onRequest | preValidation | beforeHandle: [...] }``.

A middleware is a guard when its name says it authenticates (``requireAuth``,
``isAuthenticated``, ``ensureLoggedIn``, ``passport.authenticate('jwt')``,
``expressjwt(...)``, ``jwt(...)``, ``verifyToken``, ``bearerAuth(...)``) or
checks a role (``requireRole('admin')``, ``isAdmin``, ``authorize('admin')``,
``guard.check([...])``), or when an inline hook calls ``jwtVerify()``.
``optionalAuth``-style middleware, ``passport.authenticate('anonymous')``,
rate limiters, body parsers, CORS / CSRF / helmet and trackers such as
``updateAuthenticatedUsers`` are not guards.

``guard.unless({ path: ['/login', ...] })`` (express-unless) is an explicit
opt-out: a route whose full path is listed is ``anonymous`` when no other
guard applies. A list with regexes or other keys makes the guard uncertain.

**NestJS** — ``@UseGuards(...)`` on the method or controller, and a global
guard (``app.useGlobalGuards(...)`` / ``{ provide: APP_GUARD, useClass }``)
make a route ``required``; ``Optional...`` guards don't. A metadata-driven
role guard (``RolesGuard``, ``PermissionsGuard``) counts only next to its
``@Roles(...)`` / ``@Permissions(...)`` metadata. ``@Public()`` /
``@SkipAuth()`` / ``@AllowAnonymous()`` / ``@SetMetadata('isPublic', true)``
make a route ``anonymous``, unless a guard is Passport's own
``AuthGuard('...')``, which ignores that metadata.

Anything else stays ``unknown``. Brackets are matched in one cached pass per
file, argument lists are split by jumping over nested functions, and chains,
lookups, mounts and paths are bounded, so every scan is linear.
"""

from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass, field

from .modules import ImportRef, ModuleResolver, Reexports, file_candidates, parse_imports, parse_reexports

REQUIRED = "required"
ANONYMOUS = "anonymous"
UNKNOWN = "unknown"

AUTHN = "authn"
ROLE = "role"

_EVIDENCE_MAX = 200
_ARG_SCAN = 4000
_LOOKUP_LIMIT = 64  # bindings of one name searched
_MAX_DEPTH = 16  # mount levels followed
_MAX_PATHS = 64  # mount paths explored per route
_MAX_VARIANTS = 8  # distinct mounted paths emitted per route
_MAX_USES = 32  # guarding use() calls kept per router
_MAX_GUARDS = 8  # guards kept per use() / mount / route registration
_MAX_MIDDLEWARE_ARGS = 64  # middleware arguments inspected per call
_MAX_CHAIN = 256  # calls followed in one chain
_MAX_REEXPORT_DEPTH = 6
_MAX_STAR_EXPORTS = 16


def clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _EVIDENCE_MAX else text[: _EVIDENCE_MAX - 1] + "…"


# ---------- Brackets ----------

_SCAN_TOKEN = re.compile(r"[\"'`]|//|/\*|[()\[\]{}]")
_ARG_TOKEN = re.compile(r"[\"'`,]|//|/\*|[(\[{]")
_STRING_BODY = {
    '"': re.compile(r'[^"\\\n]*(?:\\.[^"\\\n]*)*"'),
    "'": re.compile(r"[^'\\\n]*(?:\\.[^'\\\n]*)*'"),
    "`": re.compile(r"[^`\\]*(?:\\.[^`\\]*)*`", re.DOTALL),
}
_OPEN = "([{"


def _skip(content: str, token: str, pos: int, limit: int) -> int:
    if token in _STRING_BODY:
        body = _STRING_BODY[token].match(content, pos, limit)
        return body.end() if body else pos
    if token == "//":
        nl = content.find("\n", pos, limit)
        return limit if nl < 0 else nl
    if token == "/*":
        end = content.find("*/", pos, limit)
        return limit if end < 0 else end + 2
    return pos


@functools.lru_cache(maxsize=4)
def bracket_pairs(content: str) -> dict[int, int]:
    """Opening-bracket offset -> closing-bracket offset, in one forward pass
    (strings, template literals and comments skipped)."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    pos = 0
    n = len(content)
    while pos < n:
        match = _SCAN_TOKEN.search(content, pos)
        if not match:
            break
        token = match.group()
        pos = match.end()
        if token in _OPEN:
            stack.append(match.start())
        elif token in ")]}":
            if stack:
                pairs[stack.pop()] = match.start()
        else:
            pos = _skip(content, token, pos, n)
    return pairs


def matching_close(content: str, open_idx: int) -> int:
    if open_idx < 0:
        return -1
    return bracket_pairs(content).get(open_idx, -1)


def split_args(content: str, open_idx: int, close: int) -> list[tuple[int, int]]:
    """``(start, end)`` of each top-level element inside the bracket at
    ``open_idx``; nested brackets and strings are jumped over."""
    pairs = bracket_pairs(content)
    args: list[tuple[int, int]] = []
    start = pos = open_idx + 1
    while pos < close:
        match = _ARG_TOKEN.search(content, pos, close)
        if not match:
            break
        token = match.group()
        pos = match.end()
        if token == ",":
            args.append((start, match.start()))
            start = pos
        elif token in _OPEN:
            pos = max(pos, pairs.get(match.start(), close - 1) + 1)
        else:
            pos = _skip(content, token, pos, close)
    if content[start:close].strip():
        args.append((start, close))
    return args


def _strip_span(content: str, start: int, end: int) -> tuple[int, int]:
    while start < end and content[start].isspace():
        start += 1
    while end > start and content[end - 1].isspace():
        end -= 1
    return start, end


_STRING_LITERAL = re.compile(r"""\s*(['"`])([^'"`\\$]*)\1\s*$""")


def string_literal(text: str) -> str | None:
    match = _STRING_LITERAL.match(text)
    return match.group(2) if match else None


# ---------- Guards ----------

_ARG_NAME = re.compile(r"\s*(?:await\s+)?(?:new\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)")
# Names are compared lower-cased with `_` removed, one dotted segment at a time.
_AUTHN_NAME = re.compile(
    # requireAuth, isAuthenticated, authenticate, authenticateJWT, authMiddleware,
    # withAuth, isAuthorized, checkAuth
    r"(?:require|requires|ensure|check|verify|is|has|must|assert|enforce|with|need|needs)?"
    r"(?:auth|authn|authed|authenticate|authenticated|authentication|authorized|authorised)"
    r"(?:user|token|jwt|request|req|session|middleware|mw|guard|handler|check|required|only)?"
    # isLoggedIn, ensureLoggedIn, requireLogin, verifyToken, checkJwt, requireSession
    r"|(?:require|requires|ensure|check|verify|is|has|must|assert|enforce|need|needs)"
    r"(?:loggedin|login|signedin|signin|session|token|jwt|accesstoken|idtoken|bearer|bearertoken|apikey|apitoken"
    r"|authtoken|jwttoken|validtoken|validjwt|validsession|firebasetoken)"
    r"(?:middleware|mw|guard|handler|check|required)?"
    r"|validate(?:session|token|jwt|accesstoken|bearertoken|apikey|apitoken)"
    r"|(?:require|ensure)(?:user|currentuser|signedinuser)"
    r"|jwt|expressjwt|ejwt|jwt(?:middleware|guard|check|verify|required|authentication)|passportjwt"
    r"|loginrequired|requiresauth|protect|protected|protectroute|protectedroute|clerkexpressrequireauth"
    r"|isloggedin|loggedin"
)
# Ends in an auth word: webhookAuth, basicAuth, bearerAuth, apiKeyAuth, jwtAuthGuard.
_AUTHN_SUFFIX = ("auth", "authguard", "authmiddleware", "authrequired", "authcheck", "authhandler")
_ROLE_NAME = re.compile(
    # isAdmin, requireRole, hasAnyRole, checkPermissions, requireScopes, adminOnly
    r"(?:require|requires|ensure|check|verify|is|has|must|assert|only|restrict|allow|need|needs)(?:any)?"
    r"(?:role|roles|admin|admins|administrator|superuser|superadmin|staff|permission|permissions|perm|perms"
    r"|scope|scopes|privilege|privileges)"
    r"(?:middleware|mw|guard|check|required|only|access|user)?"
    r"|(?:admin|administrator|superuser|superadmin|staff|role|roles|permission|permissions|scope|scopes)"
    r"(?:only|required|guard|middleware|mw|check|access)"
    r"|authori[sz]e\w*|permit|restrictto|requiredscopes|rbac|acl|onlyadmins?"
)
# Objects whose generic method is an auth check: `auth.required`, `keycloak.protect()`.
_AUTH_OBJECTS = frozenset({"auth", "authn", "authentication", "authmiddleware", "authmw", "jwt", "passport", "keycloak"})
_AUTH_OBJECT_METHODS = frozenset(
    {"required", "require", "verify", "check", "protect", "ensure", "authenticate", "authenticated", "jwt", "user",
     "isauthenticated", "loggedin", "isloggedin", "token", "guard"}
)
_NOT_GUARD_NAME = re.compile(
    r"optional|maybe|soft|tryauth|noauth|skipauth|withoutauth|bypass|public|anonymous|guest|unauth|notauth"
    r"|ratelimit|throttl|cors|csrf|xsrf|helmet|logout|signout|callback|clerkexpresswithauth"
)
_INLINE_VERIFY = re.compile(r"\.\s*jwtVerify\s*\(")
_FUNCTION_START = re.compile(r"\s*(?:async\s+)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)")
_UNLESS = re.compile(r"\.\s*unless\s*\(")
_ANONYMOUS_STRATEGY = re.compile(r"""['"]anonymous['"]""")
_SPACES = re.compile(r"\s+")
_NEW = re.compile(r"^new\s+")


def guard_kind(name: str) -> str | None:
    """``authn`` / ``role`` when a middleware's (dotted) name says it
    authenticates or checks a role; None otherwise."""
    norm = name.lower().replace("_", "").replace(" ", "")
    if not norm or _NOT_GUARD_NAME.search(norm):
        return None
    segments = norm.split(".")
    final = segments[-1]
    if _ROLE_NAME.fullmatch(final) or (len(segments) > 1 and segments[-2] == "guard" and final == "check"):
        return ROLE
    if _AUTHN_NAME.fullmatch(final):
        return AUTHN
    if final.endswith(_AUTHN_SUFFIX) and not final.endswith("oauth") and final != "oauth":
        return AUTHN
    if len(segments) > 1 and segments[-2] in _AUTH_OBJECTS and final in _AUTH_OBJECT_METHODS:
        return AUTHN
    return None


@dataclass
class Skip:
    """An ``.unless({ path: [...] })`` opt-out list."""

    exact: set[str]
    characterized: bool
    evidence: str


@dataclass
class Guard:
    name: str
    evidence: str
    skip: Skip | None = None
    uncertain: bool = False
    prefix: str | None = None  # `use('/api', mw)`: only under this path


def _unless(content: str, start: int, end: int) -> Skip | None:
    match = _UNLESS.search(content, start, end)
    if not match:
        return None
    close = matching_close(content, match.end() - 1)
    if close < 0:
        return Skip(set(), False, "")
    evidence = clip(content[match.start() + 1 : min(close + 1, match.start() + _EVIDENCE_MAX)])
    args = split_args(content, match.end() - 1, close)
    if len(args) != 1 or content[_strip_span(content, *args[0])[0]] != "{":
        return Skip(set(), False, evidence)
    obj_open = _strip_span(content, *args[0])[0]
    obj_close = matching_close(content, obj_open)
    exact: set[str] = set()
    characterized = obj_close > 0
    for s, e in split_args(content, obj_open, obj_close) if obj_close > 0 else []:
        key, _, value = content[s:e].partition(":")
        if key.strip().strip("'\"") != "path":
            characterized = False
            continue
        value_start = s + len(key) + 1
        vs, ve = _strip_span(content, value_start, e)
        items = [(vs, ve)]
        if content[vs:vs + 1] == "[":
            vclose = matching_close(content, vs)
            items = split_args(content, vs, vclose) if vclose > 0 else []
            characterized = characterized and vclose > 0
        for item_s, item_e in items:
            literal = string_literal(content[item_s:item_e])
            if literal is None:
                characterized = False  # a regex, an object, a variable
            else:
                exact.add(literal)
    return Skip(exact, characterized and bool(exact), evidence)


def guard_from_arg(content: str, start: int, end: int, context: str | None = None) -> Guard | None:
    """A Guard when the middleware argument ``content[start:end]`` authenticates
    or checks a role."""
    end = min(end, start + _ARG_SCAN)
    text = content[start:end]
    evidence = clip(context if context is not None else text)
    if _FUNCTION_START.match(text):
        # An inline hook / middleware: a guard when it verifies a JWT.
        return Guard("jwtVerify", evidence) if _INLINE_VERIFY.search(text) else None
    match = _ARG_NAME.match(content, start, end)
    if not match:
        return None
    name = _SPACES.sub("", match.group(1))
    if guard_kind(name) is None:
        return None
    if name.endswith("passport.authenticate"):
        # `passport.authenticate('anonymous')` / `(['jwt', 'anonymous'])` admit
        # callers without credentials.
        paren = content.find("(", match.end(), end)
        close = matching_close(content, paren) if paren >= 0 else -1
        args = split_args(content, paren, close) if 0 < close <= end else []
        if args and _ANONYMOUS_STRATEGY.search(content, args[0][0], args[0][1]):
            return None
    return Guard(name, evidence, _unless(content, start, end))


_LOGIN_STRATEGY = re.compile(r"""\s*['"]local['"]""")


def guard_only_registration(content: str, spans: list[tuple[int, int]], context: str) -> list[Guard]:
    """The guards of a route registration whose every argument is a guard,
    else []. Passport's ``local`` strategy there is the login handler itself."""
    guards: list[Guard] = []
    for start, end in flatten(content, spans)[:_MAX_MIDDLEWARE_ARGS]:
        guard = guard_from_arg(content, start, end, context)
        if guard is None:
            return []
        if guard.name.endswith("passport.authenticate"):
            paren = content.find("(", start, end)
            if paren >= 0 and _LOGIN_STRATEGY.match(content, paren + 1, end):
                return []
        guards.append(guard)
    return guards[:_MAX_GUARDS]


def flatten(content: str, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Expand array arguments (``[requireAuth, validate]``) into their elements."""
    out: list[tuple[int, int]] = []
    for start, end in spans:
        s, e = _strip_span(content, start, end)
        if content[s:s + 1] == "[":
            close = matching_close(content, s)
            if close > 0:
                out += split_args(content, s, close)
                continue
        out.append((start, end))
    return out


# Used with .match(content, pos): `^` would only match at the string start.
_HOOK_KEYS = re.compile(r"""\s*['"]?(preHandler|onRequest|preValidation|preParsing|beforeHandle)['"]?\s*:""")


def route_option_guards(content: str, start: int, end: int, context: str) -> list[Guard]:
    """Route options ``{ preHandler: [...], onRequest: fn, beforeHandle: mw }``."""
    s, e = _strip_span(content, start, end)
    if content[s:s + 1] != "{":
        return []
    close = matching_close(content, s)
    if close < 0:
        return []
    guards: list[Guard] = []
    for ps, pe in split_args(content, s, close):
        key = _HOOK_KEYS.match(content, ps, pe)
        if not key:
            continue
        for vs, ve in flatten(content, [(key.end(), pe)])[:_MAX_MIDDLEWARE_ARGS]:
            guard = guard_from_arg(content, vs, ve, context)
            if guard:
                guards.append(guard)
    return guards[:_MAX_GUARDS]


# ---------- Functions ----------

_FN_KEYWORD = re.compile(r"\s*(?:async\s+)?function\b\s*\*?\s*(?:[A-Za-z_$][\w$]*)?\s*(?:<[^()]{0,200}>)?\s*\(")
_FN_ARROW_PARAMS = re.compile(r"\s*(?:async\s*)?(?:<[^()]{0,200}>\s*)?\(")
_FN_SINGLE = re.compile(r"\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>")
_FIRST_PARAM = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*[?]?\s*[:,)=]")
_ARROW = re.compile(r"\s*(?::\s*[^=;{}()]{1,200})?=>")
_BLOCK_OPEN = re.compile(r"\s*(?::\s*[^{};=]{1,200})?\{")
_EXPR_BODY_OPEN = re.compile(r"\s*\{")
# A request handler / middleware, not a route function taking the app.
_NOT_ROUTER_PARAMS = frozenset(
    {"req", "request", "res", "response", "reply", "ctx", "c", "context", "next", "err", "error", "e", "event",
     "_", "args", "options", "opts", "props", "config", "env"}
)


def function_at(content: str, start: int, end: int, *, block_only: bool = False) -> tuple[str, int, int] | None:
    """``(first parameter, body start, body end)`` of the function expression
    at ``content[start:end]``; an arrow with an expression body ends at
    ``end`` (not with ``block_only``)."""
    keyword = _FN_KEYWORD.match(content, start, end)
    head = keyword or _FN_ARROW_PARAMS.match(content, start, end)
    if head:
        paren = head.end() - 1
        close = matching_close(content, paren)
        if close < 0 or close >= end:
            return None
        param = _FIRST_PARAM.match(content, paren + 1, close + 1)
        if not param:
            return None
        after = close + 1
        if keyword is None:
            arrow = _ARROW.match(content, after, end)
            if not arrow:
                return None
            after = arrow.end()
        name = param.group(1)
    else:
        single = _FN_SINGLE.match(content, start, end)
        if not single:
            return None
        name, after = single.group(1), single.end()
        keyword = None
    if name in _NOT_ROUTER_PARAMS:
        return None
    body = (_BLOCK_OPEN if keyword else _EXPR_BODY_OPEN).match(content, after, end)
    if body:
        open_idx = body.end() - 1
        close = matching_close(content, open_idx)
        return (name, open_idx, close) if 0 < close <= end else None
    if keyword or block_only:
        return None
    return name, after, end


# ---------- Router bindings ----------


@dataclass
class Mount:
    owner: "Binding"
    offset: int
    prefix: str
    guards: list[Guard]
    routers: "FileRouters"


@dataclass
class Binding:
    name: str
    offset: int
    scope: tuple[int, int]
    root: bool = False  # express() / new Koa() / new Hono() / fastify()
    prefix: str = ""  # koa `new Router({ prefix })`, elysia `{ prefix }`, hono basePath, register `{ prefix }`
    uses: list[tuple[int, list[Guard]]] = field(default_factory=list)
    mounts: list[Mount] = field(default_factory=list)
    overflow: bool = False
    skip_prefix: bool = False  # a fastify-plugin wrapped plugin ignores `register(..., { prefix })`


@dataclass
class ChainRoute:
    """``.get('/x', ...)`` called on the result of another router call."""

    binding: Binding
    method: str
    path: str
    offset: int
    paren: int
    close: int
    head: str | None  # receiver name of the chain's first call; None after a constructor


_IDENT = r"[A-Za-z_$][\w$]*"
_SPEC = r"""['"]([^'"\n]{1,300})['"]"""
_CTOR_NAMES = (
    r"express\s*\.\s*Router|require\s*\(\s*['\"]express['\"]\s*\)\s*\.\s*Router|express|Router|fastify|Fastify|polka"
    r"|new\s+(?:Koa|Hono|OpenAPIHono|Elysia|Router|KoaRouter)\b"
)
_PREFIXED_CTORS = re.compile(r"Router|Elysia")  # `new Router({ prefix })`, `new Elysia({ prefix })`
_IDENT_RE = re.compile(_IDENT)
_VALUE_IDENT = re.compile(rf"\s*({_IDENT})\s*(?:[;,)\n]|$)")
_ROOT_CTORS = re.compile(r"express|fastify|Fastify|polka|new\s+(?:Koa|Hono|OpenAPIHono|Elysia)")
_ASSIGN_CTOR = re.compile(
    rf"\b({_IDENT})\s*(?::\s*[^=;\n]{{1,200}})?=\s*(?:await\s+)?(?P<ctor>{_CTOR_NAMES})"
)
_EXPORT_CTOR = re.compile(rf"(?:\bmodule\s*\.\s*exports\s*=(?!=)|\bexport\s+default\b)\s*(?P<ctor>{_CTOR_NAMES})")
# `(` after a constructor name, past TypeScript generics: `new Hono<{ Bindings: Env }>()`.
_CTOR_PAREN = re.compile(r"\s*(?:<[^()<>;]{0,300}(?:<[^()<>;]{0,300}>[^()<>;]{0,300})*>)?\s*\(")
_BASEPATH_ASSIGN = re.compile(
    rf"\b(?:const|let|var)\s+({_IDENT})\s*=\s*({_IDENT})\s*\.\s*basePath\s*\(\s*['\"]([^'\"\n]*)['\"]\s*\)"
)
_VERBS = frozenset({"get", "post", "put", "patch", "delete", "options", "head", "all"})
_CALL_HEAD = re.compile(
    rf"\b({_IDENT})\s*\.\s*(get|post|put|patch|delete|options|head|all|use|route|group|guard|basePath|addHook"
    rf"|register|onBeforeHandle)\s*\("
)
_WS = re.compile(r"(?:\s|//[^\n]{0,500}\n|/\*(?:[^*]|\*(?!/)){0,500}\*/)*")
def skip_space(content: str, pos: int) -> int:
    """The offset after whitespace and comments at ``pos`` (bounded)."""
    return _WS.match(content, pos).end()


_LINK = re.compile(rf"\.\s*({_IDENT})\s*(?:<[^()<>;]{{0,200}}>\s*)?\(")
# Chainable calls that return the same app (Hono / Elysia / Express / Fastify).
_PASSTHROUGH = frozenset(
    {"onError", "notFound", "decorate", "state", "derive", "resolve", "model", "onRequest", "onAfterHandle",
     "onParse", "onTransform", "onResponse", "onAfterResponse", "mapResponse", "error", "setErrorHandler",
     "setNotFoundHandler", "decorateRequest", "decorateReply", "mount", "doc", "openapi", "param", "set",
     "engine", "disable", "enable", "macro", "headers", "onStart", "onStop", "onError"}
)
_HOOK_NAME = re.compile(r"""\s*['"](?:onRequest|preHandler|preValidation|preParsing)['"]\s*,""")
_PREFIX_OPTION = re.compile(r"""\bprefix\s*:\s*['"]([^'"]*)['"]""")
_ROUTES_CALL = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:routes|middleware)\s*\(\s*\)\s*$")
_IDENT_ONLY = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*$")
_MEMBER = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*$")
_INLINE_IMPORT = re.compile(
    rf"\s*(?:\(\s*)?(?:await\s+)?(?:require|import)\s*\(\s*{_SPEC}\s*\)\s*\)?(?:\s*\.\s*({_IDENT}))?\s*$"
)
_PLUGIN_WRAP = re.compile(r"\s*(?:fp|fastifyPlugin)\s*\(")
_CALL_MOUNT = re.compile(rf"(?<![.\w$])({_IDENT})\s*\(\s*({_IDENT})\s*[,)]")
# `function name(app) {`, `name(app) {` (a method): definitions, not calls.
_DEFINITION_AFTER = re.compile(r"\s*(?::[^{};=]{1,200})?(?:\{|=>)")
_REQUIRE_CALL_MOUNT = re.compile(rf"\brequire\s*\(\s*{_SPEC}\s*\)(?:\s*\.\s*({_IDENT}))?\s*\(\s*({_IDENT})\s*[,)]")
_FN_DECL = re.compile(rf"\b(?:async\s+)?function\s*\*?\s*({_IDENT})\s*(?:<[^()]{{0,200}}>)?\s*\(")
_FN_ASSIGN = re.compile(rf"\b(?:const|let|var)\s+({_IDENT})\s*(?::\s*[^=;\n]{{1,200}})?=(?!=)")
_EXPORT_DEFAULT = re.compile(r"(?:\bmodule\s*\.\s*exports\s*=(?!=)|\bexport\s+default\b)")
_EXPORT_DECL = re.compile(rf"\bexport\s+(?:(?:const|let|var)\s+({_IDENT})|(?:async\s+)?function\s*\*?\s*({_IDENT}))")
_EXPORT_LIST = re.compile(r"\bexport\s*\{([^{}]{0,1000})\}(?!\s*from)")
_CJS_EXPORT = re.compile(rf"\b(?:module\s*\.\s*)?exports\s*\.\s*({_IDENT})\s*=(?!=)")
_EXPORT_AS = re.compile(rf"^\s*({_IDENT})(?:\s+as\s+({_IDENT}))?\s*$")
_CONVENTIONAL = frozenset({"app", "router", "server", "fastify"})
_PATH_VARIABLE = re.compile(rf"{_IDENT}(?:\s*\.\s*{_IDENT})*")
_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "function", "return", "typeof", "await", "new", "require", "import",
     "super", "with", "void", "delete", "in", "of", "do", "else", "case", "throw", "yield"}
)


def join_path(prefix: str, path: str) -> str:
    if not prefix:
        return path
    if not path or path == "/":
        return "/" + prefix.strip("/") if prefix.strip("/") else "/"
    return "/" + "/".join(p for p in (prefix.strip("/"), path.strip("/")) if p)


def _under(path: str, prefix: str) -> bool:
    """Express/Hono path-prefix match (`/api` covers `/api` and `/api/x`;
    `/api/*` covers `/api/x` but not `/api`, as in Express 4)."""
    if prefix.endswith("/*"):
        return path.startswith(prefix[:-1])
    prefix = prefix.rstrip("*")
    if prefix in ("", "/"):
        return True
    if prefix.endswith("/"):
        return path.startswith(prefix) or path == prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


_FN_BODY_ARROW = re.compile(r"=>\s*$")
_FN_BODY_AFTER_PARAMS = re.compile(r"\)\s*(?::[^{};()=]{1,150})?\s*$")
_CONTROL_KEYWORD = re.compile(r"(?:\b(?:if|for|while|switch|catch|with)|\bfor\s+await)\s*$")


def _is_function_body(content: str, open_idx: int, opens: dict[int, int]) -> bool:
    """True when the ``{`` at ``open_idx`` opens a function / method / arrow
    body (not a class, object literal or ``if`` / ``for`` block)."""
    head = content[max(0, open_idx - 200) : open_idx]
    if _FN_BODY_ARROW.search(head):
        return True
    params = _FN_BODY_AFTER_PARAMS.search(head)
    if not params:
        return False
    close = open_idx - len(head) + params.start()
    paren = opens.get(close)
    if paren is None:
        return False
    return not _CONTROL_KEYWORD.search(content, max(0, paren - 20), paren)


class FileRouters:
    """Router variables, their middleware, mounts, imports and exports in one file."""

    def __init__(self, content: str, file: str) -> None:
        self.content = content
        self.file = file
        self._length = len(content)
        pairs = bracket_pairs(content)
        blocks = sorted((o, c) for o, c in pairs.items() if content[o] == "{")
        # A router passed in as a parameter is bound per function: the
        # outermost function body around a call (a class or object literal
        # isn't one, so each method gets its own).
        opens = {c: o for o, c in pairs.items() if content[o] == "("}
        self._top: list[tuple[int, int]] = []
        for block in blocks:
            if (not self._top or block[0] > self._top[-1][1]) and _is_function_body(content, block[0], opens):
                self._top.append(block)
        self._top_starts = [s for s, _ in self._top]
        self._blocks = blocks
        self._stack: list[tuple[int, int]] = []
        self._next_block = 0
        self._by_name: dict[str, list[Binding]] = {}
        self._offsets: dict[str, list[int]] = {}
        self._free: dict[tuple[str, int], Binding] = {}
        self._anonymous: dict[int, Binding] = {}  # export-default constructor offset -> binding
        self._fn_defs: dict[str, int] | None = None
        self.imports: dict[str, ImportRef] = parse_imports(content)
        self.reexports: Reexports = parse_reexports(content)
        self.import_mounts: list[tuple[ImportRef, Mount]] = []
        self.exports: dict[str, Binding] = {}
        self.chain_routes: list[ChainRoute] = []

        self._fn_params: dict[str, Binding] = {}
        # Router variables first, then the functions whose parameter shadows
        # one (`async function routes(fastify) {...}` next to `const fastify =
        # Fastify()`), then the calls, so each call sees the right binding.
        declarations: list[tuple[int, int, re.Match]] = []
        for kind, pattern in enumerate((_ASSIGN_CTOR, _EXPORT_CTOR, _BASEPATH_ASSIGN)):
            declarations += [(m.start(), kind, m) for m in pattern.finditer(content)]
        declarations.sort(key=lambda e: (e[0], e[1]))
        calls: list[tuple[int, int, re.Match]] = []
        for kind, pattern in enumerate((_CALL_HEAD, _CALL_MOUNT, _REQUIRE_CALL_MOUNT), start=3):
            calls += [(m.start(), kind, m) for m in pattern.finditer(content)]
        calls.sort(key=lambda e: (e[0], e[1]))
        for _, kind, match in declarations:
            if kind <= 1:
                self._constructor(match, kind == 1)
            else:
                self._base_path(match)
        self._shadowing_parameters()
        for _, kind, match in calls:
            if kind == 3:
                self._call_head(match)
            elif kind == 4:
                self._call_mount(match)
            else:
                self._require_call_mount(match)
        self._parse_exports()
        # Only bindings are needed from here on; don't keep every file's source.
        self.content = ""
        self._fn_defs = None

    # -- scopes / bindings --

    def _advance(self, offset: int) -> tuple[int, int]:
        while self._next_block < len(self._blocks) and self._blocks[self._next_block][0] < offset:
            block = self._blocks[self._next_block]
            self._next_block += 1
            while self._stack and self._stack[-1][1] < block[0]:
                self._stack.pop()
            self._stack.append(block)
        while self._stack and self._stack[-1][1] < offset:
            self._stack.pop()
        # Module scope for top-level `const app = express()`.
        return self._stack[-1] if self._stack else (0, self._length)

    def _top_level(self, offset: int) -> tuple[int, int]:
        index = bisect.bisect_right(self._top_starts, offset) - 1
        if index >= 0 and self._top[index][1] >= offset:
            return self._top[index]
        return (0, self._length)

    def _bind(self, binding: Binding) -> None:
        offsets = self._offsets.setdefault(binding.name, [])
        index = bisect.bisect_right(offsets, binding.offset)
        offsets.insert(index, binding.offset)
        self._by_name.setdefault(binding.name, []).insert(index, binding)

    def names(self) -> set[str]:
        """Names bound to a router somewhere in the file."""
        return {name for name in self._by_name if name}

    def resolve(self, name: str, offset: int, *, create: bool = True) -> Binding | None:
        """The binding of ``name`` visible at ``offset``; else a free binding
        for the enclosing top-level function (a router passed in)."""
        bindings = self._by_name.get(name, [])
        index = bisect.bisect_left(self._offsets.get(name, []), offset) - 1
        for _ in range(_LOOKUP_LIMIT):
            if index < 0:
                break
            binding = bindings[index]
            if binding.scope[0] <= offset <= binding.scope[1]:
                return binding
            index -= 1
        else:
            if index >= 0:
                return None
        if not create:
            return None
        scope = self._top_level(offset)
        free = self._free.get((name, scope[0]))
        if free is None:
            free = self._free[(name, scope[0])] = Binding(name, scope[0], scope)
        return free

    def _context(self, start: int, close: int) -> str:
        return self.content[start : min(close + 1, start + 2 * _EVIDENCE_MAX)]

    def _param_binding(self, fn: tuple[str, int, int]) -> Binding:
        """The router a route function receives as its first parameter (the
        same free binding its body's routes resolve to)."""
        name, body_start, _ = fn
        return self.resolve(name, body_start + 1)  # type: ignore[return-value]

    def _definitions(self) -> dict[str, int]:
        """Same-file ``function name(...)`` / ``const name = (...) =>`` offsets."""
        if self._fn_defs is None:
            self._fn_defs = {}
            for match in _FN_DECL.finditer(self.content):
                self._fn_defs.setdefault(match.group(1), match.start())
            for match in _FN_ASSIGN.finditer(self.content):
                self._fn_defs.setdefault(match.group(1), match.end())
        return self._fn_defs

    def _function_at(self, start: int) -> tuple[str, int, int] | None:
        return function_at(self.content, start, min(len(self.content), start + _ARG_SCAN * 50), block_only=True)

    def _shadowing_parameters(self) -> None:
        """A named function whose first parameter has the name of a router
        variable gets its own binding for its body."""
        if not self._by_name:
            return
        for name, start in self._definitions().items():
            fn = self._function_at(start)
            if fn is not None and fn[0] in self._by_name:
                binding = Binding(fn[0], fn[1], (fn[1], fn[2]))
                self._bind(binding)
                self._fn_params[name] = binding

    def _function_binding(self, name: str) -> Binding | None:
        """The parameter binding of a same-file ``function name(app)`` /
        ``const name = (app) => {...}``."""
        if name in self._fn_params:
            return self._fn_params[name]
        start = self._definitions().get(name)
        fn = self._function_at(start) if start is not None else None
        return self._param_binding(fn) if fn else None

    def _import_ref(self, start: int, end: int) -> ImportRef | None:
        """An imported module named by an argument: ``require('./x')``,
        ``import('./x')``, ``imported``, ``ns.member``."""
        end = min(end, start + 400)
        inline = _INLINE_IMPORT.match(self.content, start, end)
        if inline:
            member = inline.group(2)
            return ImportRef(inline.group(1), member if member and member != "default" else "default")
        member = _MEMBER.match(self.content, start, end)
        if member and member.group(1) in self.imports:
            ref = self.imports[member.group(1)]
            if ref.name in ("*", "default"):
                return ImportRef(ref.spec, member.group(2))
            return None
        ident = _IDENT_ONLY.match(self.content, start, end)
        if ident and ident.group(1) in self.imports:
            ref = self.imports[ident.group(1)]
            return ImportRef(ref.spec, "default") if ref.name == "*" else ref
        return None

    # -- events --

    def _constructor(self, match: re.Match, exported: bool) -> None:
        ctor = match.group("ctor")
        paren_match = _CTOR_PAREN.match(self.content, match.end("ctor"))
        if paren_match is None and not ctor.startswith("new"):
            return  # `express.static(...)`, a property named `Router`, ...
        name = "" if exported else match.group(1)
        if name == "exports":
            return
        scope = self._advance(match.start())
        binding = Binding(name, match.start(), scope, root=bool(_ROOT_CTORS.fullmatch(ctor)))
        close = -1
        if paren_match is not None:
            paren = paren_match.end() - 1
            close = matching_close(self.content, paren)
            if close > 0 and _PREFIXED_CTORS.search(ctor):
                option = _PREFIX_OPTION.search(self.content, paren, min(close, paren + 400))
                binding.prefix = option.group(1) if option else ""
        if exported:
            self._anonymous[match.start()] = binding
        else:
            self._bind(binding)
        if close > 0:
            self._walk_chain(binding, close, None, binding)

    def _base_path(self, match: re.Match) -> None:
        """``const api = app.basePath('/api')`` (Hono)."""
        parent = self.resolve(match.group(2), match.start())
        if parent is None:
            return
        child = Binding(match.group(1), match.start(), self._advance(match.start()), prefix=match.group(3))
        child.mounts.append(Mount(parent, match.start(), "", [], self))
        self._bind(child)

    def _call_head(self, match: re.Match) -> None:
        name, method = match.group(1), match.group(2)
        paren = match.end() - 1
        close = matching_close(self.content, paren)
        owner = self.resolve(name, match.start())
        if owner is None or close < 0:
            return
        # `app\n  .get('/x', h)`: the analyzer's route pattern wants `app.get(`.
        spaced = self.content[match.end(1)] != "."
        following = self._call(owner, method, match.start(), paren, close, head=name, link=spaced, ctor=None)
        if following is not None:
            self._walk_chain(following, close, name, None)

    def _walk_chain(self, owner: Binding, close: int, head: str | None, ctor: Binding | None) -> None:
        pos = close + 1
        for _ in range(_MAX_CHAIN):
            link = _LINK.match(self.content, _WS.match(self.content, pos).end())
            if not link:
                return
            paren = link.end() - 1
            link_close = matching_close(self.content, paren)
            if link_close < 0:
                return
            following = self._call(owner, link.group(1), link.start(1), paren, link_close, head=head, link=True, ctor=ctor)
            if following is None:
                return
            owner, pos = following, link_close + 1

    def _call(
        self, owner: Binding, method: str, offset: int, paren: int, close: int,
        *, head: str | None, link: bool, ctor: Binding | None,
    ) -> Binding | None:
        """Apply one router call; return the binding a chained call continues
        on, or None when the result isn't the router any more. ``link``
        records a verb call as a route here (the analyzer finds the others)."""
        if method in _VERBS:
            if link:
                args = split_args(self.content, paren, close)
                path = string_literal(self.content[args[0][0] : args[0][1]]) if args else None
                if path is not None:
                    self.chain_routes.append(ChainRoute(owner, method.upper(), path, offset, paren, close, head))
            if method == "all":
                self._use(owner, offset, paren, close, "all")
            return owner
        if method in ("use", "route"):
            return owner if self._use(owner, offset, paren, close, method) else None
        if method == "addHook":
            if _HOOK_NAME.match(self.content, paren + 1, close):
                self._hooks(owner, offset, paren, close, 1)
            return owner
        if method == "onBeforeHandle":
            self._hooks(owner, offset, paren, close, 0)
            return owner
        if method == "register":
            self._register(owner, offset, paren, close)
            return owner
        if method in ("group", "guard"):
            self._group(owner, offset, paren, close, method == "group")
            return owner
        if method == "basePath":
            args = split_args(self.content, paren, close)
            literal = string_literal(self.content[args[0][0] : args[0][1]]) if len(args) == 1 else None
            if literal is None:
                return owner
            if ctor is owner:
                owner.prefix = join_path(owner.prefix, literal)
                return owner
            child = Binding("", offset, owner.scope, prefix=literal)
            child.mounts.append(Mount(owner, offset, "", [], self))
            return child
        return owner if method in _PASSTHROUGH else None

    def _mount_target(self, start: int, end: int, verb: str) -> Binding | ImportRef | None:
        """A router mounted by a use()/route() argument: a binding in this
        file, or an imported module's export. Hono's ``route(path, sub)``
        always takes a sub-app; a ``use()`` argument named like auth
        middleware is middleware."""
        text = self.content[start : min(end, start + 300)]
        routes_call = _ROUTES_CALL.match(text)
        ident = routes_call or _IDENT_ONLY.match(text)
        if ident:
            binding = self.resolve(ident.group(1), start, create=False)
            if binding is not None:
                return binding
            if verb == "use" and not routes_call and guard_kind(ident.group(1)) is not None:
                return None  # imported auth middleware
        if routes_call:
            return self._import_ref(start + routes_call.start(1), start + routes_call.end(1))
        return self._import_ref(start, end)

    def _use(self, owner: Binding, offset: int, paren: int, close: int, verb: str) -> bool:
        """``use()`` / ``all('*')`` / ``route()``; False for Express's
        one-argument ``router.route('/x')``, whose result is a route."""
        args = split_args(self.content, paren, close)
        if not args:
            return verb != "route"
        prefix: str | None = None
        prefixes: list[str] | None = None  # `use(['/a', '/b'], mw)`
        unknown_path = False  # `use(API_PREFIX, mw)`, `use(/^\/api/, mw)`
        first = string_literal(self.content[args[0][0] : args[0][1]])
        if first is not None:
            prefix, args = first, args[1:]
        elif verb in ("all", "route"):
            return True  # `.all(handler)`, Fastify `.route({ ... })`
        elif len(args) > 1:
            kind = self._path_argument(*args[0])
            if kind is not None:
                args = args[1:]
                if isinstance(kind, list):
                    prefixes = kind
                else:
                    unknown_path = True
        if verb == "route" and not args:
            return False
        if verb == "all" and not prefix.endswith("*"):
            return True  # a real `.all('/x', h)` route, not a catch-all guard
        context = self._context(offset, close)
        args = flatten(self.content, args)[:_MAX_MIDDLEWARE_ARGS]
        target = self._mount_target(*args[-1], verb) if args and verb in ("use", "route") else None
        middleware = args[:-1] if target is not None else args
        guards = [] if verb == "route" else [
            g for s, e in middleware if (g := guard_from_arg(self.content, s, e, context))
        ][:_MAX_GUARDS]
        if unknown_path:
            # A path this file can't read: the guard may not cover the route.
            guards = [Guard(g.name, g.evidence, uncertain=True) for g in guards]
        if target is not None:
            for mount_prefix in (prefixes or [prefix or ""])[:_MAX_GUARDS]:
                mount = Mount(owner, offset, mount_prefix, guards, self)
                if isinstance(target, Binding):
                    if target is not owner:
                        target.mounts.append(mount)
                else:
                    self.import_mounts.append((target, mount))
            return True
        if not guards:
            return True
        if prefixes is not None:
            # One copy per literal prefix of `use(['/a', '/b'], mw)`.
            guards = [
                Guard(g.name, g.evidence, g.skip, g.uncertain, p) for p in prefixes[:_MAX_GUARDS] for g in guards
            ][:_MAX_GUARDS * 2]
        else:
            for guard in guards:
                guard.prefix = prefix
        self._add_use(owner, offset, guards)
        return True

    def _path_argument(self, start: int, end: int) -> list[str] | bool | None:
        """What a non-string first ``use()`` argument is: a list of literal
        paths, True for a path this file can't read (a regex, a template, a
        variable such as ``API_PREFIX``), or None for middleware."""
        s, e = _strip_span(self.content, start, end)
        text = self.content[s:e]
        if text.startswith("["):
            close = matching_close(self.content, s)
            items = split_args(self.content, s, close) if close > 0 else []
            literals = [string_literal(self.content[a:b]) for a, b in items]
            if items and all(lit is not None for lit in literals):
                return literals  # type: ignore[return-value]
            return True
        if text.startswith(("/", "`")):
            return True  # a regex or template literal
        if _PATH_VARIABLE.fullmatch(text) and guard_kind(text) is None and self.resolve(text, s, create=False) is None:
            return True  # a bare identifier / member that isn't middleware we know
        return None

    def _add_use(self, owner: Binding, offset: int, guards: list[Guard]) -> None:
        if len(owner.uses) >= _MAX_USES:
            owner.overflow = True
        else:
            owner.uses.append((offset, guards))

    def _hooks(self, owner: Binding, offset: int, paren: int, close: int, first: int) -> None:
        args = split_args(self.content, paren, close)[first:]
        context = self._context(offset, close)
        guards = [
            g for s, e in flatten(self.content, args)[:_MAX_MIDDLEWARE_ARGS]
            if (g := guard_from_arg(self.content, s, e, context))
        ][:_MAX_GUARDS]
        if guards:
            self._add_use(owner, offset, guards)

    def _register(self, owner: Binding, offset: int, paren: int, close: int) -> None:
        """Fastify ``register(plugin, { prefix })``: an inline closure, a
        same-file function or an imported module."""
        args = split_args(self.content, paren, close)
        if not args:
            return
        prefix = ""
        if len(args) > 1:
            option = _PREFIX_OPTION.search(self.content, args[1][0], min(args[1][1], args[1][0] + 400))
            prefix = option.group(1) if option else ""
        start, end = _strip_span(self.content, *args[0])
        skip_prefix = False
        wrapped = _PLUGIN_WRAP.match(self.content, start, end)
        if wrapped:
            inner_close = matching_close(self.content, wrapped.end() - 1)
            inner = split_args(self.content, wrapped.end() - 1, inner_close) if 0 < inner_close <= end else []
            if not inner:
                return
            start, end = _strip_span(self.content, *inner[0])
            skip_prefix = True
        mount = Mount(owner, offset, "" if skip_prefix else prefix, [], self)
        fn = function_at(self.content, start, end, block_only=True)
        if fn is not None:
            child = Binding(fn[0], fn[1], (fn[1], fn[2]))
            child.mounts.append(mount)
            self._bind(child)
            return
        ref = self._import_ref(start, end)
        if ref is not None:
            self.import_mounts.append((ref, mount))
            return
        ident = _IDENT_ONLY.match(self.content, start, end)
        binding = self._function_binding(ident.group(1)) if ident else None
        if binding is not None and binding is not owner:
            binding.mounts.append(mount)

    def _group(self, owner: Binding, offset: int, paren: int, close: int, with_prefix: bool) -> None:
        """Elysia ``group('/x', [opts,] (g) => ...)`` / ``guard(opts, (g) => ...)``."""
        args = split_args(self.content, paren, close)
        prefix = ""
        if with_prefix:
            literal = string_literal(self.content[args[0][0] : args[0][1]]) if args else None
            if literal is None:
                return
            prefix, args = literal, args[1:]
        if not args:
            return
        context = self._context(offset, close)
        callback = function_at(self.content, args[-1][0], args[-1][1])
        options = args[:-1] if callback else args
        guards = [g for s, e in options for g in route_option_guards(self.content, s, e, context)][:_MAX_GUARDS]
        if callback is None:
            if guards and not with_prefix:
                self._add_use(owner, offset, guards)
            return
        child = Binding(callback[0], callback[1], (callback[1], callback[2]), prefix=prefix)
        child.mounts.append(Mount(owner, offset, "", guards, self))
        self._bind(child)

    def _call_mount(self, match: re.Match) -> None:
        """``usersRoutes(app)``: an imported / same-file route function
        registers its routes on ``app``."""
        function, argument = match.group(1), match.group(2)
        if function in _KEYWORDS or argument in _KEYWORDS:
            return
        paren = self.content.find("(", match.start() + len(function))
        close = matching_close(self.content, paren)
        if close < 0 or _DEFINITION_AFTER.match(self.content, close + 1):
            return
        if self.resolve(argument, match.start(), create=argument in _CONVENTIONAL) is None:
            return
        target: Binding | ImportRef | None = None
        if function in self.imports:
            ref = self.imports[function]
            target = ImportRef(ref.spec, "default") if ref.name == "*" else ref
        elif function not in self._by_name:
            target = self._function_binding(function)
        if target is None:
            return
        self._mount_call(target, argument, match.start())

    def _require_call_mount(self, match: re.Match) -> None:
        """``require('./routes/users')(app)``."""
        member = match.group(2)
        ref = ImportRef(match.group(1), member if member and member != "default" else "default")
        self._mount_call(ref, match.group(3), match.start())

    def _mount_call(self, target: Binding | ImportRef, argument: str, offset: int) -> None:
        owner = self.resolve(argument, offset, create=argument in _CONVENTIONAL)
        if owner is None or target is owner:
            return
        mount = Mount(owner, offset, "", [], self)
        if isinstance(target, Binding):
            target.mounts.append(mount)
        else:
            self.import_mounts.append((target, mount))

    # -- exports --

    def _value_binding(self, start: int) -> Binding | None:
        """The router / route function an export's value names."""
        end = min(len(self.content), start + _ARG_SCAN)
        skip_prefix = False
        wrapped = _PLUGIN_WRAP.match(self.content, start, end)
        if wrapped:
            inner_close = matching_close(self.content, wrapped.end() - 1)
            inner = split_args(self.content, wrapped.end() - 1, inner_close) if inner_close > 0 else []
            if not inner:
                return None
            start, end = inner[0]
            skip_prefix = True
        binding: Binding | None = None
        fn = function_at(self.content, start, min(len(self.content), start + _ARG_SCAN * 50), block_only=True)
        if fn is not None:
            binding = self._param_binding(fn)
        else:
            ident = _VALUE_IDENT.match(self.content, start, end)
            if ident:
                binding = self.resolve(ident.group(1), start, create=False) or self._function_binding(ident.group(1))
        if binding is not None and skip_prefix:
            binding.skip_prefix = True
        return binding

    def _parse_exports(self) -> None:
        last = None
        for last in _EXPORT_DEFAULT.finditer(self.content):
            pass
        if last is not None:
            binding = self._anonymous.get(last.start()) or self._value_binding(last.end())
            if binding is not None:
                self.exports["default"] = binding
            elif self.content.startswith("module", last.start()):
                self._object_exports(_WS.match(self.content, last.end()).end())
        for match in _EXPORT_DECL.finditer(self.content):
            name = match.group(1) or match.group(2)
            binding = self.resolve(name, match.end(), create=False) if match.group(1) else None
            binding = binding or self._function_binding(name)
            if binding is not None:
                self.exports.setdefault(name, binding)
        for match in _EXPORT_LIST.finditer(self.content):
            for part in match.group(1).split(","):
                names = _EXPORT_AS.match(part)
                if names:
                    local = names.group(1)
                    binding = self.resolve(local, match.start(), create=False) or self._function_binding(local)
                    if binding is not None:
                        self.exports.setdefault(names.group(2) or local, binding)
        for match in _CJS_EXPORT.finditer(self.content):
            binding = self._value_binding(match.end())
            if binding is not None:
                self.exports.setdefault(match.group(1), binding)

    def _object_exports(self, open_idx: int) -> None:
        """``module.exports = { users, admin: adminRouter }``."""
        if self.content[open_idx : open_idx + 1] != "{":
            return
        close = matching_close(self.content, open_idx)
        if close < 0:
            return
        for s, e in split_args(self.content, open_idx, close)[:256]:
            key, colon, value = self.content[s:e].partition(":")
            key = key.strip().strip("'\"")
            local = (value if colon else key).strip()
            if _IDENT_RE.fullmatch(key) and _IDENT_RE.fullmatch(local):
                binding = self.resolve(local, s, create=False) or self._function_binding(local)
                if binding is not None:
                    self.exports.setdefault(key, binding)


@dataclass
class Resolution:
    auth: str = UNKNOWN
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None
    # The routers each mount chain ends at (by identity): routes reaching one
    # app by the same path and method are the same endpoint to Express.
    roots: frozenset[int] = field(default_factory=frozenset)


_TEST_DIRS = frozenset({"tests", "test", "__tests__", "spec", "specs", "testing", "e2e", "__mocks__", "fixtures"})
_TEST_FILE = re.compile(r"[._](?:test|spec)\.[a-z0-9]+$", re.IGNORECASE)


def is_test_path(path: str) -> bool:
    """Test / spec / fixture code (mirrors core's test-file heuristic)."""
    parts = path.split("/")
    return any(part.lower() in _TEST_DIRS for part in parts[:-1]) or bool(_TEST_FILE.search(parts[-1]))


class Registry:
    """Every file's routers, so mounts of imported routers can be followed."""

    def __init__(self, resolver: ModuleResolver | None = None) -> None:
        self.files: dict[str, FileRouters] = {}
        self.reexports: dict[str, Reexports] = {}
        self.resolver = resolver or ModuleResolver(None)
        self._export_memo: dict[tuple[str, str], Binding | None] = {}
        self._module_memo: dict[tuple[str, str], str | None] = {}

    def add(self, routers: FileRouters) -> None:
        self.files[routers.file] = routers

    def add_module(self, file: str, content: str) -> None:
        """A file without routers that may re-export one (a barrel)."""
        if file not in self.files:
            reexports = parse_reexports(content)
            if reexports.named or reexports.star:
                self.reexports[file] = reexports

    def resolve_module(self, importer: str, spec: str) -> str | None:
        key = (importer, spec)
        if key not in self._module_memo:
            self._module_memo[key] = next(
                (
                    candidate
                    for base in self.resolver.bases(importer, spec)
                    for candidate in file_candidates(base)
                    if candidate in self.files or candidate in self.reexports
                ),
                None,
            )
        return self._module_memo[key]

    def lookup_export(self, file: str, name: str) -> Binding | None:
        """The binding ``file`` exports as ``name``, through re-exports.
        Memoized, and no (module, name) is visited twice in one lookup, so
        `export *` cycles stay linear."""
        if name == "*":
            name = "default"
        return self._lookup(file, name, 0, set())

    def _lookup(self, file: str, name: str, depth: int, visiting: set[tuple[str, str]]) -> Binding | None:
        key = (file, name)
        if key in self._export_memo:
            return self._export_memo[key]
        if key in visiting or depth >= _MAX_REEXPORT_DEPTH:
            return None
        visiting.add(key)
        found: Binding | None = None
        routers = self.files.get(file)
        if routers is not None and name in routers.exports:
            found = routers.exports[name]
        else:
            reexports = routers.reexports if routers is not None else self.reexports.get(file)
            ref = reexports.named.get(name) if reexports is not None else None
            if ref is not None:
                target = self.resolve_module(file, ref.spec)
                found = self._lookup(target, ref.name, depth + 1, visiting) if target else None
            elif reexports is not None:
                for spec in reexports.star[:_MAX_STAR_EXPORTS]:
                    target = self.resolve_module(file, spec)
                    found = self._lookup(target, name, depth + 1, visiting) if target else None
                    if found is not None:
                        break
        if found is not None or depth == 0:
            # A miss deep in a cycle may only be a cut-off: cache it from the top.
            self._export_memo[key] = found
        return found

    def finalize(self) -> None:
        """Attach cross-file mounts to the export they mount. Mounts made by
        test code would add paths that production never serves."""
        for routers in self.files.values():
            if is_test_path(routers.file):
                continue
            for ref, mount in routers.import_mounts:
                target = self.resolve_module(routers.file, ref.spec)
                binding = self.lookup_export(target, ref.name) if target else None
                if binding is not None and binding is not mount.owner:
                    binding.mounts.append(mount)

    def route_variants(
        self, binding: Binding | None, offset: int, path: str, local: list[Guard], fallback: str
    ) -> list[tuple[str, Resolution]]:
        """``(full path, auth)`` for each distinct path the route is mounted
        at. ``fallback`` (the file-local path) is kept when no mount or prefix
        applies."""
        if binding is None:
            return [(fallback, Resolution())]
        chains = self._paths(binding, offset, path, list(local), 0, [_MAX_PATHS])
        mounted = any(full != path for _, full, _, _ in chains)
        grouped: dict[str, list[Resolution]] = {}
        roots: dict[str, set[int]] = {}
        for guards, full, complete, root in chains:
            key = full if mounted else fallback
            if key in grouped or len(grouped) < _MAX_VARIANTS:
                grouped.setdefault(key, []).append(evaluate(guards, full if complete else None, complete))
                roots.setdefault(key, set()).add(root)
        out: list[tuple[str, Resolution]] = []
        for key, results in grouped.items():
            resolution = combine(results)
            resolution.roots = frozenset(roots[key])
            out.append((key, resolution))
        return out

    def _paths(
        self, binding: Binding, offset: int, rel_path: str, applied: list[Guard], depth: int, budget: list[int]
    ) -> list[tuple[list[Guard], str, bool, int]]:
        """Every (guards, path, whole chain seen, top router) from a route up
        to a root."""
        budget[0] -= 1
        if binding.overflow or depth >= _MAX_DEPTH or budget[0] < 0:
            return [(applied, rel_path, False, id(binding))]
        applied = list(applied)
        for use_offset, guards in binding.uses:
            if use_offset >= offset:
                continue
            for guard in guards:
                if guard.prefix is None or _under(rel_path, guard.prefix):
                    applied.append(guard)
        up_path = join_path(binding.prefix, rel_path)
        if not binding.mounts:
            return [(applied, up_path, binding.root, id(binding))]
        if len(binding.mounts) > _MAX_PATHS:
            return [(applied, up_path, False, id(binding))]
        out: list[tuple[list[Guard], str, bool, int]] = []
        for mount in binding.mounts:
            prefix = "" if binding.skip_prefix else mount.prefix
            out += self._paths(mount.owner, mount.offset, join_path(prefix, up_path), applied + mount.guards, depth + 1, budget)
        return out


def combine(results: list[Resolution]) -> Resolution:
    """One route's state over every mount chain that reaches it."""
    if not results or any(r.auth == UNKNOWN for r in results):
        return Resolution()
    if all(r.auth == REQUIRED for r in results):
        names = list(dict.fromkeys(n for r in results for n in r.guards))
        return Resolution(REQUIRED, names, clip("; ".join(dict.fromkeys(r.evidence for r in results if r.evidence))))
    if all(r.auth == ANONYMOUS for r in results):
        return Resolution(ANONYMOUS, [], clip("; ".join(dict.fromkeys(r.evidence for r in results if r.evidence))))
    return Resolution()


def evaluate(guards: list[Guard], full_path: str | None, complete: bool) -> Resolution:
    required: list[Guard] = []
    skipped: list[Guard] = []
    uncertain = False
    for guard in guards:
        if guard.uncertain:
            uncertain = True
        elif guard.skip is None:
            required.append(guard)
        elif not guard.skip.characterized or full_path is None:
            uncertain = True
        elif full_path in guard.skip.exact:
            skipped.append(guard)
        else:
            required.append(guard)
    if required:
        names = list(dict.fromkeys(g.name for g in required))
        return Resolution(REQUIRED, names, clip("; ".join(dict.fromkeys(g.evidence for g in required))))
    if uncertain or not complete:
        return Resolution()
    if skipped:
        return Resolution(ANONYMOUS, [], clip("; ".join(dict.fromkeys(g.skip.evidence for g in skipped if g.skip))))
    return Resolution()


# ---------- NestJS ----------

_DECORATOR = re.compile(r"@([A-Za-z_$][\w$]*)\s*(\()?")
_CLASS_AFTER = re.compile(r"(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\b")
_PUBLIC_DECORATORS = frozenset({"Public", "SkipAuth", "AllowAnonymous", "IsPublic", "Anonymous", "NoAuth", "PublicRoute"})
_PUBLIC_METADATA = re.compile(r"""^\s*['"](?:isPublic|IS_PUBLIC_KEY|public|skipAuth)['"]\s*,\s*true\s*$|^\s*IS_PUBLIC_KEY\s*,\s*true\s*$""")
_PASSPORT_GUARD = re.compile(r"^\s*AuthGuard\s*\(")
_NEST_GUARD_NAME = re.compile(r"auth(?!or)|jwt|session|api_?key|bearer|logged_?in|clerk|firebase", re.IGNORECASE)
# Admits callers without credentials: not a guard.
_NEST_NOT_GUARD = re.compile(r"optional|public|anonymous|guest|maybe|soft", re.IGNORECASE)
# Reads role metadata (`@Roles(...)`); without that metadata it lets requests through.
_NEST_METADATA_ROLE_GUARD = re.compile(r"role|permission|polic|casl|abilit|pbac|acl|scope", re.IGNORECASE)
_NEST_ROLE_GUARD = re.compile(r"admin|staff|superuser", re.IGNORECASE)
_NEST_ROLE_METADATA = re.compile(
    r"\w*Roles?|\w*Permissions?|CheckPolicies|Policies|Pbac|Scopes|RequireScopes|CheckAbilities|Abilities"
)
_GLOBAL_GUARDS = re.compile(r"\.\s*useGlobalGuards\s*\(")
_APP_GUARD = re.compile(r"provide\s*:\s*APP_GUARD\s*,\s*use(?:Class|Existing)\s*:\s*([A-Za-z_$][\w$]*)")


@dataclass
class DecoratorBlock:
    decorators: list[tuple[int, str, str]]  # (offset, name, argument text)
    is_class: bool


def decorator_blocks(content: str) -> list[DecoratorBlock]:
    """Consecutive ``@Decorator(...)`` runs and whether a class follows."""
    blocks: list[DecoratorBlock] = []
    current: list[tuple[int, str, str]] = []
    pos = 0
    while True:
        match = _DECORATOR.search(content, pos)
        if not match:
            break
        args = ""
        end = match.end()
        if match.group(2):
            close = matching_close(content, match.end() - 1)
            if close < 0:
                pos = match.end()
                continue
            args = content[match.end() : min(close, match.end() + _ARG_SCAN)]
            end = close + 1
        current.append((match.start(), match.group(1), args))
        nxt = _WS.match(content, end).end()
        pos = end
        if content.startswith("@", nxt):
            continue
        blocks.append(DecoratorBlock(current, bool(_CLASS_AFTER.match(content, nxt))))
        current = []
    return blocks


def _nest_guards(args: str) -> list[tuple[str, bool, str]]:
    """``(guard name, is Passport's AuthGuard(...), kind)`` for the auth and
    role guards in ``@UseGuards(...)`` / ``useGlobalGuards(...)`` arguments.
    ``kind`` is ``authn``, ``role`` or ``metadata`` (a role guard that needs
    role metadata to reject anything)."""
    out = []
    for part in args.split(","):
        part = part.strip()
        name = _NEW.sub("", part).split("(", 1)[0].strip()
        if not name or _NEST_NOT_GUARD.search(name):
            continue
        passport = bool(_PASSPORT_GUARD.match(part))
        if _NEST_GUARD_NAME.search(name):
            out.append((part if passport else name, passport, AUTHN))
        elif _NEST_ROLE_GUARD.search(name):
            out.append((name, False, ROLE))
        elif _NEST_METADATA_ROLE_GUARD.search(name):
            out.append((name, False, "metadata"))
    return out


def nest_global_guards(content: str) -> list[tuple[str, bool, str, str]]:
    found = []
    for match in _GLOBAL_GUARDS.finditer(content):
        close = matching_close(content, match.end() - 1)
        if close > 0:
            args = content[match.end() : min(close, match.end() + _ARG_SCAN)]
            evidence = clip(content[match.start() + 1 : close + 1])
            found += [(name, passport, kind, evidence) for name, passport, kind in _nest_guards(args)]
    for match in _APP_GUARD.finditer(content):
        for name, passport, kind in _nest_guards(match.group(1)):
            found.append((name, passport, kind, clip(match.group(0))))
    return found


class NestFile:
    """Decorator blocks of one file, for its route decorators."""

    def __init__(self, content: str) -> None:
        blocks = decorator_blocks(content)
        self._by_offset = {off: block for block in blocks for off, _, _ in block.decorators}
        self._classes = [b for b in blocks if b.is_class]
        self._class_starts = [b.decorators[0][0] for b in self._classes]

    def resolve(self, route_offset: int, global_guards: list[tuple[str, bool, str, str]]) -> Resolution:
        block = self._by_offset.get(route_offset)
        if block is None:
            return Resolution()
        index = bisect.bisect_left(self._class_starts, route_offset) - 1
        owner = self._classes[index] if index >= 0 else None
        guards: list[tuple[str, bool, str, str]] = list(global_guards)
        public: list[str] = []
        metadata: list[str] = []
        for decorated in (owner, block):
            if decorated is None:
                continue
            for _, name, args in decorated.decorators:
                if name == "UseGuards":
                    evidence = clip(f"@UseGuards({args})")
                    guards += [(g, passport, kind, evidence) for g, passport, kind in _nest_guards(args)]
                elif name in _PUBLIC_DECORATORS or name == "SetMetadata" and _PUBLIC_METADATA.match(args):
                    public.append(clip(f"@{name}({args})"))
                elif _NEST_ROLE_METADATA.fullmatch(name):
                    metadata.append(clip(f"@{name}({args})"))
        # A metadata-driven role guard only rejects routes that carry its metadata.
        guards = [g for g in guards if g[2] != "metadata" or metadata]
        if public and not any(passport for _, passport, _, _ in guards):
            return Resolution(ANONYMOUS, [], clip("; ".join(public)))
        if guards:
            names = list(dict.fromkeys(g for g, _, _, _ in guards))
            evidence = list(dict.fromkeys(ev for _, _, _, ev in guards))
            if any(kind != AUTHN for _, _, kind, _ in guards):
                evidence += metadata
            return Resolution(REQUIRED, names, clip("; ".join(evidence)))
        return Resolution()
