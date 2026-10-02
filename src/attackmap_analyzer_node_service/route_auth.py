"""Route-level auth resolution for the AttackMap#256 contract.

Each emitted ``Route`` carries ``auth`` (``required`` / ``anonymous`` /
``unknown``), the ``guards`` that apply and the ``guard_evidence`` source text
that established the state. Core trusts a declared state over its own
same-file resolution, so this only declares what the source verifiably says.

**Express / Koa / Hono / Fastify** — routers are tracked by variable:

- roots (``express()``, ``new Koa()``, ``new Hono()``, ``fastify()``) and
  routers (``express.Router()``, ``new Router({ prefix })``);
- ``X.use([path,] mw...)``, ``X.all('*', mw...)`` and Fastify
  ``X.addHook('onRequest' | 'preHandler' | ..., mw)`` guard the routes
  registered on ``X`` *after* them (in order, as Express / Koa / Hono run
  them), under ``path`` when one is given;
- ``X.use([path,] mw..., router)`` / ``X.use(router.routes())`` /
  ``X.route(path, sub)`` mount a router: the mount's middleware, and ``X``'s
  earlier middleware, wrap every route of the mounted router. A router
  imported from another file (``require('./routes/users')`` / ``import users
  from './routes/users'``) is followed to that file's ``module.exports`` /
  ``export default`` router;
- Fastify ``register(async (instance) => {...}, { prefix })`` closures
  inherit the parent's hooks;
- route-local middleware: ``router.post('/x', requireAuth, h)`` (arrays
  flattened), ``router.route('/x').post(mw, h)``, and Fastify route options
  ``{ preHandler | onRequest | preValidation: [...] }``.

A middleware is a guard when its name says it authenticates (``requireAuth``,
``isAuthenticated``, ``passport.authenticate('jwt')``, ``expressjwt(...)``,
``jwt(...)``, ``bearerAuth(...)``, ``fastify.authenticate``) or an inline
hook calls ``jwtVerify()``. ``optionalAuth``-style middleware and
``passport.authenticate('anonymous')`` are not guards.

``guard.unless({ path: ['/login', ...] })`` (express-unless) is an explicit
opt-out: a route whose full path is listed is ``anonymous`` when no other
guard applies. A list with regexes or other keys makes the guard uncertain.

**NestJS** — ``@UseGuards(...)`` on the method or controller, and a global
guard (``app.useGlobalGuards(...)`` / ``{ provide: APP_GUARD, useClass }``)
make a route ``required``. ``@Public()`` / ``@SkipAuth()`` /
``@AllowAnonymous()`` / ``@SetMetadata('isPublic', true)`` make it
``anonymous``, unless a guard is Passport's own ``AuthGuard('...')``, which
ignores that metadata.

Anything else stays ``unknown``. Brackets are matched in one cached pass per
file, argument lists are split by jumping over nested functions, and lookups
are bounded, so every scan is linear.
"""

from __future__ import annotations

import bisect
import functools
import posixpath
import re
from dataclasses import dataclass, field

REQUIRED = "required"
ANONYMOUS = "anonymous"
UNKNOWN = "unknown"

_EVIDENCE_MAX = 200
_ARG_SCAN = 4000
_LOOKUP_LIMIT = 64  # bindings of one name searched
_MAX_DEPTH = 16  # mount levels followed
_MAX_PATHS = 64  # mount paths explored per route
_MAX_USES = 32  # guarding use() calls kept per router


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
_AUTH_NAME = re.compile(
    r"auth(?!or)|jwt|bearer|logged_?in|login_?required|require_?(?:user|login|admin|token|role|permission|session)"
    r"|verify_?(?:token|jwt|user|session)|check_?(?:jwt|token|session)|protect|passport|api_?key"
    r"|session_?required|clerk",
    re.IGNORECASE,
)
_NOT_AUTH_NAME = re.compile(r"optional|maybe|soft|try_?auth|cors|csrf|rate_?limit|throttl|helmet", re.IGNORECASE)
_INLINE_VERIFY = re.compile(r"\.\s*jwtVerify\s*\(")
_FUNCTION_START = re.compile(r"\s*(?:async\s+)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)")
_UNLESS = re.compile(r"\.\s*unless\s*\(")
_ANONYMOUS_STRATEGY = re.compile(r"""\s*['"]anonymous['"]""")


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
    """A Guard when the middleware argument ``content[start:end]`` authenticates."""
    end = min(end, start + _ARG_SCAN)
    text = content[start:end]
    evidence = clip(context if context is not None else text)
    if _FUNCTION_START.match(text):
        # An inline hook / middleware: a guard when it verifies a JWT.
        return Guard("jwtVerify", evidence) if _INLINE_VERIFY.search(text) else None
    match = _ARG_NAME.match(content, start, end)
    if not match:
        return None
    name = re.sub(r"\s+", "", match.group(1))
    if not _AUTH_NAME.search(name) or _NOT_AUTH_NAME.search(name):
        return None
    if name.endswith("passport.authenticate") or name == "passport.authenticate":
        paren = content.find("(", match.end(), end)
        if paren >= 0 and _ANONYMOUS_STRATEGY.match(content, paren + 1, end):
            return None
    return Guard(name, evidence, _unless(content, start, end))


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
_HOOK_KEYS = re.compile(r"""\s*['"]?(preHandler|onRequest|preValidation|preParsing)['"]?\s*:""")


def route_option_guards(content: str, start: int, end: int, context: str) -> list[Guard]:
    """Fastify route options ``{ preHandler: [...], onRequest: fn }``."""
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
        for vs, ve in flatten(content, [(key.end(), pe)]):
            guard = guard_from_arg(content, vs, ve, context)
            if guard:
                guards.append(guard)
    return guards


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
    prefix: str = ""  # koa `new Router({ prefix })`, fastify register `{ prefix }`
    uses: list[tuple[int, list[Guard]]] = field(default_factory=list)
    mounts: list[Mount] = field(default_factory=list)
    overflow: bool = False


_ROOT = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*(?::\s*[^=;\n]+)?=\s*(?:await\s+)?"
    r"(?:express\s*\(\s*\)|fastify\s*\(|Fastify\s*\(|polka\s*\(|new\s+(?:Koa|Hono|OpenAPIHono|Elysia)\b)"
)
_ROUTER = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*(?::\s*[^=;\n]+)?=\s*(?:express\s*\.\s*Router\s*\(|Router\s*\(|new\s+(?:Router|KoaRouter)\s*\()"
)
_USE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*(use|all|route)\s*\(")
_HOOK = re.compile(
    r"""\b([A-Za-z_$][\w$]*)\s*\.\s*addHook\s*\(\s*['"](?:onRequest|preHandler|preValidation|preParsing)['"]\s*,"""
)
_REGISTER = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*register\s*\(\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?\(\s*([A-Za-z_$][\w$]*)"
)
_IMPORT_REQUIRE = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](\.{1,2}/[^'"]+)['"]\s*\)"""
)
_IMPORT_DEFAULT = re.compile(r"""\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+['"](\.{1,2}/[^'"]+)['"]""")
_EXPORT_DEFAULT = re.compile(r"\b(?:module\s*\.\s*exports|export\s+default)\s*=?\s*([A-Za-z_$][\w$]*)\s*;?\s*$", re.MULTILINE)
_PREFIX_OPTION = re.compile(r"""\bprefix\s*:\s*['"]([^'"]*)['"]""")
_ROUTES_CALL = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:routes|middleware)\s*\(\s*\)\s*$")
_IDENT = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*$")


def join_path(prefix: str, path: str) -> str:
    if not prefix:
        return path
    if not path or path == "/":
        return "/" + prefix.strip("/") if prefix.strip("/") else "/"
    return "/" + "/".join(p for p in (prefix.strip("/"), path.strip("/")) if p)


def _under(path: str, prefix: str) -> bool:
    """Express/Hono path-prefix match (`/api` covers `/api` and `/api/x`)."""
    prefix = prefix.rstrip("*")
    if prefix in ("", "/"):
        return True
    if prefix.endswith("/"):
        return path.startswith(prefix) or path == prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


class FileRouters:
    """Router variables, their middleware and mounts in one file."""

    def __init__(self, content: str, file: str) -> None:
        self.content = content
        self.file = file
        pairs = bracket_pairs(content)
        blocks = sorted((o, c) for o, c in pairs.items() if content[o] == "{")
        self._top: list[tuple[int, int]] = []
        for block in blocks:
            if not self._top or block[0] > self._top[-1][1]:
                self._top.append(block)
        self._top_starts = [s for s, _ in self._top]
        self._blocks = blocks
        self._stack: list[tuple[int, int]] = []
        self._next_block = 0
        self._by_name: dict[str, list[Binding]] = {}
        self._offsets: dict[str, list[int]] = {}
        self._free: dict[tuple[str, int], Binding] = {}
        self.imports: dict[str, str] = {}  # local name -> import specifier
        self.import_mounts: list[tuple[str, Mount]] = []  # (specifier, mount)
        self.exported: Binding | None = None
        for match in _IMPORT_REQUIRE.finditer(content):
            self.imports.setdefault(match.group(1), match.group(2))
        for match in _IMPORT_DEFAULT.finditer(content):
            self.imports.setdefault(match.group(1), match.group(2))

        events: list[tuple[int, int, re.Match]] = []
        for kind, pattern in enumerate((_ROOT, _ROUTER, _REGISTER, _USE, _HOOK)):
            events += [(m.start(), kind, m) for m in pattern.finditer(content)]
        events.sort(key=lambda e: (e[0], e[1]))
        for offset, kind, match in events:
            scope = self._advance(offset)
            if kind in (0, 1):
                binding = Binding(match.group(1), offset, scope, root=kind == 0)
                if kind == 1:
                    paren = content.find("(", match.end() - 1)
                    close = matching_close(content, paren)
                    if close > 0:
                        option = _PREFIX_OPTION.search(content, paren, min(close, paren + 400))
                        binding.prefix = option.group(1) if option else ""
                self._bind(binding)
            elif kind == 2:
                self._register(match)
            elif kind == 3:
                self._use(match)
            else:
                self._hook(match)
        export = None
        for export in _EXPORT_DEFAULT.finditer(content):
            pass
        if export is not None:
            self.exported = self.resolve(export.group(1), export.start(), create=False)

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
        return self._stack[-1] if self._stack else (0, len(self.content))

    def _top_level(self, offset: int) -> tuple[int, int]:
        index = bisect.bisect_right(self._top_starts, offset) - 1
        if index >= 0 and self._top[index][1] >= offset:
            return self._top[index]
        return (0, len(self.content))

    def _bind(self, binding: Binding) -> None:
        offsets = self._offsets.setdefault(binding.name, [])
        index = bisect.bisect_right(offsets, binding.offset)
        offsets.insert(index, binding.offset)
        self._by_name.setdefault(binding.name, []).insert(index, binding)

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

    # -- events --

    def _register(self, match: re.Match) -> None:
        """``fastify.register(async (instance, opts) => {...}, { prefix })``."""
        parent = self.resolve(match.group(1), match.start())
        paren = self.content.find("(", match.start() + len(match.group(1)))
        close = matching_close(self.content, paren)
        if parent is None or close < 0:
            return
        args = split_args(self.content, paren, close)
        if not args:
            return
        body_open = self.content.find("{", match.end(), args[0][1])
        body_close = matching_close(self.content, body_open)
        if body_open < 0 or body_close < 0:
            return
        prefix = ""
        if len(args) > 1:
            option = _PREFIX_OPTION.search(self.content, args[1][0], min(args[1][1], args[1][0] + 400))
            prefix = option.group(1) if option else ""
        child = Binding(match.group(2), body_open, (body_open, body_close), prefix=prefix)
        child.mounts.append(Mount(parent, match.start(), "", [], self))
        self._bind(child)

    def _mount_target(self, start: int, end: int) -> tuple[str, Binding | None] | None:
        """A router mounted by a use()/route() argument: (name, binding), or
        (name, None) for an imported module."""
        text = self.content[start : min(end, start + 300)]
        routes_call = _ROUTES_CALL.match(text)
        ident = routes_call or _IDENT.match(text)
        if not ident:
            return None
        name = ident.group(1)
        binding = self.resolve(name, start, create=False)
        if binding is not None and (binding.root or name in self._by_name):
            return name, binding
        if name in self.imports and (routes_call or not _AUTH_NAME.search(name)):
            return name, None
        return None

    def _use(self, match: re.Match) -> None:
        owner = self.resolve(match.group(1), match.start())
        paren = match.end() - 1
        close = matching_close(self.content, paren)
        if owner is None or close < 0:
            return
        args = split_args(self.content, paren, close)
        if not args:
            return
        verb = match.group(2)
        prefix: str | None = None
        first = string_literal(self.content[args[0][0] : args[0][1]])
        if first is not None:
            prefix, args = first, args[1:]
        elif verb in ("all", "route"):
            return
        if verb == "all" and not prefix.endswith("*"):
            return  # a real `.all('/x', h)` route, not a catch-all guard
        context = self._context(match.start(), close)
        args = flatten(self.content, args)
        target = self._mount_target(*args[-1]) if args and verb in ("use", "route") else None
        middleware = args[:-1] if target else args
        guards = [g for s, e in middleware if (g := guard_from_arg(self.content, s, e, context))]
        if target is not None:
            name, binding = target
            mount = Mount(owner, match.start(), prefix or "", guards, self)
            if binding is not None:
                binding.mounts.append(mount)
            else:
                self.import_mounts.append((self.imports[name], mount))
            return
        if not guards:
            return
        for guard in guards:
            guard.prefix = prefix
        if len(owner.uses) >= _MAX_USES:
            owner.overflow = True
            return
        owner.uses.append((match.start(), guards))

    def _hook(self, match: re.Match) -> None:
        owner = self.resolve(match.group(1), match.start())
        paren = self.content.find("(", match.start() + len(match.group(1)))
        close = matching_close(self.content, paren)
        if owner is None or close < 0:
            return
        args = split_args(self.content, paren, close)[1:]
        context = self._context(match.start(), close)
        guards = [g for s, e in flatten(self.content, args) if (g := guard_from_arg(self.content, s, e, context))]
        if guards and len(owner.uses) < _MAX_USES:
            owner.uses.append((match.start(), guards))
        elif guards:
            owner.overflow = True


@dataclass
class Resolution:
    auth: str = UNKNOWN
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


class Registry:
    """Every file's routers, so mounts of imported routers can be followed."""

    def __init__(self) -> None:
        self.files: dict[str, FileRouters] = {}

    def add(self, routers: FileRouters) -> None:
        self.files[routers.file] = routers

    def _import_target(self, importer: str, spec: str) -> FileRouters | None:
        base = posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))
        stem = re.sub(r"\.(?:js|mjs|cjs|ts|tsx)$", "", base)
        for candidate in (base, *(stem + ext for ext in (".js", ".ts", ".mjs", ".cjs", ".tsx")),
                          *(f"{base}/index{ext}" for ext in (".js", ".ts", ".mjs", ".cjs"))):
            if candidate in self.files:
                return self.files[candidate]
        return None

    def finalize(self) -> None:
        """Attach cross-file mounts to the exported router they mount."""
        for routers in self.files.values():
            for spec, mount in routers.import_mounts:
                target = self._import_target(routers.file, spec)
                if target is not None and target.exported is not None:
                    target.exported.mounts.append(mount)
                elif target is None:
                    continue

    def resolve_route(
        self, routers: FileRouters, receiver: str, offset: int, path: str, local: list[Guard]
    ) -> Resolution:
        binding = routers.resolve(receiver, offset)
        if binding is None:
            return Resolution()
        budget = [_MAX_PATHS]
        paths = self._paths(binding, offset, path, list(local), 0, budget)
        results = [evaluate(guards, full_path, complete) for guards, full_path, complete in paths]
        if not results or any(r.auth == UNKNOWN for r in results):
            return Resolution()
        if all(r.auth == REQUIRED for r in results):
            names = list(dict.fromkeys(n for r in results for n in r.guards))
            evidence = "; ".join(dict.fromkeys(r.evidence for r in results if r.evidence))
            return Resolution(REQUIRED, names, clip(evidence))
        if all(r.auth == ANONYMOUS for r in results):
            return Resolution(ANONYMOUS, [], clip("; ".join(dict.fromkeys(r.evidence for r in results if r.evidence))))
        return Resolution()

    def _paths(
        self, binding: Binding, offset: int, rel_path: str | None, applied: list[Guard], depth: int, budget: list[int]
    ) -> list[tuple[list[Guard], str | None, bool]]:
        """Every (guards, full path, whole chain seen) from a route up to a root."""
        budget[0] -= 1
        if binding.overflow or depth >= _MAX_DEPTH or budget[0] < 0:
            return [(applied, None, False)]
        applied = list(applied)
        for use_offset, guards in binding.uses:
            if use_offset >= offset:
                continue
            for guard in guards:
                if guard.prefix is None:
                    applied.append(guard)
                elif rel_path is None:
                    applied.append(Guard(guard.name, guard.evidence, uncertain=True))
                elif _under(rel_path, guard.prefix):
                    applied.append(guard)
        up_path = None if rel_path is None else join_path(binding.prefix, rel_path)
        if not binding.mounts:
            return [(applied, up_path if binding.root else None, binding.root)]
        if len(binding.mounts) > _MAX_PATHS:
            return [(applied, None, False)]
        out: list[tuple[list[Guard], str | None, bool]] = []
        for mount in binding.mounts:
            mounted_path = None if up_path is None else join_path(mount.prefix, up_path)
            out += self._paths(mount.owner, mount.offset, mounted_path, applied + mount.guards, depth + 1, budget)
        return out


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
_WS = re.compile(r"(?:\s|//[^\n]{0,500}\n|/\*(?:[^*]|\*(?!/)){0,500}\*/)*")
_CLASS_AFTER = re.compile(r"(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\b")
_PUBLIC_DECORATORS = frozenset({"Public", "SkipAuth", "AllowAnonymous", "IsPublic", "Anonymous", "NoAuth", "PublicRoute"})
_PUBLIC_METADATA = re.compile(r"""^\s*['"](?:isPublic|IS_PUBLIC_KEY|public|skipAuth)['"]\s*,\s*true\s*$|^\s*IS_PUBLIC_KEY\s*,\s*true\s*$""")
_PASSPORT_GUARD = re.compile(r"^\s*AuthGuard\s*\(")
_NEST_GUARD_NAME = re.compile(r"auth(?!or)|jwt|session|api_?key|bearer|logged_?in|clerk|firebase", re.IGNORECASE)
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


def _nest_guards(args: str) -> list[tuple[str, bool]]:
    """``(guard name, is Passport's AuthGuard(...))`` for auth guards in
    ``@UseGuards(...)`` / ``useGlobalGuards(...)`` arguments."""
    out = []
    for part in args.split(","):
        part = part.strip()
        name = re.sub(r"^new\s+", "", part).split("(", 1)[0].strip()
        if name and _NEST_GUARD_NAME.search(name):
            out.append((part if _PASSPORT_GUARD.match(part) else name, bool(_PASSPORT_GUARD.match(part))))
    return out


def nest_global_guards(content: str) -> list[tuple[str, bool, str]]:
    found = []
    for match in _GLOBAL_GUARDS.finditer(content):
        close = matching_close(content, match.end() - 1)
        if close > 0:
            args = content[match.end() : min(close, match.end() + _ARG_SCAN)]
            evidence = clip(content[match.start() + 1 : close + 1])
            found += [(name, passport, evidence) for name, passport in _nest_guards(args)]
    for match in _APP_GUARD.finditer(content):
        if _NEST_GUARD_NAME.search(match.group(1)):
            found.append((match.group(1), False, clip(match.group(0))))
    return found


class NestFile:
    """Decorator blocks of one file, for its route decorators."""

    def __init__(self, content: str) -> None:
        blocks = decorator_blocks(content)
        self._by_offset = {off: block for block in blocks for off, _, _ in block.decorators}
        self._classes = [b for b in blocks if b.is_class]
        self._class_starts = [b.decorators[0][0] for b in self._classes]

    def resolve(self, route_offset: int, global_guards: list[tuple[str, bool, str]]) -> Resolution:
        block = self._by_offset.get(route_offset)
        if block is None:
            return Resolution()
        index = bisect.bisect_left(self._class_starts, route_offset) - 1
        owner = self._classes[index] if index >= 0 else None
        guards: list[tuple[str, bool, str]] = list(global_guards)
        public: list[str] = []
        for decorated in (owner, block):
            if decorated is None:
                continue
            for _, name, args in decorated.decorators:
                if name == "UseGuards":
                    evidence = clip(f"@UseGuards({args})")
                    guards += [(g, passport, evidence) for g, passport in _nest_guards(args)]
                elif name in _PUBLIC_DECORATORS or name == "SetMetadata" and _PUBLIC_METADATA.match(args):
                    public.append(clip(f"@{name}({args})"))
        if public and not any(passport for _, passport, _ in guards):
            return Resolution(ANONYMOUS, [], clip("; ".join(public)))
        if guards:
            names = list(dict.fromkeys(g for g, _, _ in guards))
            return Resolution(REQUIRED, names, clip("; ".join(dict.fromkeys(ev for _, _, ev in guards))))
        return Resolution()
