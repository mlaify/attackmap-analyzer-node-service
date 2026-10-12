"""Import / export maps and module-specifier resolution (#4).

Cross-file router mounts need to know which file an import names and which
binding that file exports. Everything here is a bounded regex or a lookup:

- **imports**: ``const x = require('s')`` (``.default`` / ``.name``),
  ``const { a, b: c } = require('s')``, ``import x, { a as b } from 's'``,
  ``import * as ns from 's'``;
- **re-exports** (barrel files): ``export { default as x, y } from 's'``,
  ``export * from 's'``, ``module.exports = require('s')``,
  ``exports.x = require('s')``;
- **specifiers**: relative paths, then ``compilerOptions.paths`` /
  ``baseUrl`` from the nearest ``tsconfig.json`` / ``jsconfig.json`` (one
  level of relative ``extends`` per step, three steps at most), then workspace
  packages by their ``package.json`` ``name``. A path resolves to a file by
  extension (``.js`` / ``.ts`` / ...) or to its ``index`` file. Nothing outside
  the repo is ever read, and specifiers that leave it are dropped.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, read_source, rel

SKIP_DIRS = DEFAULT_SKIP_DIRS | {".svelte-kit"}

_EXTENSIONS = (".ts", ".js", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".jsx")
_STRIP_EXT = re.compile(r"\.(?:js|mjs|cjs|jsx|ts|tsx|mts|cts)$")
_MAX_IMPORTS = 512  # import bindings kept per file
_MAX_REEXPORTS = 256
_MAX_CONFIGS = 2000  # tsconfig / package.json files read per repo
_MAX_CONFIG_BYTES = 256 * 1024
_MAX_EXTENDS = 3
_MAX_BASES = 8

_IDENT = r"[A-Za-z_$][\w$]*"
_SPEC = r"""['"]([^'"\n]{1,300})['"]"""

# `const x = require('s')`, `const x = require('s').default`, `... .router`
_REQUIRE_DEFAULT = re.compile(
    rf"\b(?:const|let|var)\s+({_IDENT})\s*=\s*(?:await\s+)?require\s*\(\s*{_SPEC}\s*\)(?:\s*\.\s*({_IDENT}))?"
)
# `const { a, b: c } = require('s')`
_REQUIRE_NAMED = re.compile(rf"\b(?:const|let|var)\s*\{{([^{{}}]{{0,1000}})\}}\s*=\s*require\s*\(\s*{_SPEC}\s*\)")
# `import x from 's'`, `import x, { a as b } from 's'`, `import { a } from 's'`,
# `import * as ns from 's'`, `import type ...` (harmless: types never mount).
_IMPORT_FROM = re.compile(
    rf"\bimport\s+(?:type\s+)?(?:({_IDENT})\s*,?\s*)?(?:\*\s*as\s+({_IDENT})\s*)?"
    rf"(?:\{{([^{{}}]{{0,1000}})\}}\s*)?from\s*{_SPEC}"
)
# `export { default as x, y as z } from 's'` / `export * from 's'`
_REEXPORT_NAMED = re.compile(rf"\bexport\s+(?:type\s+)?\{{([^{{}}]{{0,1000}})\}}\s*from\s*{_SPEC}")
_REEXPORT_STAR = re.compile(rf"\bexport\s+\*\s+from\s*{_SPEC}")
# `module.exports = require('s')` / `exports.x = require('s')` / `module.exports.x = require('s')`
_CJS_REEXPORT = re.compile(
    rf"\b(?:module\s*\.\s*exports(?:\s*\.\s*({_IDENT}))?|exports\s*\.\s*({_IDENT}))\s*=\s*require\s*\(\s*{_SPEC}\s*\)"
)
_AS = re.compile(rf"^\s*(?:type\s+)?({_IDENT})(?:\s+as\s+({_IDENT}))?\s*$")
_COLON = re.compile(rf"^\s*({_IDENT})(?:\s*:\s*({_IDENT}))?\s*(?:=[^,]*)?$")


@dataclass(frozen=True)
class ImportRef:
    """``name`` exported by the module ``spec``: ``default``, a named export,
    or ``*`` for a namespace / CommonJS object import."""

    spec: str
    name: str


def parse_imports(content: str) -> dict[str, ImportRef]:
    """Local name -> what it imports."""
    imports: dict[str, ImportRef] = {}

    def add(local: str, ref: ImportRef) -> None:
        if len(imports) < _MAX_IMPORTS:
            imports.setdefault(local, ref)

    for match in _REQUIRE_DEFAULT.finditer(content):
        member = match.group(3)
        add(match.group(1), ImportRef(match.group(2), member if member and member != "default" else "*"))
    for match in _REQUIRE_NAMED.finditer(content):
        for part in match.group(1).split(","):
            names = _COLON.match(part)
            if names:
                add(names.group(2) or names.group(1), ImportRef(match.group(2), names.group(1)))
    for match in _IMPORT_FROM.finditer(content):
        default, namespace, named, spec = match.groups()
        if default:
            add(default, ImportRef(spec, "default"))
        if namespace:
            add(namespace, ImportRef(spec, "*"))
        for part in (named or "").split(","):
            names = _AS.match(part)
            if names:
                add(names.group(2) or names.group(1), ImportRef(spec, names.group(1)))
    return imports


@dataclass
class Reexports:
    named: dict[str, ImportRef] = field(default_factory=dict)
    star: list[str] = field(default_factory=list)


def parse_reexports(content: str) -> Reexports:
    out = Reexports()
    if "export" not in content:
        return out
    for match in _REEXPORT_NAMED.finditer(content):
        for part in match.group(1).split(","):
            names = _AS.match(part)
            if names and len(out.named) < _MAX_REEXPORTS:
                out.named.setdefault(names.group(2) or names.group(1), ImportRef(match.group(2), names.group(1)))
    for match in _REEXPORT_STAR.finditer(content):
        if len(out.star) < _MAX_REEXPORTS:
            out.star.append(match.group(1))
    for match in _CJS_REEXPORT.finditer(content):
        # `exports.x = require('s')`: x is what `s` assigned to module.exports.
        # `module.exports = require('s')` re-exports all of `s`.
        name = match.group(1) or match.group(2) or "default"
        if len(out.named) < _MAX_REEXPORTS:
            out.named.setdefault(name, ImportRef(match.group(3), "default"))
            if name == "default":
                out.star.append(match.group(3))
    return out


# ---------- Specifier resolution ----------

_JSONC_START = re.compile(r'"|//|/\*')
_JSON_STRING_BODY = re.compile(r'[^"\\\n]*(?:\\.[^"\\\n]*)*"')
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_comments(text: str) -> str:
    """Drop ``//`` and ``/* */`` comments outside strings, in one pass."""
    out: list[str] = []
    pos, n = 0, len(text)
    while pos < n:
        match = _JSONC_START.search(text, pos)
        if not match:
            out.append(text[pos:])
            break
        out.append(text[pos : match.start()])
        token = match.group()
        if token == '"':
            body = _JSON_STRING_BODY.match(text, match.end())
            end = body.end() if body else n
            out.append(text[match.start() : end])
            pos = end
        elif token == "//":
            newline = text.find("\n", match.end())
            pos = n if newline < 0 else newline
        else:
            close = text.find("*/", match.end())
            pos = n if close < 0 else close + 2
    return "".join(out)


def load_jsonc(text: str) -> object:
    """``tsconfig.json`` allows comments and trailing commas."""
    if len(text) > _MAX_CONFIG_BYTES:
        return None
    stripped = _strip_comments(text)
    try:
        return json.loads(_TRAILING_COMMA.sub(r"\1", stripped))
    except (ValueError, RecursionError):
        return None


def file_candidates(base: str) -> list[str]:
    """Files a resolved specifier may name: itself, with an extension (a
    ``.js`` specifier may name the ``.ts`` source), or its ``index``."""
    stem = _STRIP_EXT.sub("", base)
    return [base, *(stem + ext for ext in _EXTENSIONS), *(f"{base}/index{ext}" for ext in _EXTENSIONS)]


def _inside(path: str) -> str | None:
    path = posixpath.normpath(path)
    if path == ".." or path.startswith("../") or path.startswith("/"):
        return None
    return "" if path == "." else path


@dataclass
class _PathConfig:
    base: str  # repo-relative directory paths are resolved against
    paths: list[tuple[str, list[str]]]
    base_url: str | None


class ModuleResolver:
    """Specifier -> candidate repo-relative paths (without extension)."""

    def __init__(self, root: Path | None) -> None:
        self.root = root
        self._configs: dict[str, _PathConfig] | None = None
        self._packages: list[tuple[str, str, str | None]] | None = None

    def bases(self, importer: str, spec: str) -> list[str]:
        if spec.startswith("."):
            base = _inside(posixpath.join(posixpath.dirname(importer), spec))
            return [] if base is None else [base]
        if self.root is None or spec.startswith("/") or ":" in spec:
            return []
        out = self._config_bases(importer, spec) + self._package_bases(spec)
        return list(dict.fromkeys(out))[:_MAX_BASES]

    # -- tsconfig / jsconfig `paths` --

    def _config_bases(self, importer: str, spec: str) -> list[str]:
        configs = self._load_configs()
        directory = posixpath.dirname(importer)
        while True:
            config = configs.get(directory)
            if config is not None:
                return self._apply(config, spec)
            if not directory:
                return []
            directory = posixpath.dirname(directory)

    @staticmethod
    def _apply(config: _PathConfig, spec: str) -> list[str]:
        out: list[str] = []
        for pattern, targets in config.paths:
            head, star, tail = pattern.partition("*")
            if star:
                if not (spec.startswith(head) and spec.endswith(tail) and len(spec) >= len(head) + len(tail)):
                    continue
                middle = spec[len(head) : len(spec) - len(tail)]
            elif spec != pattern:
                continue
            else:
                middle = ""
            for target in targets:
                resolved = _inside(posixpath.join(config.base, target.replace("*", middle, 1)))
                if resolved is not None:
                    out.append(resolved)
        if config.base_url is not None:
            resolved = _inside(posixpath.join(config.base_url, spec))
            if resolved is not None:
                out.append(resolved)
        return out

    def _load_configs(self) -> dict[str, _PathConfig]:
        if self._configs is not None:
            return self._configs
        self._configs = {}
        assert self.root is not None
        raw: dict[str, dict] = {}
        for count, path in enumerate(
            iter_repo_files(self.root, names={"tsconfig.json", "jsconfig.json"}, skip_dirs=SKIP_DIRS)
        ):
            if count >= _MAX_CONFIGS:
                break
            data = load_jsonc(read_source(path, root=self.root) or "")
            if isinstance(data, dict):
                raw.setdefault(rel(path, self.root), data)
        for config_path, data in list(raw.items()):
            options = self._options(config_path, raw)
            directory = posixpath.dirname(config_path)
            paths_owner, paths = options.get("paths", (directory, None))
            url_owner, base_url = options.get("baseUrl", (directory, None))
            if not isinstance(paths, dict) and not isinstance(base_url, str):
                continue
            base_url_dir = _inside(posixpath.join(url_owner, base_url)) if isinstance(base_url, str) else None
            pairs = [
                (pattern, [t for t in targets if isinstance(t, str)][:8])
                for pattern, targets in (paths.items() if isinstance(paths, dict) else [])
                if isinstance(pattern, str) and isinstance(targets, list)
            ][:64]
            # `paths` resolve against baseUrl when set, else the declaring config.
            base = base_url_dir if base_url_dir is not None else paths_owner
            self._configs.setdefault(directory, _PathConfig(base, pairs, base_url_dir))
        return self._configs

    def _options(self, config_path: str, raw: dict[str, dict]) -> dict[str, tuple[str, object]]:
        """``compilerOptions`` ``paths`` / ``baseUrl`` with the directory of the
        config that set each, following relative ``extends`` (which may name
        any file, e.g. ``tsconfig.base.json``)."""
        found: dict[str, tuple[str, object]] = {}
        current: str | None = config_path
        seen: set[str] = set()
        for _ in range(_MAX_EXTENDS + 1):
            if current is None or current in seen:
                break
            if current not in raw:
                assert self.root is not None
                data = load_jsonc(read_source(self.root / current, root=self.root) or "")
                if not isinstance(data, dict):
                    break
                raw[current] = data
            seen.add(current)
            config = raw[current]
            options = config.get("compilerOptions")
            if isinstance(options, dict):
                for key in ("paths", "baseUrl"):
                    if key in options and key not in found:
                        found[key] = (posixpath.dirname(current), options[key])
            parent = config.get("extends")
            following: str | None = None
            if isinstance(parent, str) and parent.startswith("."):
                target = _inside(posixpath.join(posixpath.dirname(current), parent))
                if target is not None:
                    following = target if target.endswith(".json") else target + ".json"
            current = following
        return found

    # -- workspace packages --

    def _package_bases(self, spec: str) -> list[str]:
        best: tuple[str, str, str | None] | None = None
        for name, directory, main in self._load_packages():
            if (spec == name or spec.startswith(name + "/")) and (best is None or len(name) > len(best[0])):
                best = (name, directory, main)
        if best is None:
            return []
        name, directory, main = best
        sub = spec[len(name) + 1 :]
        join = lambda *parts: _inside(posixpath.join(*parts))  # noqa: E731
        if sub:
            candidates = [join(directory, sub), join(directory, "src", sub)]
        else:
            candidates = [join(directory, main) if main else None, join(directory, "src", "index"), directory or None]
            if main:
                # `main` usually names build output; its source lives under src/.
                candidates.insert(1, join(directory, "src", posixpath.basename(_STRIP_EXT.sub("", main))))
        return [c for c in candidates if c]

    def _load_packages(self) -> list[tuple[str, str, str | None]]:
        if self._packages is not None:
            return self._packages
        self._packages = []
        assert self.root is not None
        for count, path in enumerate(iter_repo_files(self.root, names={"package.json"}, skip_dirs=SKIP_DIRS)):
            if count >= _MAX_CONFIGS:
                break
            data = load_jsonc(read_source(path, root=self.root) or "")
            if not isinstance(data, dict) or not isinstance(data.get("name"), str) or not data["name"]:
                continue
            main = data.get("main") if isinstance(data.get("main"), str) else None
            directory = posixpath.dirname(rel(path, self.root))
            self._packages.append((data["name"], directory, _STRIP_EXT.sub("", main) if main else None))
        return self._packages
