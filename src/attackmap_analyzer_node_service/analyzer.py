from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .contracts import AnalyzerMetadata, AuthHint, DatabaseHint, ExternalCall, Route, ScanResult, SecretHint

CODE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".turbo"}

EXPRESS_ROUTE_PATTERN = re.compile(
    r"\b(?:app|router)\.(get|post|put|patch|delete|options|head)\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
FASTIFY_ROUTE_PATTERN = re.compile(
    r"\bfastify\.(get|post|put|patch|delete|options|head)\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
ENTRYPOINT_PATTERNS = [
    (re.compile(r"\bapp\.listen\s*\(", re.IGNORECASE), "entrypoint:express_listen"),
    (re.compile(r"\bcreateServer\s*\(", re.IGNORECASE), "entrypoint:create_server"),
    (re.compile(r"\bfastify\s*\(", re.IGNORECASE), "entrypoint:fastify_server"),
    (re.compile(r"\bnew\s+Hono\s*\(", re.IGNORECASE), "entrypoint:hono_app"),
    (re.compile(r"\bregisterHandler\b|\bregisterRoute\b", re.IGNORECASE), "entrypoint:handler_registration"),
]

OUTBOUND_PATTERNS = [
    re.compile(r"\bfetch\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\baxios\.(?:get|post|put|patch|delete)\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\bgot(?:\.(?:get|post|put|patch|delete))?\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\bundici\.(?:request|fetch)\(\s*['\"](https?://[^'\"]+)['\"]", re.IGNORECASE),
]
ENV_URL_PATTERN = re.compile(r"process\.env\.([A-Z0-9_]+_URL)\b")

DB_PATTERNS = [
    (re.compile(r"\bnew\s+PrismaClient\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bPool\s*\(\s*\{", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bpg\b|\bnode-postgres\b", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bknex\s*\(", re.IGNORECASE), "sql"),
    (re.compile(r"\bmongoose\.connect\s*\(", re.IGNORECASE), "mongodb"),
    (re.compile(r"\bMongoClient\s*\(", re.IGNORECASE), "mongodb"),
    (re.compile(r"\bredis\.createClient\s*\(", re.IGNORECASE), "redis"),
    (re.compile(r"\bioredis\b|\bnew\s+Redis\s*\(", re.IGNORECASE), "redis"),
    (re.compile(r"\bS3Client\b|\bPutObjectCommand\b|\bGetObjectCommand\b", re.IGNORECASE), "object_storage"),
]

AUTH_PATTERNS = [
    (re.compile(r"\bAuthorization\b", re.IGNORECASE), "authorization_header"),
    (re.compile(r"\bBearer\b", re.IGNORECASE), "bearer_token"),
    (re.compile(r"\bjwt\b|\bjsonwebtoken\b", re.IGNORECASE), "jwt"),
    (re.compile(r"\bverify\b\s*\(", re.IGNORECASE), "signature_verify"),
    (re.compile(r"\bsign\b\s*\(", re.IGNORECASE), "signature_sign"),
    (re.compile(r"\boauth\b|\boidc\b", re.IGNORECASE), "oauth"),
    (re.compile(r"\btoken\b", re.IGNORECASE), "token"),
]

SECRET_PATTERNS = [
    re.compile(r"process\.env\.([A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*)"),
]


class NodeServiceAnalyzer:
    metadata = AnalyzerMetadata(
        name="node-service",
        display_name="Node Service Analyzer",
        version="0.1.0",
        description="Broad Node.js/TypeScript service analyzer for distributed backend repositories.",
        scope="Node/TypeScript backend service repos with service boundaries, handler registration, and inter-service calls.",
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

        has_package = (root / "package.json").exists() or any(root.glob("**/package.json"))
        has_typescript = (root / "tsconfig.json").exists() or any(root.glob("**/tsconfig.json"))
        has_service_dirs = (root / "services").is_dir() or (root / "packages").is_dir()

        if has_package and (has_typescript or has_service_dirs):
            return True

        for file_path in root.rglob("*"):
            if not file_path.is_file() or file_path.suffix not in CODE_SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue
            content = self._read_text(file_path)
            if not content:
                continue
            if re.search(r"\bapp\.listen\b|\bfastify\b|\bcreateServer\b|\bservices?/|packages?/", content, re.IGNORECASE):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        root_package_name = self._package_name_from(root / "package.json")
        for file_path in root.rglob("*"):
            if not file_path.is_file() or file_path.suffix not in CODE_SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue

            result.files_scanned += 1
            language = "typescript" if file_path.suffix in {".ts", ".tsx"} else "javascript"
            if language not in result.languages:
                result.languages.append(language)

            content = self._read_text(file_path)
            if content is None:
                continue

            relative = str(file_path.relative_to(root))
            service_name = self._infer_service_name(relative, root_package_name)
            service_role = self._infer_service_role(service_name, relative)

            self._append_unique_auth(result, f"service_name:{service_name}", relative)
            self._append_unique_auth(result, f"service_role:{service_role}", relative)

            self._extract_routes(content, relative, result)
            self._extract_entrypoint_hints(content, relative, result)
            self._extract_outbound_and_edges(content, relative, service_name, result)
            self._extract_datastore_hints(content, relative, result)
            self._extract_auth_hints(content, relative, result)
            self._extract_secret_hints(content, relative, result)

        result.languages.sort()
        return result

    def _extract_routes(self, content: str, relative: str, result: ScanResult) -> None:
        for match in EXPRESS_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            self._append_unique_route(result, path, method, relative)
        for match in FASTIFY_ROUTE_PATTERN.finditer(content):
            method, path = match.group(1).upper(), match.group(2)
            self._append_unique_route(result, path, method, relative)

    def _extract_entrypoint_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in ENTRYPOINT_PATTERNS:
            if pattern.search(content):
                self._append_unique_auth(result, hint, relative)

    def _extract_outbound_and_edges(self, content: str, relative: str, service_name: str, result: ScanResult) -> None:
        for pattern in OUTBOUND_PATTERNS:
            for match in pattern.finditer(content):
                target = match.group(1)
                self._append_unique_external(result, target, relative)
                target_service = self._service_from_url(target)
                if target_service:
                    self._append_unique_auth(result, f"edge:{service_name}->{target_service}", relative)

        for match in ENV_URL_PATTERN.finditer(content):
            env_name = match.group(1)
            self._append_unique_external(result, f"env://{env_name}", relative)
            target_service = self._service_from_env_name(env_name)
            if target_service:
                self._append_unique_auth(result, f"edge:{service_name}->{target_service}", relative)

    def _extract_datastore_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, kind in DB_PATTERNS:
            if pattern.search(content):
                self._append_unique_database(result, kind, relative)

    def _extract_auth_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern, hint in AUTH_PATTERNS:
            if pattern.search(content):
                self._append_unique_auth(result, hint, relative)

    def _extract_secret_hints(self, content: str, relative: str, result: ScanResult) -> None:
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                self._append_unique_secret(result, match.group(1), relative)

    def _infer_service_name(self, relative: str, root_package_name: str | None) -> str:
        normalized = relative.replace("\\", "/")
        parts = normalized.split("/")
        if len(parts) >= 2 and parts[0] in {"services", "packages"}:
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
    def _package_name_from(path: Path) -> str | None:
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        name = data.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        return None

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file))
