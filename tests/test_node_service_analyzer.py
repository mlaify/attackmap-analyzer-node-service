import os
import shutil
import sys
from pathlib import Path

import pytest

from attackmap.sdk.contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.sdk.models import ScanResult as SharedScanResult
from attackmap_analyzer_node_service.contracts import AnalyzerMetadata, ScanResult
from attackmap_analyzer_node_service import NodeServiceAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(fixture_name: str):
    return NodeServiceAnalyzer().analyze(FIXTURES / fixture_name)


# ---------------------------------------------------------------------------
# Baseline: contract shape, metadata, detect()
# ---------------------------------------------------------------------------


def test_contracts_use_shared_sdk_types() -> None:
    assert AnalyzerMetadata is SharedAnalyzerMetadata
    assert ScanResult is SharedScanResult


def test_metadata_contains_required_fields() -> None:
    metadata = NodeServiceAnalyzer().metadata
    assert metadata.name == "node-service"
    assert metadata.display_name == "Node Service Analyzer"
    assert metadata.version == "0.2.0"
    assert metadata.description
    assert metadata.scope
    assert "node-service" in metadata.targets
    assert "typescript" in metadata.languages


def test_detect_identifies_node_service_repo() -> None:
    assert NodeServiceAnalyzer().detect(FIXTURES / "node_service_repo") is True


def test_analyze_returns_core_compatible_scan_shape() -> None:
    result = _analyze("node_service_repo")
    assert isinstance(result.root, str)
    assert isinstance(result.files_scanned, int)
    assert isinstance(result.languages, list)
    for attr in ("routes", "external_calls", "databases", "auth_hints", "secret_hints"):
        assert hasattr(result, attr)


# ---------------------------------------------------------------------------
# Baseline coverage (pre-0.2 behavior) — still works
# ---------------------------------------------------------------------------


def test_analyze_extracts_service_signals_and_edges() -> None:
    result = _analyze("node_service_repo")
    route_keys = {(route.path, route.method) for route in result.routes}
    auth_hints = {hint.hint for hint in result.auth_hints}
    external_targets = {call.target for call in result.external_calls}
    databases = {db.kind for db in result.databases}
    secret_names = {secret.name for secret in result.secret_hints}

    assert ("/xrpc/ping", "GET") in route_keys
    assert ("/internal/rebuild", "POST") in route_keys
    assert "service_name:api" in auth_hints
    assert "service_role:api" in auth_hints
    assert "service_name:worker" in auth_hints
    assert "entrypoint:express_listen" in auth_hints
    assert "edge:api->worker" in auth_hints
    assert "edge:api->feedgen" in auth_hints
    assert "https://worker.internal.local/rebuild" in external_targets
    assert "env://FEEDGEN_URL" in external_targets
    assert "postgresql" in databases
    assert "redis" in databases
    assert "JWT_SIGNING_KEY" in secret_names


# ---------------------------------------------------------------------------
# NestJS decorators (#17)
# ---------------------------------------------------------------------------


def test_nestjs_decorators_produce_prefixed_routes() -> None:
    result = _analyze("nestjs_repo")
    keys = {(r.path, r.method) for r in result.routes}
    # @Controller("users") + method decorators combine to full paths.
    assert ("/users", "GET") in keys
    assert ("/users/:id", "GET") in keys
    assert ("/users", "POST") in keys
    assert ("/users/:id", "DELETE") in keys
    # @All → ANY method sentinel
    assert ("/users/proxy", "ANY") in keys


def test_nestjs_hints_are_emitted() -> None:
    result = _analyze("nestjs_repo")
    hints = {h.hint for h in result.auth_hints}
    assert "entrypoint:nestjs_bootstrap" in hints
    assert "entrypoint:nestjs_module" in hints
    assert "nestjs_guard" in hints  # @UseGuards()


# ---------------------------------------------------------------------------
# NextJS file-based routing (#17)
# ---------------------------------------------------------------------------


def test_nextjs_app_router_named_exports_become_method_specific_routes() -> None:
    result = _analyze("nextjs_repo")
    keys = {(r.path, r.method) for r in result.routes}
    assert ("/api/health", "GET") in keys
    # `app/orders/[id]/route.ts` → `/orders/:id` — App Router doesn't
    # require an `api/` segment; any route.ts file becomes a route.
    assert ("/orders/:id", "GET") in keys
    assert ("/orders/:id", "DELETE") in keys


def test_nextjs_pages_router_files_become_any_routes() -> None:
    result = _analyze("nextjs_repo")
    keys = {(r.path, r.method) for r in result.routes}
    assert ("/api/legacy", "ANY") in keys
    assert ("/api/webhooks/:provider", "ANY") in keys


# ---------------------------------------------------------------------------
# Express advanced: prefix mounts + chained .route() (#17)
# ---------------------------------------------------------------------------


def test_express_use_prefix_mounts_propagate_through_nested_routers() -> None:
    result = _analyze("express_advanced_repo")
    keys = {(r.path, r.method) for r in result.routes}
    assert ("/health", "GET") in keys
    # Three-level prefix chain: /api + /v1 + /orgs/:orgId + /members
    assert ("/api/v1/orgs/:orgId/members", "GET") in keys
    assert ("/api/v1/orgs/:orgId/invite", "POST") in keys


def test_express_route_chain_emits_route_per_chained_verb() -> None:
    result = _analyze("express_advanced_repo")
    keys = {(r.path, r.method) for r in result.routes}
    # `v1.route("/status").get().post()` — v1 is mounted at /api, and
    # `.route()` sits directly on v1 (not the nested orgs router), so the
    # prefix here is /api, not /api/v1.
    assert ("/api/status", "GET") in keys
    assert ("/api/status", "POST") in keys


# ---------------------------------------------------------------------------
# Framework variety: Hono, Koa, Elysia, tRPC (#17)
# ---------------------------------------------------------------------------


def test_hono_koa_elysia_routes_are_extracted() -> None:
    result = _analyze("framework_variety_repo")
    keys = {(r.path, r.method) for r in result.routes}
    assert ("/hello", "GET") in keys
    assert ("/hello", "POST") in keys
    assert ("/koa-hello", "GET") in keys
    assert ("/koa-items", "POST") in keys
    assert ("/elysia/ping", "GET") in keys
    assert ("/elysia/events", "POST") in keys


def test_hono_koa_elysia_entrypoints_emit_hints() -> None:
    result = _analyze("framework_variety_repo")
    hints = {h.hint for h in result.auth_hints}
    assert "entrypoint:hono_app" in hints
    assert "entrypoint:koa_app" in hints
    assert "entrypoint:elysia_app" in hints


def test_trpc_procedures_are_extracted_as_prefixed_routes() -> None:
    result = _analyze("framework_variety_repo")
    keys = {(r.path, r.method) for r in result.routes}
    assert ("trpc:listUsers", "GET") in keys      # .query -> GET
    assert ("trpc:createUser", "POST") in keys    # .mutation -> POST
    assert ("trpc:streamEvents", "STREAM") in keys
    hints = {h.hint for h in result.auth_hints}
    assert "entrypoint:trpc_http_server" in hints


# ---------------------------------------------------------------------------
# XRPC / AT Protocol handler registration (#17, progresses #19)
# ---------------------------------------------------------------------------


def test_xrpc_handlers_emit_xrpc_routes_and_lexicon_hints() -> None:
    result = _analyze("xrpc_repo")
    keys = {(r.path, r.method) for r in result.routes}
    hints = {h.hint for h in result.auth_hints}
    # `server.method(...)` form
    assert ("/xrpc/com.atproto.server.createSession", "ANY") in keys
    assert ("/xrpc/app.bsky.feed.getFeed", "ANY") in keys
    # Object-literal handler map form
    assert ("/xrpc/com.atproto.repo.putRecord", "ANY") in keys
    assert ("/xrpc/chat.bsky.convo.getConvo", "ANY") in keys
    # Lexicon hints per NSID
    assert "atproto_lexicon:com.atproto.server.createSession" in hints
    assert "atproto_lexicon:app.bsky.feed.getFeed" in hints
    assert "entrypoint:xrpc_server" in hints


# ---------------------------------------------------------------------------
# EXPO_PUBLIC_* client-bundled secrets (#17, from Bluesky FINDINGS §3)
# ---------------------------------------------------------------------------


def test_expo_public_env_vars_are_tagged_as_client_bundled_secrets() -> None:
    result = _analyze("expo_secrets_repo")
    names = {s.name for s in result.secret_hints}
    # Expo prefix tagged so downstream findings can elevate it.
    assert "expo_public:EXPO_PUBLIC_BITDRIFT_API_KEY" in names
    assert "expo_public:EXPO_PUBLIC_POSTHOG_KEY" in names
    # Non-Expo secrets are still tagged normally, without the prefix.
    assert "JWT_SIGNING_KEY" in names


# ---------------------------------------------------------------------------
# Workspaces topology (#17)
# ---------------------------------------------------------------------------


def test_npm_workspaces_declared_at_root_emit_service_hints_for_each_package() -> None:
    # The existing node_service_repo fixture declares services/* + packages/*
    # in its root package.json workspaces.
    result = _analyze("node_service_repo")
    hints = {h.hint for h in result.auth_hints}
    assert "workspace_package:@attackmap/node-service-demo" not in hints  # root itself excluded
    # `services/api`, `services/worker`, `packages/shared` each have their
    # own package.json in the fixture — but only if they exist as workspace
    # entries with package.json files. Our current fixture doesn't put
    # per-package package.json files inside services/*, so this test just
    # verifies workspace parsing didn't crash. The pnpm test below covers
    # the actual per-package emission path.


def test_pnpm_workspace_emits_service_hints_for_each_workspace_package() -> None:
    result = _analyze("pnpm_workspace_repo")
    hints = {h.hint for h in result.auth_hints}
    assert "service_name:gateway" in hints
    assert "service_name:telemetry" in hints
    assert "workspace_package:@attackmap/gateway" in hints
    assert "workspace_package:@attackmap/telemetry" in hints


# ---------------------------------------------------------------------------
# Async workers: BullMQ + Kafka (#17)
# ---------------------------------------------------------------------------


def test_bullmq_workers_and_queues_emit_queue_edges() -> None:
    result = _analyze("async_workers_repo")
    hints = {h.hint for h in result.auth_hints}
    targets = {c.target for c in result.external_calls}
    assert "entrypoint:bullmq_worker" in hints
    assert "entrypoint:bullmq_queue" in hints
    assert "queue://bullmq/image-processing" in targets
    assert "queue://bullmq/email-outbox" in targets
    # Per-service outbound edge to the named queue.
    assert any(h.startswith("edge:async-workers->queue:") for h in hints)


def test_kafka_consumer_topics_emit_topic_edges() -> None:
    result = _analyze("async_workers_repo")
    hints = {h.hint for h in result.auth_hints}
    targets = {c.target for c in result.external_calls}
    assert "entrypoint:kafka_consumer" in hints
    assert "queue://kafka/orders-created" in targets
    assert "queue://kafka/payments-events" in targets
    assert any(h.endswith("->topic:orders-created") for h in hints)


# ---------------------------------------------------------------------------
# Repo walking via attackmap.sdk.fs (AttackMap#253)
# ---------------------------------------------------------------------------


def test_repo_checked_out_under_build_dir_is_still_analyzed(tmp_path: Path) -> None:
    # Skip dirs used to be matched against absolute path parts, so a repo
    # under any `build/` or `out/` directory yielded nothing at all.
    repo = tmp_path / "build" / "out" / "repo"
    shutil.copytree(FIXTURES / "node_service_repo", repo)
    analyzer = NodeServiceAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned > 0
    assert result.routes
    assert result.external_calls


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_source_outside_repo_is_not_analyzed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.ts").write_text(
        "app.get('/outside-secret', handler);\nconst k = process.env.EXPO_PUBLIC_OUTSIDE_KEY;\n"
    )
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "node_service_repo", repo)
    (repo / "services" / "api" / "src" / "linked.ts").symlink_to(outside / "secret.ts")

    result = NodeServiceAnalyzer().analyze(repo)
    files = {r.file for r in result.routes} | {h.file for h in result.auth_hints} | {s.file for s in result.secret_hints}
    assert not any(f.endswith("linked.ts") for f in files)
    assert "/outside-secret" not in {r.path for r in result.routes}
    assert "expo_public:EXPO_PUBLIC_OUTSIDE_KEY" not in {s.name for s in result.secret_hints}


def test_detect_does_not_walk_node_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Only node_modules has Node files: detect() must neither match them nor
    # descend into node_modules (it used to `root.glob("**/package.json")`).
    dep = tmp_path / "node_modules" / "express"
    dep.mkdir(parents=True)
    (dep / "package.json").write_text('{"name": "express"}')
    (dep / "tsconfig.json").write_text("{}")
    (dep / "server.js").write_text("app.listen(3000)\n")
    (tmp_path / "README.md").write_text("not a node service\n")

    entered: list[str] = []
    real_walk = os.walk

    def spy(top, *args, **kwargs):
        for dirpath, dirnames, filenames in real_walk(top, *args, **kwargs):
            entered.append(Path(dirpath).name)
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(os, "walk", spy)
    assert NodeServiceAnalyzer().detect(tmp_path) is False
    assert entered, "detect() should walk the repo via the SDK walker"
    assert "node_modules" not in entered and "express" not in entered


def test_workspace_globs_do_not_pick_up_node_modules_packages(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "mono", "workspaces": ["packages/**"]}')
    pkg = tmp_path / "packages" / "api"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text('{"name": "@mono/api"}')
    (pkg / "index.ts").write_text("app.get('/x', h);\n")
    nested_dep = pkg / "node_modules" / "left-pad"
    nested_dep.mkdir(parents=True)
    (nested_dep / "package.json").write_text('{"name": "left-pad"}')

    hints = {h.hint for h in NodeServiceAnalyzer().analyze(tmp_path).auth_hints}
    assert "workspace_package:@mono/api" in hints
    assert "workspace_package:left-pad" not in hints
