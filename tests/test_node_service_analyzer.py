from pathlib import Path

from attackmap_analyzer_node_service import NodeServiceAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


def test_metadata_contains_required_fields() -> None:
    analyzer = NodeServiceAnalyzer()
    metadata = analyzer.metadata

    assert metadata.name == "node-service"
    assert metadata.display_name == "Node Service Analyzer"
    assert metadata.version == "0.1.0"
    assert metadata.description
    assert metadata.scope
    assert "node-service" in metadata.targets
    assert "typescript" in metadata.languages


def test_detect_identifies_node_service_repo() -> None:
    analyzer = NodeServiceAnalyzer()
    assert analyzer.detect(FIXTURES / "node_service_repo") is True


def test_analyze_extracts_service_signals_and_edges() -> None:
    analyzer = NodeServiceAnalyzer()
    result = analyzer.analyze(FIXTURES / "node_service_repo")

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
    assert "service_role:worker" in auth_hints
    assert "entrypoint:express_listen" in auth_hints
    assert "edge:api->worker" in auth_hints
    assert "edge:api->feedgen" in auth_hints

    assert "https://worker.internal.local/rebuild" in external_targets
    assert "env://FEEDGEN_URL" in external_targets

    assert "postgresql" in databases
    assert "redis" in databases
    assert "JWT_SIGNING_KEY" in secret_names


def test_analyze_returns_core_compatible_scan_shape() -> None:
    analyzer = NodeServiceAnalyzer()
    result = analyzer.analyze(FIXTURES / "node_service_repo")

    assert isinstance(result.root, str)
    assert isinstance(result.files_scanned, int)
    assert isinstance(result.languages, list)
    assert hasattr(result, "routes")
    assert hasattr(result, "external_calls")
    assert hasattr(result, "databases")
    assert hasattr(result, "auth_hints")
    assert hasattr(result, "secret_hints")
