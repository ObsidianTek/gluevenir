from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    ROOT / "compose.yaml",
    ROOT / "compose.ephemeral.yaml",
    ROOT / "compose.hybrid.yaml",
    ROOT / "compose.cloud.yaml",
)
OBSERVABILITY_COMPOSE_FILES = COMPOSE_FILES[:3]
OBSERVABILITY_ROOT = ROOT / "observability" / "local"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_all_modes_are_explicit_loopback_bound_and_exactly_pinned() -> None:
    combined = "\n".join(_source(path) for path in COMPOSE_FILES)
    assert "cockroachdb/cockroach:v26.2.5" in _source(ROOT / "compose.yaml")
    assert "cockroachdb/cockroach:v26.2.5" in _source(ROOT / "compose.ephemeral.yaml")
    assert "cockroachdb/cockroach:" not in _source(ROOT / "compose.hybrid.yaml")
    assert "cockroachdb/cockroach:" not in _source(ROOT / "compose.cloud.yaml")
    assert ":latest" not in combined
    published_ports = re.findall(r'^\s+- "([^" ]+:\d+:\d+)"$', combined, re.MULTILINE)
    assert published_ports
    assert all(value.startswith("127.0.0.1:") for value in published_ports)


def test_secrets_are_ignored_file_mounts_not_environment_values() -> None:
    local = _source(ROOT / "compose.yaml")
    hybrid = _source(ROOT / "compose.hybrid.yaml")
    cloud = _source(ROOT / "compose.cloud.yaml")
    env_example = _source(ROOT / ".env.example")
    combined = local + hybrid + cloud + env_example

    assert ".private/compose/bedrock_api_key" in local
    assert ".private/compose/cockroach_runtime_url" in hybrid
    assert "GLUEVENIR_BEDROCK_TOKEN_FILE: /run/secrets/bedrock_api_key" in local
    assert "GLUEVENIR_DATABASE_URL_FILE: /run/secrets/cockroach_runtime_url" in hybrid
    assert "AWS_ACCESS_KEY_ID" not in combined
    assert "AWS_SECRET_ACCESS_KEY" not in combined
    assert "/.aws" not in combined
    assert ".secrets/" not in combined
    assert "secrets:" not in cloud

    for path in (
        ".private/compose/bedrock_api_key",
        ".private/compose/cockroach_runtime_url",
    ):
        ignored = subprocess.run(
            ["git", "check-ignore", "--quiet", path],
            cwd=ROOT,
            check=False,
            timeout=5,
        )
        assert ignored.returncode == 0


def test_local_bootstrap_health_and_storage_contracts_are_ordered() -> None:
    local = _source(ROOT / "compose.yaml")
    ephemeral = _source(ROOT / "compose.ephemeral.yaml")
    hybrid = _source(ROOT / "compose.hybrid.yaml")

    assert "condition: service_healthy" in local
    assert "condition: service_completed_successfully" in local
    assert "scripts.bootstrap_local" in local
    assert "scripts/verify_local_stack.py" in local
    assert "cockroach-data:/cockroach/cockroach-data" in local
    assert "signing-data:/run/gluevenir-signing" in local
    assert "/cockroach/cockroach-data:size=1g" in ephemeral
    assert "/run/gluevenir-signing:size=1m" in ephemeral
    assert "--generate-signing-key" in ephemeral
    assert "GLUEVENIR_DATABASE_URL_FILE" in hybrid
    assert '--mode", "hybrid' in hybrid


def test_cloud_aligned_mode_models_external_dependencies_without_deploying() -> None:
    cloud = _source(ROOT / "compose.cloud.yaml")
    assert 'io.gluevenir.external.aws-runtime: "required-not-deployed"' in cloud
    assert 'io.gluevenir.external.cockroachdb-cloud: "required-not-deployed"' in cloud
    assert "GLUEVENIR_CLOUD_API_URL" in cloud
    assert "GLUEVENIR_CLOUD_SITE_URL" in cloud
    assert "cockroach_runtime_url" not in cloud
    assert "bedrock_api_key" not in cloud


def test_local_observability_services_are_pinned_and_task_internal() -> None:
    expected_images = {
        "otel/opentelemetry-collector-contrib:0.123.0",
        "prom/prometheus:v3.2.1",
        "jaegertracing/all-in-one:1.66.0",
        "grafana/grafana-oss:11.6.0",
    }
    for compose_file in OBSERVABILITY_COMPOSE_FILES:
        source = _source(compose_file)
        for image in expected_images:
            assert f"image: {image}" in source
        assert (
            "GLUEVENIR_OTLP_TRACES_ENDPOINT: http://collector:4318/v1/traces" in source
        )
        assert "127.0.0.1:16686:16686" in source or "127.0.0.1:17686:16686" in source
        assert "127.0.0.1:3000:3000" in source or "127.0.0.1:13000:3000" in source
        assert re.search(r'^\s+- "(?:9090|4318):', source, re.MULTILINE) is None
        assert "condition: service_completed_successfully" in source
        assert "wait_for_stack.py" in source
        assert "--jaeger-url" in source
        assert "http://jaeger:16686" in source
        assert "--prometheus-url" in source
        assert "http://prometheus:9090" in source
        assert 'GF_SECURITY_ALLOW_EMBEDDING: "true"' in source


def test_ephemeral_observability_storage_is_memory_backed() -> None:
    ephemeral = _source(ROOT / "compose.ephemeral.yaml")
    assert "/prometheus:size=256m,uid=65534,gid=65534,mode=0755" in ephemeral
    assert "/var/lib/grafana:size=128m" in ephemeral
    assert "prometheus-data:/prometheus" not in ephemeral
    assert "grafana-data:/var/lib/grafana" not in ephemeral


def test_collector_projects_only_bounded_spanmetrics() -> None:
    collector = _source(OBSERVABILITY_ROOT / "otel-collector.yaml")
    assert "receivers: [otlp]" in collector
    assert "exporters: [otlphttp/jaeger, spanmetrics]" in collector
    assert "receivers: [spanmetrics]" in collector
    assert "exporters: [prometheus]" in collector
    for safe_dimension in (
        "gluevenir.candidate_count",
        "gluevenir.decision",
        "gluevenir.excluded_count",
        "gluevenir.included_count",
        "gluevenir.model_invoked",
        "gluevenir.operation",
        "gluevenir.persona",
        "gluevenir.reason_code",
        "gluevenir.receipt_verified",
        "gluevenir.status",
    ):
        assert f"name: {safe_dimension}" in collector
    for prohibited in (
        "prompt",
        "answer",
        "memory_id",
        "tenant_id",
        "program_id",
        "credential",
        "detector_match",
    ):
        assert prohibited not in collector


def test_grafana_is_anonymous_viewer_with_provisioned_internal_sources() -> None:
    local = _source(ROOT / "compose.yaml")
    datasources = _source(
        OBSERVABILITY_ROOT
        / "grafana"
        / "provisioning"
        / "datasources"
        / "datasources.yaml"
    )
    dashboards = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(
            (ROOT / "observability" / "shared" / "dashboards").glob("*.json")
        )
    ]
    assert 'GF_AUTH_ANONYMOUS_ENABLED: "true"' in local
    assert "GF_AUTH_ANONYMOUS_ORG_ROLE: Viewer" in local
    assert 'GF_AUTH_DISABLE_LOGIN_FORM: "true"' in local
    for compose_file in OBSERVABILITY_COMPOSE_FILES:
        compose = _source(compose_file)
        assert (
            "./observability/shared/dashboards:/var/lib/grafana/dashboards:ro"
            in compose
        )
        assert "observability/local/grafana/dashboards" not in compose
    assert "url: http://prometheus:9090" in datasources
    assert "url: http://jaeger:16686" in datasources
    assert {dashboard["uid"] for dashboard in dashboards} == {
        "gluevenir-local-telemetry",
        "gluevenir-persona-governance",
    }
    assert all(
        "synthetic-telemetry-only" in dashboard["tags"] for dashboard in dashboards
    )
    dashboard = next(
        item for item in dashboards if item["uid"] == "gluevenir-local-telemetry"
    )
    outcome_panel = next(
        panel
        for panel in dashboard["panels"]
        if panel.get("title") == "Five-outcome distribution"
    )
    outcome_query = outcome_panel["targets"][0]["expr"]
    assert 'span_name="gluevenir.gateway.evaluation"' in outcome_query
    assert "gluevenir_decision" in outcome_query


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is unavailable")
@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_docker_compose_configuration_validates_offline(
    compose_file: Path,
    tmp_path: Path,
) -> None:
    token = tmp_path / "bedrock-token"
    database_url = tmp_path / "database-url"
    token.write_text("test-only-token", encoding="utf-8")
    test_url = "postgresql://gluevenir_runtime" + ":test@cluster.example:26257/"
    database_url.write_text(
        f"{test_url}gluevenir?sslmode=verify-full",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "GLUEVENIR_BEDROCK_GUARDRAIL_ID": "test-guardrail",
            "GLUEVENIR_BEDROCK_TOKEN_FILE": str(token),
            "GLUEVENIR_COCKROACH_URL_FILE": str(database_url),
            "GLUEVENIR_CLOUD_API_URL": "https://api.example/v1/demo",
            "GLUEVENIR_CLOUD_SITE_URL": "https://site.example/",
        }
    )
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "config", "--quiet"],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
