from __future__ import annotations

import json
import subprocess
import sys

import pytest

from observability.aws.grafana.generate_public_dashboards import (
    generate_public_dashboards,
)
from scripts.verify_observability_configs import (
    PUBLIC_SHARES,
    ROOT,
    _read,
    verify_static_contract,
)


def test_static_observability_config_contract() -> None:
    verify_static_contract()


def test_observability_verifier_runs_directly_from_repository_root() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_observability_configs.py"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "AWS observability config-image contract verified" in result.stdout


def test_viewer_has_only_allowlisted_public_share_tokens() -> None:
    config = _read("observability/aws/viewer/default.conf.template")

    assert len(PUBLIC_SHARES) == 5
    assert len(set(PUBLIC_SHARES.values())) == 5
    assert "/api/ds/query" not in config
    assert "location = /otlp/v1/traces" in config
    assert "location = /otlp/v1/metrics" not in config


def test_public_persona_dashboards_are_fixed_and_variable_free(tmp_path) -> None:
    generated = generate_public_dashboards(
        ROOT / "observability" / "shared" / "dashboards",
        tmp_path / "public",
    )
    assert len(generated) == 5
    combined = "\n".join(path.read_text(encoding="utf-8") for path in generated)
    assert "$persona" not in combined
    assert '"templating": {\n    "list": []' in combined
    assert set(PUBLIC_SHARES) == {
        json.loads(path.read_text(encoding="utf-8"))["uid"] for path in generated
    }


def test_collector_and_jaeger_use_unique_task_local_ports() -> None:
    collector = _read("observability/aws/collector/config.yaml")
    trace = _read("observability/aws/trace/config.yaml")
    assert "endpoint: 127.0.0.1:4318" in collector
    assert "endpoint: http://127.0.0.1:14318" in collector
    assert "endpoint: 127.0.0.1:14318" in trace
    assert "endpoint: 127.0.0.1:13134" in trace
    assert "endpoint: 127.0.0.1:4318" not in trace
    assert "endpoint: 127.0.0.1:13133" not in trace
    assert "metrics:\n      level: none" in trace


def test_viewer_allows_only_the_branded_site_to_embed() -> None:
    config = _read("observability/aws/viewer/default.conf.template")

    assert (
        "frame-ancestors https://gluevenir.obsidiantek.io "
        "https://production.d2v1tx01e3zvx8.amplifyapp.com"
    ) in config
    assert "frame-ancestors 'none'" not in config
    assert "X-Frame-Options" not in config


def test_viewer_allows_grafana_same_origin_base_and_only_root_assets() -> None:
    config = _read("observability/aws/viewer/default.conf.template")

    assert "base-uri 'self'" in config
    assert "base-uri 'none'" not in config
    assert (
        'location ~ "^/public/(build|fonts|img)/[A-Za-z0-9_./@-]{1,384}$"'
    ) in config
    assert 'location ~ "^/grafana/public/(build|fonts|img)/' not in config


def test_browser_policies_support_grafana_panels_and_jaeger_bootstrap() -> None:
    config = _read("observability/aws/viewer/default.conf.template")
    server_policy = config.split("location = /healthz", maxsplit=1)[0]
    traces_policy = config.split("location ^~ /jaeger/", maxsplit=1)[1].split(
        "location = /otlp/v1/traces", maxsplit=1
    )[0]

    assert "script-src 'self' 'unsafe-eval' 'unsafe-inline' blob:;" in server_policy
    assert "style-src 'self' 'unsafe-inline' blob:;" in server_policy
    assert "worker-src 'self' blob:;" in server_policy
    assert "script-src 'self' 'unsafe-eval' 'unsafe-inline';" in traces_policy


def test_public_grafana_routes_are_exactly_token_scoped_at_root() -> None:
    config = _read("observability/aws/viewer/default.conf.template")

    assert 'location ~ "^/public-dashboards/(' in config
    assert 'location ~ "^/api/public/dashboards/(' in config
    assert "/public-dashboards/*" not in config
    assert "/grafana/public-dashboards/" not in config
    assert "/bootdata/" not in config
    for token in PUBLIC_SHARES.values():
        assert token in config
    assert "/annotations$" in config
    assert 'location ~ "^/api/public/dashboards/.*/annotations' not in config


def test_public_grafana_annotation_refresh_is_read_only_and_token_scoped() -> None:
    config = _read("observability/aws/viewer/default.conf.template")
    annotation_route = config.split(
        "# Grafana 11.6 refreshes this endpoint", maxsplit=1
    )[1].split("# Grafana's public-dashboard API executes", maxsplit=1)[0]

    assert ')/annotations$"' in annotation_route
    assert "limit_except GET HEAD { deny all; }" in annotation_route
    assert "proxy_pass http://127.0.0.1:3000;" in annotation_route
    assert "/panels/" not in annotation_route


def test_jaeger_uses_a_non_conflicting_public_base_path() -> None:
    viewer = _read("observability/aws/viewer/default.conf.template")
    trace = _read("observability/aws/trace/config.yaml")

    assert "base_path: /jaeger" in trace
    assert "base_path: /traces" not in trace
    assert "location ^~ /jaeger/" in viewer
    assert "return 308 /jaeger/;" in viewer


def test_grafana_organization_anonymous_access_is_disabled() -> None:
    config = _read("observability/aws/grafana/grafana.ini")

    assert "[auth.anonymous]\nenabled = false" in config
    assert "allow_embedding = true" in config
    assert "root_url = %(protocol)s://%(domain)s/" in config
    assert "serve_from_sub_path = false" in config


def test_grafana_public_share_probe_uses_the_exact_api_route() -> None:
    start = _read("observability/aws/grafana/start.sh")

    assert '"${endpoint}/"; then' in start
    assert '--post-data="$payload"' in start
    assert start.count('"${endpoint}/"') == 2
    assert '"$endpoint"; then' not in start


@pytest.mark.parametrize(
    "image", ["viewer", "collector", "metrics", "grafana", "trace"]
)
def test_every_image_has_shell_and_wget_smoke_contract(image: str) -> None:
    dockerfile = _read(f"observability/aws/{image}/Dockerfile")

    if image in {"collector", "trace"}:
        assert "FROM alpine:3.21.3" in dockerfile
    else:
        assert any(
            base in dockerfile
            for base in ("alpine", "prom/prometheus", "grafana/grafana")
        )
