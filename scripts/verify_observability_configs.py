#!/usr/bin/env python3
"""Verify the bounded AWS observability configuration-image contract."""

from __future__ import annotations

import argparse
import configparser
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from observability.aws.grafana.generate_public_dashboards import (  # noqa: E402
    OVERVIEW_TOKEN,
    OVERVIEW_UID,
    PUBLIC_PERSONAS,
    generate_public_dashboards,
)

AWS_ROOT = ROOT / "observability" / "aws"
PUBLIC_SHARES = {
    OVERVIEW_UID: OVERVIEW_TOKEN,
    **{uid: token for _persona_id, _display_name, uid, token in PUBLIC_PERSONAS},
}
IMAGE_NAMES = ("viewer", "collector", "metrics", "grafana", "trace")
PINNED_BASES = {
    "viewer": "nginxinc/nginx-unprivileged:1.27.4-alpine3.21",
    "collector": "otel/opentelemetry-collector-contrib:0.123.0",
    "metrics": "prom/prometheus:v3.2.1",
    "grafana": "grafana/grafana-oss:11.6.0",
    "trace": "jaegertracing/jaeger:2.20.0",
}


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_static_contract() -> None:
    """Parse configs and fail when the bounded topology drifts."""

    for name in IMAGE_NAMES:
        dockerfile = _read(f"observability/aws/{name}/Dockerfile")
        _require("latest" not in dockerfile.lower(), f"{name} image is unpinned")
        _require(PINNED_BASES[name] in dockerfile, f"{name} base image drifted")
    _require(
        "python:3.12.11-alpine3.21" in _read("observability/aws/grafana/Dockerfile"),
        "dashboard generator image is unpinned",
    )

    viewer = _read("observability/aws/viewer/default.conf.template")
    _require(
        "map_hash_bucket_size 128;" in viewer,
        "viewer cannot safely map the production-length bearer token",
    )
    _require("client_max_body_size 64k;" in viewer, "OTLP body bound is missing")
    _require(
        '"Bearer ${GLUEVENIR_OTLP_BEARER_TOKEN}" 1;' in viewer,
        "OTLP bearer authentication is missing",
    )
    _require("location = /otlp/v1/traces" in viewer, "trace route is not exact")
    _require("/otlp/v1/metrics" not in viewer, "metrics ingestion must be rejected")
    _require("/api/ds/query" not in viewer, "arbitrary Grafana queries are exposed")
    _require("^/public-dashboards/(" in viewer, "Grafana share routes are missing")
    _require(
        "^/api/public/dashboards/(" in viewer,
        "Grafana public query routes are missing",
    )
    _require("/grafana/" not in viewer, "Grafana subpath routing is still enabled")
    _require("/bootdata/" not in viewer, "authenticated Grafana bootdata is exposed")
    _require(
        "script-src 'self' 'unsafe-eval' 'unsafe-inline' blob:;" in viewer
        and "style-src 'self' 'unsafe-inline' blob:;" in viewer
        and "worker-src 'self' blob:;" in viewer,
        "Grafana panel browser policy is incomplete",
    )
    _require(
        (
            "frame-ancestors https://gluevenir.obsidiantek.io "
            "https://production.d2v1tx01e3zvx8.amplifyapp.com"
        )
        in viewer,
        "viewer embed origin is not restricted to the branded site",
    )
    _require("X-Frame-Options" not in viewer, "legacy header blocks branded embed")
    _require("proxy_pass http://collector" not in viewer, "AWS config uses Compose DNS")
    upstreams = re.findall(r"proxy_pass\s+(http://[^;]+);", viewer)
    _require(bool(upstreams), "viewer has no task-local upstreams")
    _require(
        all(url.startswith("http://127.0.0.1:") for url in upstreams),
        "viewer upstream escaped the task-local network",
    )
    for token in PUBLIC_SHARES.values():
        _require(token in viewer, "viewer public-share allowlist drifted")
    _require(
        "panels/[0-9]{1,6}/query" in viewer and "client_max_body_size 16k;" in viewer,
        "stored public-panel query route is not bounded",
    )

    collector = yaml.safe_load(_read("observability/aws/collector/config.yaml"))
    _require(
        set(collector["service"]["pipelines"]) == {"traces", "metrics"},
        "unexpected telemetry pipeline",
    )
    trace_pipeline = collector["service"]["pipelines"]["traces"]
    _require(
        "filter/synthetic_only" in trace_pipeline["processors"],
        "synthetic filter missing",
    )
    _require(
        "transform/content_safe" in trace_pipeline["processors"],
        "content allowlist missing",
    )
    filter_config = collector["processors"]["filter/synthetic_only"]["traces"]
    _require(filter_config.get("spanevent") == ["true"], "span events are retained")
    transform_statements = collector["processors"]["transform/content_safe"][
        "trace_statements"
    ]
    _require(
        any(
            "set(links, [])" in statement
            for context in transform_statements
            for statement in context["statements"]
        ),
        "span links are retained",
    )
    filters = "\n".join(filter_config["span"])
    for bounded_domain in (
        "gluevenir-bio",
        "program_lead",
        "ALLOW|MODIFY|STEP_UP|DEFER|DENY",
        "INTERNAL_POLICY_ALLOW",
    ):
        _require(bounded_domain in filters, "telemetry value domain is unbounded")
    _require(
        set(collector["exporters"]) == {"otlphttp/jaeger", "prometheus"},
        "unexpected exporter",
    )
    _require(
        collector["receivers"]["otlp"]["protocols"]["http"]["endpoint"]
        == "127.0.0.1:4318",
        "collector receiver is not task-local",
    )
    _require(
        collector["exporters"]["otlphttp/jaeger"]["endpoint"]
        == "http://127.0.0.1:14318",
        "collector does not target the isolated Jaeger receiver",
    )
    dimensions = {
        item["name"] for item in collector["connectors"]["spanmetrics"]["dimensions"]
    }
    required_dimensions = {
        "gluevenir.candidate_count",
        "gluevenir.included_count",
        "gluevenir.excluded_count",
        "gluevenir.model_invoked",
    }
    _require(required_dimensions <= dimensions, "dashboard span dimensions are missing")

    prometheus = yaml.safe_load(_read("observability/aws/metrics/prometheus.yml"))
    targets = prometheus["scrape_configs"][0]["static_configs"][0]["targets"]
    _require(
        targets == ["127.0.0.1:8889"], "Prometheus scrape escaped task-local network"
    )
    prometheus_start = _read("observability/aws/metrics/start.sh")
    _require(
        "--no-web.enable-admin-api" in prometheus_start,
        "Prometheus admin API is enabled",
    )
    _require(
        "--no-web.enable-lifecycle" in prometheus_start,
        "Prometheus lifecycle API is enabled",
    )
    _require(
        "--web.listen-address=127.0.0.1:9090" in prometheus_start,
        "Prometheus is not task-local",
    )

    grafana = configparser.ConfigParser(interpolation=None)
    grafana.read_string(_read("observability/aws/grafana/grafana.ini"))
    _require(
        not grafana.getboolean("auth.anonymous", "enabled"),
        "Grafana organization-anonymous access is enabled",
    )
    _require(
        grafana.get("auth.anonymous", "org_role") == "Viewer",
        "anonymous role is not Viewer",
    )
    _require(grafana.getboolean("auth", "disable_login_form"), "login form is exposed")
    _require(not grafana.getboolean("explore", "enabled"), "Grafana Explore is enabled")
    _require(
        not grafana.getboolean("feature_toggles", "publicDashboardsScene"),
        "Grafana public dashboard scene renderer is enabled",
    )
    _require(
        not grafana.getboolean("analytics", "reporting_enabled"),
        "Grafana telemetry is enabled",
    )
    _require(
        grafana.getboolean("security", "allow_embedding"),
        "Grafana would emit a framing-denial header behind the bounded viewer",
    )
    _require(
        grafana.get("server", "http_addr") == "127.0.0.1", "Grafana is not task-local"
    )
    _require(
        grafana.get("server", "root_url") == "%(protocol)s://%(domain)s/",
        "Grafana is not rooted at the dedicated observability origin",
    )
    _require(
        not grafana.getboolean("server", "serve_from_sub_path"),
        "Grafana subpath routing is enabled",
    )
    datasources = yaml.safe_load(
        _read("observability/aws/grafana/provisioning/datasources/gluevenir.yaml")
    )
    _require(
        all(
            source["url"].startswith("http://127.0.0.1:")
            for source in datasources["datasources"]
        ),
        "Grafana datasource escaped task-local network",
    )
    bootstrap = _read("observability/aws/grafana/start.sh")
    for uid, token in PUBLIC_SHARES.items():
        _require(
            uid in bootstrap and token in bootstrap,
            "public-dashboard bootstrap drifted",
        )
    _require(
        "/proc/sys/kernel/random/uuid" in bootstrap,
        "admin bootstrap credential is not ephemeral",
    )

    dashboards = ROOT / "observability" / "shared" / "dashboards"
    with tempfile.TemporaryDirectory() as temporary_directory:
        generated_directory = Path(temporary_directory) / "public"
        generated = generate_public_dashboards(dashboards, generated_directory)
        documents = [json.loads(path.read_text(encoding="utf-8")) for path in generated]
    _require(
        {document["uid"] for document in documents} == set(PUBLIC_SHARES),
        "public dashboard UID set drifted",
    )
    _require(
        all("$persona" not in json.dumps(document) for document in documents),
        "public dashboard retains an unsupported variable",
    )
    _require(
        all(document["templating"] == {"list": []} for document in documents),
        "public dashboard templating is not disabled",
    )

    trace_start = _read("observability/aws/trace/start.sh")
    trace_config = yaml.safe_load(_read("observability/aws/trace/config.yaml"))
    _require(
        trace_config["receivers"]["otlp"]["protocols"]["http"]["endpoint"]
        == "127.0.0.1:14318",
        "Jaeger OTLP receiver is not task-local",
    )
    _require(
        trace_config["extensions"]["healthcheckv2"]["http"]["endpoint"]
        == "127.0.0.1:13134",
        "Jaeger health endpoint conflicts with the Collector",
    )
    _require(
        trace_config["extensions"]["jaeger_query"]["base_path"] == "/jaeger",
        "Jaeger trace subpath drifted",
    )
    _require(
        trace_config["extensions"]["jaeger_query"]["ai"]["enable_mcp"] is False,
        "Jaeger MCP surface is enabled",
    )
    _require(
        trace_config["service"]["telemetry"]["metrics"]["level"] == "none",
        "Jaeger internal metrics must not collide in the shared task network",
    )
    _require("MEMORY_MAX_TRACES" in trace_start, "Jaeger memory bound is missing")
    _require(
        'max_lifetime_seconds="${GLUEVENIR_TRACE_MAX_LIFETIME_SECONDS:-86400}"'
        in trace_start,
        "Jaeger lifetime bound is missing",
    )
    _require(
        'timeout -s TERM -k 30 "$max_lifetime_seconds"' in trace_start,
        "Jaeger lifetime bound is not enforced",
    )

    for path in (
        AWS_ROOT / "metrics" / "start.sh",
        AWS_ROOT / "grafana" / "start.sh",
        AWS_ROOT / "trace" / "start.sh",
    ):
        subprocess.run(["sh", "-n", str(path)], check=True)


def verify_container_contract() -> None:
    """Build pinned images and ask upstream binaries to parse their configs."""

    for name in IMAGE_NAMES:
        tag = f"gluevenir-observability-{name}:verify"
        subprocess.run(
            [
                "docker",
                "build",
                "--platform",
                "linux/amd64",
                "--file",
                str(AWS_ROOT / name / "Dockerfile"),
                "--tag",
                tag,
                str(ROOT / "observability"),
            ],
            check=True,
        )
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--entrypoint",
                "sh",
                tag,
                "-c",
                "command -v wget >/dev/null",
            ],
            check=True,
        )

    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--entrypoint",
            "sh",
            "gluevenir-observability-trace:verify",
            "-c",
            "command -v timeout >/dev/null",
        ],
        check=True,
    )

    metrics_id = subprocess.check_output(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--platform",
            "linux/amd64",
            "gluevenir-observability-metrics:verify",
        ],
        text=True,
    ).strip()
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            metrics_ready = subprocess.run(
                [
                    "docker",
                    "exec",
                    metrics_id,
                    "wget",
                    "-q",
                    "-O",
                    "/dev/null",
                    "http://127.0.0.1:9090/-/ready",
                ],
                check=False,
            )
            if metrics_ready.returncode == 0:
                break
            time.sleep(1)
        _require(
            metrics_ready.returncode == 0,
            "Prometheus did not start with the bundled entrypoint flags",
        )
    finally:
        subprocess.run(
            ["docker", "stop", "--time", "5", metrics_id],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--user",
            "0",
            "--env",
            f"GLUEVENIR_OTLP_BEARER_TOKEN={'v' * 48}",
            "--entrypoint",
            "/docker-entrypoint.sh",
            "gluevenir-observability-viewer:verify",
            "nginx",
            "-t",
        ],
        check=True,
    )
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "gluevenir-observability-collector:verify",
            "validate",
            "--config=/etc/otelcol-contrib/config.yaml",
        ],
        check=True,
    )
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--entrypoint",
            "/bin/promtool",
            "gluevenir-observability-metrics:verify",
            "check",
            "config",
            "/etc/prometheus/prometheus.yml",
        ],
        check=True,
    )
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--entrypoint",
            "/cmd/jaeger/jaeger-linux",
            "gluevenir-observability-trace:verify",
            "validate",
            "--config=/etc/jaeger/config.yaml",
        ],
        check=True,
    )

    trace_id = subprocess.check_output(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--platform",
            "linux/amd64",
            "gluevenir-observability-trace:verify",
        ],
        text=True,
    ).strip()
    collector_id = ""
    try:
        collector_id = subprocess.check_output(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--platform",
                "linux/amd64",
                "--network",
                f"container:{trace_id}",
                "gluevenir-observability-collector:verify",
            ],
            text=True,
        ).strip()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            collector_ready = subprocess.run(
                [
                    "docker",
                    "exec",
                    collector_id,
                    "wget",
                    "-q",
                    "-O",
                    "/dev/null",
                    "http://127.0.0.1:13133/",
                ],
                check=False,
            )
            trace_ready = subprocess.run(
                [
                    "docker",
                    "exec",
                    collector_id,
                    "wget",
                    "-q",
                    "-O",
                    "/dev/null",
                    "http://127.0.0.1:16686/jaeger/",
                ],
                check=False,
            )
            if collector_ready.returncode == 0 and trace_ready.returncode == 0:
                break
            time.sleep(1)
        _require(
            collector_ready.returncode == 0 and trace_ready.returncode == 0,
            "Collector and Jaeger did not start in one task-local network",
        )
    finally:
        if collector_id:
            subprocess.run(
                ["docker", "stop", "--time", "5", collector_id],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        subprocess.run(
            ["docker", "stop", "--time", "5", trace_id],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    container_id = subprocess.check_output(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--platform",
            "linux/amd64",
            "gluevenir-observability-grafana:verify",
        ],
        text=True,
    ).strip()
    try:
        deadline = time.monotonic() + 60
        pending = set(PUBLIC_SHARES.values())
        while pending and time.monotonic() < deadline:
            for token in tuple(pending):
                result = subprocess.run(
                    [
                        "docker",
                        "exec",
                        container_id,
                        "wget",
                        "-q",
                        "-O",
                        "/dev/null",
                        (f"http://127.0.0.1:3000/api/public/dashboards/{token}"),
                    ],
                    check=False,
                )
                if result.returncode == 0:
                    pending.remove(token)
            if pending:
                time.sleep(1)
        _require(not pending, "Grafana public-dashboard bootstrap did not complete")

        viewer_id = subprocess.check_output(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--platform",
                "linux/amd64",
                "--network",
                f"container:{container_id}",
                "--env",
                f"GLUEVENIR_OTLP_BEARER_TOKEN={'v' * 48}",
                "gluevenir-observability-viewer:verify",
            ],
            text=True,
        ).strip()
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                ready = subprocess.run(
                    [
                        "docker",
                        "exec",
                        viewer_id,
                        "wget",
                        "-q",
                        "-O",
                        "/dev/null",
                        "http://127.0.0.1:8080/healthz",
                    ],
                    check=False,
                )
                if ready.returncode == 0:
                    break
                time.sleep(1)
            _require(ready.returncode == 0, "Viewer health route did not start")
            for index, token in enumerate(PUBLIC_SHARES.values()):
                public_response = subprocess.run(
                    [
                        "docker",
                        "exec",
                        viewer_id,
                        "wget",
                        "-S",
                        "-q",
                        "-O",
                        "/dev/null",
                        f"http://127.0.0.1:8080/public-dashboards/{token}",
                    ],
                    check=True,
                    capture_output=index == 0,
                    text=index == 0,
                )
                if index == 0:
                    headers = public_response.stderr
                    _require(
                        (
                            "frame-ancestors https://gluevenir.obsidiantek.io "
                            "https://production.d2v1tx01e3zvx8.amplifyapp.com"
                        )
                        in headers,
                        "live Viewer response lost the branded-site frame policy",
                    )
                    _require(
                        "X-Frame-Options" not in headers,
                        "live Viewer response contains a framing-denial header",
                    )
            rejected = subprocess.run(
                [
                    "docker",
                    "exec",
                    viewer_id,
                    "wget",
                    "-q",
                    "-O",
                    "/dev/null",
                    "http://127.0.0.1:8080/explore",
                ],
                check=False,
            )
            _require(rejected.returncode != 0, "Viewer exposed Grafana Explore")
        finally:
            subprocess.run(
                ["docker", "stop", "--time", "5", viewer_id],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    finally:
        subprocess.run(
            ["docker", "stop", "--time", "5", container_id],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--containers",
        action="store_true",
        help="also build AMD64 images and invoke upstream config parsers",
    )
    args = parser.parse_args()
    verify_static_contract()
    if args.containers:
        verify_container_contract()
    print("AWS observability config-image contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
