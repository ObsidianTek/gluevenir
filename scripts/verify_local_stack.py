"""Content-safe smoke checks for local/hybrid runtime and cloud-aligned viewer."""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Sequence
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
from uuid import UUID


def _external_https_url(value: str, *, path: str | None = None) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ValueError("cloud endpoint is invalid") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname in {"localhost", "127.0.0.1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (path is not None and parsed.path != path)
    ):
        raise ValueError("cloud endpoint is invalid")
    return value


def _json_request(url: str, *, payload: dict[str, object] | None = None) -> object:
    body = (
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if payload is not None
        else None
    )
    request = Request(
        url,
        data=body,
        headers={"content-type": "application/json"} if body is not None else {},
        method="POST" if body is not None else "GET",
    )
    with urlopen(request, timeout=30) as response:  # noqa: S310
        if response.status != 200:
            raise RuntimeError("local smoke endpoint returned an error")
        raw = response.read(128_001)
    if len(raw) > 128_000:
        raise RuntimeError("local smoke response is too large")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("local smoke response is invalid") from None


def _runtime_smoke(base_url: str) -> None:
    base = urlsplit(base_url)
    if (
        base.scheme != "http"
        or base.hostname not in {"app", "localhost", "127.0.0.1"}
        or base.username is not None
        or base.password is not None
        or base.path.rstrip("/")
        or base.query
        or base.fragment
    ):
        raise ValueError("local base URL is invalid")
    health = _json_request(f"{base_url.rstrip('/')}/health")
    if not isinstance(health, dict) or health.get("status") != "ok":
        raise RuntimeError("local health contract is invalid")
    cases = (
        (
            "ALLOW",
            {
                "journey_id": "program-current-status",
                "persona": "program_lead",
                "persona_token": "program-lead-synthetic",
                "query": "What is the current synthetic HX-17 program status?",
                "turn_id": "91000000-0000-4000-8000-000000000001",
            },
        ),
        (
            "MODIFY",
            {
                "journey_id": "partner-stability-update",
                "persona": "authorized_external_partner",
                "persona_token": "external-partner-synthetic",
                "query": "What is approved for the synthetic HX-17 partner update?",
                "turn_id": "91000000-0000-4000-8000-000000000002",
            },
        ),
    )
    for decision, payload in cases:
        response = _json_request(
            f"{base_url.rstrip('/')}/v1/demo",
            payload=payload,
        )
        if not isinstance(response, dict):
            raise RuntimeError("local demo response is invalid")
        result = response.get("public_result")
        receipt = result.get("public_receipt") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or result.get("decision") != decision
            or not isinstance(receipt, dict)
            or receipt.get("decision") != decision
            or receipt.get("signature_verified") is not True
        ):
            raise RuntimeError("local governed-turn smoke check failed")
        UUID(str(receipt.get("receipt_id")))


def _internal_observability_url(value: str, *, host: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ValueError("local observability endpoint is invalid") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname != host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("local observability endpoint is invalid")
    return value.rstrip("/")


def _has_request_trace(payload: object, *, started_after_us: int) -> bool:
    if type(started_after_us) is not int or started_after_us < 0:
        raise ValueError("trace lower bound is invalid")
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return False
    for trace in payload["data"]:
        if not isinstance(trace, dict) or not isinstance(trace.get("spans"), list):
            continue
        if any(
            isinstance(span, dict)
            and span.get("operationName") == "gluevenir.request"
            and type(span.get("startTime")) is int
            and span["startTime"] >= started_after_us
            for span in trace["spans"]
        ):
            return True
    return False


def _request_metric_value(payload: object) -> float | None:
    if not isinstance(payload, dict) or payload.get("status") != "success":
        return None
    data = payload.get("data")
    results = data.get("result") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return None
    for result in results:
        value = result.get("value") if isinstance(result, dict) else None
        if not isinstance(value, list) or len(value) != 2:
            continue
        try:
            metric_value = float(value[1])
            if metric_value >= 0:
                return metric_value
        except (TypeError, ValueError):
            continue
    return 0.0


def _metric_query_url(prometheus_url: str) -> str:
    metric_query = urlencode(
        {
            "query": (
                'sum(traces_span_metrics_calls_total{span_name="gluevenir.request"})'
            )
        }
    )
    return f"{prometheus_url}/api/v1/query?{metric_query}"


def _metric_baseline(prometheus_url: str) -> float:
    value = _request_metric_value(_json_request(_metric_query_url(prometheus_url)))
    if value is None:
        raise RuntimeError("local telemetry baseline is invalid")
    return value


def _has_metric_delta(current: float | None, *, baseline: float) -> bool:
    if not isinstance(baseline, (int, float)) or baseline < 0:
        raise ValueError("metric baseline is invalid")
    return current is not None and current >= baseline + 2


def _telemetry_smoke(
    jaeger_url: str,
    prometheus_url: str,
    *,
    baseline_metric: float,
    started_after_us: int,
) -> None:
    if not isinstance(baseline_metric, (int, float)) or baseline_metric < 0:
        raise ValueError("metric baseline is invalid")
    trace_query = urlencode(
        {
            "service": "gluevenir-bio",
            "limit": "20",
            "start": str(started_after_us),
        }
    )
    deadline = time.monotonic() + 30
    trace_verified = metric_verified = False
    while time.monotonic() < deadline and not (trace_verified and metric_verified):
        try:
            if not trace_verified:
                trace_verified = _has_request_trace(
                    _json_request(f"{jaeger_url}/api/traces?{trace_query}"),
                    started_after_us=started_after_us,
                )
            if not metric_verified:
                current = _request_metric_value(
                    _json_request(_metric_query_url(prometheus_url))
                )
                metric_verified = _has_metric_delta(
                    current,
                    baseline=baseline_metric,
                )
        except (OSError, RuntimeError, URLError):
            pass
        if not (trace_verified and metric_verified):
            time.sleep(1)
    if not trace_verified or not metric_verified:
        raise RuntimeError("local bounded telemetry smoke check failed")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("runtime", "cloud-aligned"), required=True)
    parser.add_argument("--base-url")
    parser.add_argument("--api-url")
    parser.add_argument("--site-url")
    parser.add_argument("--jaeger-url")
    parser.add_argument("--prometheus-url")
    args = parser.parse_args(argv)
    if args.mode == "runtime":
        if args.api_url is not None or args.site_url is not None:
            raise SystemExit("runtime smoke accepts only local endpoints")
        jaeger_url = _internal_observability_url(args.jaeger_url or "", host="jaeger")
        prometheus_url = _internal_observability_url(
            args.prometheus_url or "", host="prometheus"
        )
        baseline_metric = _metric_baseline(prometheus_url)
        started_after_us = time.time_ns() // 1_000
        _runtime_smoke(args.base_url or "")
        _telemetry_smoke(
            jaeger_url,
            prometheus_url,
            baseline_metric=baseline_metric,
            started_after_us=started_after_us,
        )
        print(
            "local ALLOW/MODIFY, signed-receipt, trace, and metric smoke checks passed"
        )
        return
    if any(
        value is not None
        for value in (args.base_url, args.jaeger_url, args.prometheus_url)
    ):
        raise SystemExit("cloud-aligned verification accepts only cloud endpoints")
    _external_https_url(args.api_url or "", path="/v1/demo")
    _external_https_url(args.site_url or "")
    print("cloud-aligned external endpoint contract verified; nothing was deployed")


if __name__ == "__main__":
    main()
