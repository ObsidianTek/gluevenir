from __future__ import annotations

import pytest

from scripts.verify_local_stack import (
    _has_metric_delta,
    _has_request_trace,
    _internal_observability_url,
    _request_metric_value,
)


def test_observability_urls_are_exact_task_internal_hosts() -> None:
    assert (
        _internal_observability_url("http://jaeger:16686", host="jaeger")
        == "http://jaeger:16686"
    )
    with pytest.raises(ValueError, match="observability endpoint"):
        _internal_observability_url("http://user:secret@jaeger:16686", host="jaeger")
    with pytest.raises(ValueError, match="observability endpoint"):
        _internal_observability_url("https://jaeger:16686", host="jaeger")


def test_trace_smoke_accepts_only_bounded_request_operation() -> None:
    assert _has_request_trace(
        {
            "data": [
                {
                    "spans": [
                        {
                            "operationName": "gluevenir.request",
                            "startTime": 1_786_920_000_000_001,
                        },
                        {
                            "operationName": "gluevenir.gateway.evaluation",
                            "startTime": 1_786_920_000_000_002,
                        },
                    ]
                }
            ]
        },
        started_after_us=1_786_920_000_000_000,
    )
    assert not _has_request_trace(
        {
            "data": [
                {
                    "spans": [
                        {
                            "operationName": "gluevenir.request",
                            "startTime": 1_786_919_999_999_999,
                        }
                    ]
                }
            ]
        },
        started_after_us=1_786_920_000_000_000,
    )


def test_metric_smoke_returns_current_counter_for_baseline_delta() -> None:
    assert _request_metric_value(
        {
            "status": "success",
            "data": {"result": [{"value": [1_786_920_000, "2"]}]},
        }
    ) == pytest.approx(2.0)
    assert _request_metric_value(
        {"status": "success", "data": {"result": []}}
    ) == pytest.approx(0.0)
    assert _request_metric_value({"status": "error"}) is None
    assert not _has_metric_delta(8.0, baseline=8.0)
    assert not _has_metric_delta(9.0, baseline=8.0)
    assert _has_metric_delta(10.0, baseline=8.0)
