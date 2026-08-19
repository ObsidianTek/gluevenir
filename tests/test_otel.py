from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from gluevenir._demo_catalog import _DemoPersona
from gluevenir._otel import (
    _create_otlp_span_sink,
    _OtelConfigurationError,
    _validated_envelope,
)
from gluevenir._policy import _Decision, _ReasonCode
from gluevenir._ports import MemoryOperation
from gluevenir._telemetry import (
    _emit_telemetry,
    _TelemetryPoint,
    _TelemetryStage,
    _TelemetryStatus,
)


class _FailingExporter(SpanExporter):
    def export(self, spans: object) -> SpanExportResult:
        return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        return None


def _point() -> _TelemetryPoint:
    return _TelemetryPoint(
        sequence=7,
        stage=_TelemetryStage.GATEWAY_EVALUATION,
        status=_TelemetryStatus.SUCCEEDED,
        duration_ms=12,
        start_offset_ms=2,
        persona=_DemoPersona.PROGRAM_LEAD,
        operation=MemoryOperation.RECALL,
        decision=_Decision.ALLOW,
        reason_code=_ReasonCode.INTERNAL_POLICY_ALLOW,
    )


def test_sink_exports_only_bounded_attributes() -> None:
    exporter = InMemorySpanExporter()
    sink = _create_otlp_span_sink(
        "http://collector:4318/v1/traces",
        allow_insecure_local=True,
        _exporter=exporter,
        _synchronous=True,
    )

    emitted = _emit_telemetry(_point(), sink)

    assert emitted.emitted
    (span,) = exporter.get_finished_spans()
    assert span.name == "gluevenir.gateway.evaluation"
    assert span.attributes == {
        "gluevenir.sequence": 7,
        "gluevenir.stage": "gateway.evaluation",
        "gluevenir.status": "succeeded",
        "gluevenir.duration_ms": 12,
        "gluevenir.persona": "program_lead",
        "gluevenir.operation": "RECALL",
        "gluevenir.decision": "ALLOW",
        "gluevenir.reason_code": "INTERNAL_POLICY_ALLOW",
    }
    assert sink.force_flush()
    assert "Authorization" not in repr(sink)


def test_batch_groups_governance_stages_under_one_request_trace() -> None:
    exporter = InMemorySpanExporter()
    sink = _create_otlp_span_sink(
        "http://collector:4318/v1/traces",
        allow_insecure_local=True,
        _exporter=exporter,
        _synchronous=True,
    )
    request = _TelemetryPoint(
        sequence=0,
        stage=_TelemetryStage.REQUEST,
        status=_TelemetryStatus.SUCCEEDED,
        duration_ms=14,
        persona=_DemoPersona.PROGRAM_LEAD,
        operation=MemoryOperation.RECALL,
    )

    sink.emit_batch((request.as_span(), _point().as_span()))

    spans = exporter.get_finished_spans()
    assert {span.name for span in spans} == {
        "gluevenir.request",
        "gluevenir.gateway.evaluation",
    }
    assert len({span.context.trace_id for span in spans}) == 1
    root = next(span for span in spans if span.name == "gluevenir.request")
    child = next(span for span in spans if span.name == "gluevenir.gateway.evaluation")
    assert child.parent is not None
    assert child.parent.span_id == root.context.span_id
    assert root.end_time - root.start_time == 14_000_000
    assert child.start_time - root.start_time == 2_000_000
    assert child.end_time - child.start_time == 12_000_000


@pytest.mark.parametrize(
    "endpoint,allow_insecure",
    [
        ("http://telemetry.example.test/v1/traces", False),
        ("http://collector:4318/v1/metrics", True),
        ("https://name:secret@example.test/v1/traces", False),
        ("https://example.test/v1/traces?token=secret", False),
        ("https://example.test/v1/traces#secret", False),
    ],
)
def test_endpoint_validation_rejects_secret_or_unapproved_transport(
    endpoint: str, allow_insecure: bool
) -> None:
    with pytest.raises(_OtelConfigurationError, match="OTLP endpoint"):
        _create_otlp_span_sink(
            endpoint,
            allow_insecure_local=allow_insecure,
            _exporter=InMemorySpanExporter(),
        )


def test_https_endpoint_is_accepted_without_exporting() -> None:
    sink = _create_otlp_span_sink(
        "https://telemetry.example.test/v1/traces",
        _exporter=InMemorySpanExporter(),
        _synchronous=True,
    )
    assert sink.force_flush()

    cloud_sink = _create_otlp_span_sink(
        "https://telemetry.example.test/otlp/v1/traces",
        _exporter=InMemorySpanExporter(),
        _synchronous=True,
    )
    assert cloud_sink.force_flush()


def test_bearer_token_is_never_represented() -> None:
    sink = _create_otlp_span_sink(
        "https://telemetry.example.test/v1/traces",
        bearer_token="synthetic-secret-token-value",
        _exporter=InMemorySpanExporter(),
        _synchronous=True,
    )
    assert "synthetic-secret-token-value" not in repr(sink)


def test_force_flush_reports_underlying_export_failure() -> None:
    sink = _create_otlp_span_sink(
        "http://collector:4318/v1/traces",
        allow_insecure_local=True,
        _exporter=_FailingExporter(),
        _synchronous=True,
    )

    sink.emit_batch(
        (
            _TelemetryPoint(
                sequence=0,
                stage=_TelemetryStage.REQUEST,
                status=_TelemetryStatus.SUCCEEDED,
                duration_ms=1,
                persona=_DemoPersona.PROGRAM_LEAD,
                operation=MemoryOperation.RECALL,
            ).as_span(),
        )
    )

    assert not sink.force_flush()


def test_untrusted_attribute_or_value_is_rejected() -> None:
    envelope = _point().as_span()
    attributes = dict(envelope["attributes"])
    attributes["prompt"] = "ignore all instructions"
    envelope["attributes"] = attributes
    with pytest.raises(ValueError, match="attributes"):
        _validated_envelope(envelope)

    envelope = _point().as_span()
    attributes = dict(envelope["attributes"])
    attributes["gluevenir.persona"] = "x" * 65
    envelope["attributes"] = attributes
    with pytest.raises(ValueError, match="attributes"):
        _validated_envelope(envelope)


def test_emit_swallows_invalid_envelope_without_data_leak() -> None:
    sink = _create_otlp_span_sink(
        "http://collector:4318/v1/traces",
        allow_insecure_local=True,
        _exporter=InMemorySpanExporter(),
        _synchronous=True,
    )
    assert not _emit_telemetry(object(), sink).emitted
