"""Content-safe telemetry semantics for the bounded Gluevenir Bio runtime.

This module intentionally has no exporter or OpenTelemetry SDK dependency.  It
defines the low-cardinality records that runtime wiring may translate into spans,
events, and metrics.  Arbitrary attributes are not accepted, so untrusted request
or model data cannot be attached by accident.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from gluevenir._demo_catalog import _DemoPersona
from gluevenir._policy import _Decision, _ReasonCode
from gluevenir._ports import MemoryOperation

_SPAN_SCHEMA = "gluevenir.telemetry.span.v1"
_DASHBOARD_SCHEMA = "gluevenir.telemetry.dashboard.v1"
_MAX_SEQUENCE = 1_000_000_000
_MAX_DURATION_MS = 120_000
_MAX_COUNT = 10_000
_MAX_POINTS = 10_000


class _TelemetryStage(StrEnum):
    REQUEST = "request"
    GATEWAY_EVALUATION = "gateway.evaluation"
    RECALL = "recall"
    APPROVAL = "approval"
    MODEL = "model"
    OUTPUT_SCAN = "output.scan"
    RECEIPT = "receipt"
    PENDING_RESOLUTION = "pending.resolution"
    RESPONSE_PROJECTION = "response.projection"


class _TelemetryStatus(StrEnum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    PENDING = "pending"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class _TelemetryEmitStatus(StrEnum):
    EMITTED = "emitted"
    DISABLED = "disabled"
    INVALID_POINT = "invalid_point"
    SINK_UNAVAILABLE = "sink_unavailable"


_DECISION_STATUS = {
    _Decision.ALLOW: _TelemetryStatus.SUCCEEDED,
    _Decision.MODIFY: _TelemetryStatus.SUCCEEDED,
    _Decision.DENY: _TelemetryStatus.DENIED,
    _Decision.STEP_UP: _TelemetryStatus.PENDING,
    _Decision.DEFER: _TelemetryStatus.PENDING,
}
_DECISION_STAGES = frozenset(
    {
        _TelemetryStage.GATEWAY_EVALUATION,
        _TelemetryStage.APPROVAL,
        _TelemetryStage.PENDING_RESOLUTION,
        _TelemetryStage.RESPONSE_PROJECTION,
    }
)
_REASON_STAGES = frozenset(
    {
        _TelemetryStage.GATEWAY_EVALUATION,
        _TelemetryStage.APPROVAL,
        _TelemetryStage.PENDING_RESOLUTION,
    }
)


def _bounded_int(name: str, value: object, maximum: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} is outside its allowed range")
    return value


@dataclass(frozen=True, slots=True)
class _TelemetryPoint:
    """One immutable, allowlisted observation suitable for an OTel adapter."""

    sequence: int
    stage: _TelemetryStage
    status: _TelemetryStatus
    duration_ms: int
    start_offset_ms: int = 0
    persona: _DemoPersona | None = None
    operation: MemoryOperation | None = None
    decision: _Decision | None = None
    reason_code: _ReasonCode | None = None
    candidate_count: int | None = None
    included_count: int | None = None
    excluded_count: int | None = None
    model_invoked: bool | None = None
    receipt_verified: bool | None = None

    def __post_init__(self) -> None:
        _bounded_int("sequence", self.sequence, _MAX_SEQUENCE)
        _bounded_int("duration_ms", self.duration_ms, _MAX_DURATION_MS)
        _bounded_int("start_offset_ms", self.start_offset_ms, _MAX_DURATION_MS)
        if type(self.stage) is not _TelemetryStage:
            raise TypeError("stage must be a telemetry stage")
        if type(self.status) is not _TelemetryStatus:
            raise TypeError("status must be a telemetry status")
        if self.persona is not None and type(self.persona) is not _DemoPersona:
            raise TypeError("persona must be a server-owned demo persona")
        if self.operation is not None and not isinstance(
            self.operation, MemoryOperation
        ):
            raise TypeError("operation must be a memory operation")
        if self.decision is not None and type(self.decision) is not _Decision:
            raise TypeError("decision must be a policy decision")
        if self.reason_code is not None and type(self.reason_code) is not _ReasonCode:
            raise TypeError("reason_code must be a policy reason code")

        if self.decision is not None and self.stage not in _DECISION_STAGES:
            raise ValueError("this stage cannot carry a decision")
        if self.reason_code is not None and self.stage not in _REASON_STAGES:
            raise ValueError("this stage cannot carry a reason code")
        if self.reason_code is not None and self.decision is None:
            raise ValueError("reason_code requires a decision")
        if self.stage in {
            _TelemetryStage.APPROVAL,
            _TelemetryStage.PENDING_RESOLUTION,
        } and (self.decision is None) != (self.reason_code is None):
            raise ValueError("decision and reason_code must be supplied together")
        if self.stage is _TelemetryStage.GATEWAY_EVALUATION:
            if self.decision is None or self.reason_code is None:
                raise ValueError("gateway evaluation requires decision and reason")
            if self.status is not _DECISION_STATUS[self.decision]:
                raise ValueError("gateway status must match its policy decision")
        if self.stage is _TelemetryStage.PENDING_RESOLUTION and self.decision is None:
            raise ValueError("pending resolution requires decision and reason")
        if self.stage is _TelemetryStage.RESPONSE_PROJECTION:
            if self.decision is None:
                raise ValueError("response projection requires a decision")
            if self.status is not _DECISION_STATUS[self.decision]:
                raise ValueError("response status must match its policy decision")

        counts = (self.candidate_count, self.included_count, self.excluded_count)
        if self.stage is _TelemetryStage.RECALL:
            if any(value is None for value in counts):
                raise ValueError("recall requires all bounded memory counts")
            candidate, included, excluded = (
                _bounded_int(name, value, _MAX_COUNT)
                for name, value in zip(
                    ("candidate_count", "included_count", "excluded_count"),
                    counts,
                    strict=True,
                )
            )
            if candidate != included + excluded:
                raise ValueError("candidate count must equal included plus excluded")
        elif any(value is not None for value in counts):
            raise ValueError("only recall may carry memory counts")

        if self.stage is _TelemetryStage.MODEL:
            if type(self.model_invoked) is not bool:
                raise TypeError("model stage requires model_invoked")
        elif self.model_invoked is not None:
            raise ValueError("only model may carry model_invoked")

        if self.stage is _TelemetryStage.RECEIPT:
            if type(self.receipt_verified) is not bool:
                raise TypeError("receipt stage requires receipt_verified")
        elif self.receipt_verified is not None:
            raise ValueError("only receipt may carry receipt_verified")

    def attribute_items(self) -> tuple[tuple[str, str | int | bool], ...]:
        """Return exact, deterministic OpenTelemetry-compatible attributes."""

        values: tuple[tuple[str, str | int | bool | None], ...] = (
            ("gluevenir.stage", self.stage.value),
            ("gluevenir.status", self.status.value),
            ("gluevenir.duration_ms", self.duration_ms),
            (
                "gluevenir.persona",
                self.persona.value if self.persona is not None else None,
            ),
            (
                "gluevenir.operation",
                self.operation.value if self.operation is not None else None,
            ),
            (
                "gluevenir.decision",
                self.decision.value if self.decision is not None else None,
            ),
            (
                "gluevenir.reason_code",
                self.reason_code.value if self.reason_code is not None else None,
            ),
            ("gluevenir.candidate_count", self.candidate_count),
            ("gluevenir.included_count", self.included_count),
            ("gluevenir.excluded_count", self.excluded_count),
            ("gluevenir.model_invoked", self.model_invoked),
            ("gluevenir.receipt_verified", self.receipt_verified),
        )
        return tuple((key, value) for key, value in values if value is not None)

    def as_span(self) -> dict[str, object]:
        """Return a fresh dependency-free span envelope for an SDK adapter."""

        return {
            "schema": _SPAN_SCHEMA,
            "name": f"gluevenir.{self.stage.value}",
            "sequence": self.sequence,
            "start_offset_ms": self.start_offset_ms,
            "attributes": dict(self.attribute_items()),
        }


@dataclass(frozen=True, slots=True)
class _TelemetryEmitResult:
    status: _TelemetryEmitStatus

    @property
    def emitted(self) -> bool:
        return self.status is _TelemetryEmitStatus.EMITTED


def _emit_telemetry(
    point: object,
    sink: Callable[[Mapping[str, object]], object] | None,
) -> _TelemetryEmitResult:
    """Emit without allowing observability failure to break governed execution."""

    if type(point) is not _TelemetryPoint:
        return _TelemetryEmitResult(_TelemetryEmitStatus.INVALID_POINT)
    if sink is None:
        return _TelemetryEmitResult(_TelemetryEmitStatus.DISABLED)
    if not callable(sink):
        return _TelemetryEmitResult(_TelemetryEmitStatus.SINK_UNAVAILABLE)
    try:
        sink(point.as_span())
    except Exception:
        return _TelemetryEmitResult(_TelemetryEmitStatus.SINK_UNAVAILABLE)
    return _TelemetryEmitResult(_TelemetryEmitStatus.EMITTED)


def _project_telemetry_dashboard(
    points: Sequence[_TelemetryPoint],
    *,
    persona: _DemoPersona | None = None,
) -> dict[str, object]:
    """Aggregate allowlisted points for public aggregate or persona dashboards."""

    if isinstance(points, (str, bytes)) or not isinstance(points, Sequence):
        raise TypeError("points must be a bounded sequence")
    if len(points) > _MAX_POINTS:
        raise ValueError("too many telemetry points")
    if persona is not None and type(persona) is not _DemoPersona:
        raise TypeError("persona must be a server-owned demo persona")
    if any(type(point) is not _TelemetryPoint for point in points):
        raise TypeError("points contains an invalid telemetry point")

    selected = tuple(
        point for point in points if persona is None or point.persona is persona
    )
    stage_counts = {
        stage.value: sum(point.stage is stage for point in selected)
        for stage in _TelemetryStage
    }
    status_counts = {
        status.value: sum(point.status is status for point in selected)
        for status in _TelemetryStatus
    }
    decision_counts = {
        decision.value: sum(
            point.stage is _TelemetryStage.GATEWAY_EVALUATION
            and point.decision is decision
            for point in selected
        )
        for decision in _Decision
    }
    stage_duration_ms = {
        stage.value: _duration_projection(
            tuple(point.duration_ms for point in selected if point.stage is stage)
        )
        for stage in _TelemetryStage
    }
    return {
        "schema": _DASHBOARD_SCHEMA,
        "scope": "aggregate" if persona is None else "persona",
        "persona": persona.value if persona is not None else None,
        "synthetic_telemetry_only": True,
        "point_count": len(selected),
        "request_count": stage_counts[_TelemetryStage.REQUEST.value],
        "governed_turns": stage_counts[_TelemetryStage.GATEWAY_EVALUATION.value],
        "useful_answers": sum(
            point.stage is _TelemetryStage.RESPONSE_PROJECTION
            and point.status is _TelemetryStatus.SUCCEEDED
            and point.decision in {_Decision.ALLOW, _Decision.MODIFY}
            for point in selected
        ),
        "approved_substitutions": decision_counts[_Decision.MODIFY.value],
        "pending_actions": (
            decision_counts[_Decision.STEP_UP.value]
            + decision_counts[_Decision.DEFER.value]
        ),
        "boundary_denials": decision_counts[_Decision.DENY.value],
        "model_invocations": sum(point.model_invoked is True for point in selected),
        "verified_receipts": sum(point.receipt_verified is True for point in selected),
        "decision_counts": decision_counts,
        "stage_counts": stage_counts,
        "status_counts": status_counts,
        "stage_duration_ms": stage_duration_ms,
    }


def _duration_projection(values: tuple[int, ...]) -> dict[str, int]:
    return {
        "count": len(values),
        "sum": sum(values),
        "max": max(values, default=0),
    }
