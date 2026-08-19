from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError

import pytest

from gluevenir._demo_catalog import _DemoPersona
from gluevenir._policy import _Decision, _ReasonCode
from gluevenir._ports import MemoryOperation
from gluevenir._telemetry import (
    _emit_telemetry,
    _project_telemetry_dashboard,
    _TelemetryEmitStatus,
    _TelemetryPoint,
    _TelemetryStage,
    _TelemetryStatus,
)

_SENTINELS = (
    "RAW-PROMPT-SENTINEL",
    "RAW-ANSWER-SENTINEL",
    "MEMORY-CONTENT-SENTINEL",
    "DETECTOR-MATCH-SENTINEL",
    "CREDENTIAL-SENTINEL",
    "TENANT-SENTINEL",
    "CUSTOMER-SENTINEL",
    "EXCLUDED-ID-SENTINEL",
    "GUARDRAIL-BODY-SENTINEL",
)


def _point(
    stage: _TelemetryStage,
    *,
    sequence: int = 0,
    status: _TelemetryStatus = _TelemetryStatus.SUCCEEDED,
    persona: _DemoPersona = _DemoPersona.PROGRAM_LEAD,
    **values: object,
) -> _TelemetryPoint:
    return _TelemetryPoint(
        sequence=sequence,
        stage=stage,
        status=status,
        duration_ms=7,
        persona=persona,
        **values,  # type: ignore[arg-type]
    )


def _full_turn(
    persona: _DemoPersona = _DemoPersona.PROGRAM_LEAD,
) -> tuple[_TelemetryPoint, ...]:
    return (
        _point(
            _TelemetryStage.REQUEST,
            sequence=0,
            persona=persona,
            operation=MemoryOperation.RECALL,
        ),
        _point(
            _TelemetryStage.GATEWAY_EVALUATION,
            sequence=1,
            persona=persona,
            operation=MemoryOperation.RECALL,
            decision=_Decision.ALLOW,
            reason_code=_ReasonCode.INTERNAL_POLICY_ALLOW,
        ),
        _point(
            _TelemetryStage.RECALL,
            sequence=2,
            persona=persona,
            operation=MemoryOperation.RECALL,
            candidate_count=3,
            included_count=2,
            excluded_count=1,
        ),
        _point(
            _TelemetryStage.APPROVAL,
            sequence=3,
            persona=persona,
            decision=_Decision.ALLOW,
            reason_code=_ReasonCode.INTERNAL_POLICY_ALLOW,
        ),
        _point(
            _TelemetryStage.MODEL,
            sequence=4,
            persona=persona,
            model_invoked=True,
        ),
        _point(_TelemetryStage.OUTPUT_SCAN, sequence=5, persona=persona),
        _point(
            _TelemetryStage.RECEIPT,
            sequence=6,
            persona=persona,
            receipt_verified=True,
        ),
        _point(
            _TelemetryStage.PENDING_RESOLUTION,
            sequence=7,
            persona=persona,
            decision=_Decision.ALLOW,
            reason_code=_ReasonCode.INTERNAL_POLICY_ALLOW,
        ),
        _point(
            _TelemetryStage.RESPONSE_PROJECTION,
            sequence=8,
            persona=persona,
            decision=_Decision.ALLOW,
        ),
    )


def test_all_ratified_stages_have_typed_content_safe_span_semantics() -> None:
    points = _full_turn()

    assert {point.stage for point in points} == set(_TelemetryStage)
    assert [point.sequence for point in points] == list(range(len(points)))
    for point in points:
        span = point.as_span()
        assert span["name"] == f"gluevenir.{point.stage.value}"
        assert span["schema"] == "gluevenir.telemetry.span.v1"
        assert list(span) == [
            "schema",
            "name",
            "sequence",
            "start_offset_ms",
            "attributes",
        ]
        assert tuple(span["attributes"]) == tuple(  # type: ignore[arg-type]
            key for key, _ in point.attribute_items()
        )


def test_span_has_an_exact_allowlist_and_never_serializes_sensitive_sentinels() -> None:
    point = _point(
        _TelemetryStage.GATEWAY_EVALUATION,
        operation=MemoryOperation.RECALL,
        decision=_Decision.DENY,
        reason_code=_ReasonCode.POLICY_UNAVAILABLE,
        status=_TelemetryStatus.DENIED,
    )

    span = point.as_span()
    assert set(span["attributes"]) == {  # type: ignore[arg-type]
        "gluevenir.stage",
        "gluevenir.status",
        "gluevenir.duration_ms",
        "gluevenir.persona",
        "gluevenir.operation",
        "gluevenir.decision",
        "gluevenir.reason_code",
    }
    assert all(value not in repr(span) for value in _SENTINELS)
    assert not any(
        fragment in key
        for key in span["attributes"]  # type: ignore[union-attr]
        for fragment in (
            "prompt",
            "answer",
            "content",
            "match",
            "credential",
            "tenant",
            "customer",
            "excluded_id",
            "guardrail",
        )
    )


def test_only_server_owned_enums_can_supply_low_cardinality_labels() -> None:
    with pytest.raises(TypeError, match="persona"):
        _TelemetryPoint(
            0,
            _TelemetryStage.REQUEST,
            _TelemetryStatus.SUCCEEDED,
            1,
            persona="RAW-PROMPT-SENTINEL",  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="decision"):
        _point(
            _TelemetryStage.GATEWAY_EVALUATION,
            decision="ALLOW",  # type: ignore[arg-type]
            reason_code=_ReasonCode.INTERNAL_POLICY_ALLOW,
        )
    with pytest.raises(TypeError, match="reason_code"):
        _point(
            _TelemetryStage.GATEWAY_EVALUATION,
            decision=_Decision.ALLOW,
            reason_code="RAW-ANSWER-SENTINEL",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("values", "error"),
    [
        ({"sequence": True}, TypeError),
        ({"sequence": 1_000_000_001}, ValueError),
        ({"duration_ms": -1}, ValueError),
        ({"duration_ms": 120_001}, ValueError),
    ],
)
def test_sequence_and_duration_are_bounded(
    values: dict[str, object], error: type[Exception]
) -> None:
    arguments: dict[str, object] = {
        "sequence": 0,
        "stage": _TelemetryStage.REQUEST,
        "status": _TelemetryStatus.SUCCEEDED,
        "duration_ms": 1,
    }
    arguments.update(values)

    with pytest.raises(error):
        _TelemetryPoint(**arguments)  # type: ignore[arg-type]


def test_recall_counts_are_bounded_and_must_balance() -> None:
    with pytest.raises(ValueError, match="requires all"):
        _point(_TelemetryStage.RECALL)
    with pytest.raises(ValueError, match="equal"):
        _point(
            _TelemetryStage.RECALL,
            candidate_count=4,
            included_count=2,
            excluded_count=1,
        )
    with pytest.raises(ValueError, match="only recall"):
        _point(_TelemetryStage.REQUEST, candidate_count=1)


def test_gateway_status_cannot_misrepresent_the_policy_decision() -> None:
    with pytest.raises(ValueError, match="status"):
        _point(
            _TelemetryStage.GATEWAY_EVALUATION,
            decision=_Decision.DENY,
            reason_code=_ReasonCode.IDENTITY_DENIED,
            status=_TelemetryStatus.SUCCEEDED,
        )
    unavailable = _point(
        _TelemetryStage.GATEWAY_EVALUATION,
        decision=_Decision.DENY,
        reason_code=_ReasonCode.POLICY_UNAVAILABLE,
        status=_TelemetryStatus.DENIED,
    )
    assert unavailable.decision is _Decision.DENY

    with pytest.raises(ValueError, match="response status"):
        _point(
            _TelemetryStage.RESPONSE_PROJECTION,
            decision=_Decision.DENY,
            status=_TelemetryStatus.SUCCEEDED,
        )


def test_pending_resolution_requires_a_complete_bounded_outcome() -> None:
    with pytest.raises(ValueError, match="requires decision"):
        _point(_TelemetryStage.PENDING_RESOLUTION)
    with pytest.raises(ValueError, match="supplied together"):
        _point(
            _TelemetryStage.APPROVAL,
            decision=_Decision.ALLOW,
        )


def test_stage_specific_flags_cannot_be_attached_elsewhere() -> None:
    with pytest.raises(ValueError, match="only model"):
        _point(_TelemetryStage.REQUEST, model_invoked=False)
    with pytest.raises(TypeError, match="model stage"):
        _point(_TelemetryStage.MODEL)
    with pytest.raises(ValueError, match="only receipt"):
        _point(_TelemetryStage.REQUEST, receipt_verified=False)
    with pytest.raises(TypeError, match="receipt stage"):
        _point(_TelemetryStage.RECEIPT)


def test_point_is_frozen_and_span_projection_is_deterministic() -> None:
    point = _full_turn()[1]

    assert point.as_span() == point.as_span()
    with pytest.raises(FrozenInstanceError):
        point.duration_ms = 99  # type: ignore[misc]


def test_emitter_is_fail_safe_when_disabled_invalid_or_sink_is_unavailable() -> None:
    point = _full_turn()[0]
    captured: list[Mapping[str, object]] = []

    assert (
        _emit_telemetry(point, captured.append).status is _TelemetryEmitStatus.EMITTED
    )
    assert captured == [point.as_span()]
    assert _emit_telemetry(point, None).status is _TelemetryEmitStatus.DISABLED
    assert (
        _emit_telemetry("RAW-PROMPT-SENTINEL", captured.append).status
        is _TelemetryEmitStatus.INVALID_POINT
    )

    def unavailable(_span: Mapping[str, object]) -> None:
        raise RuntimeError("CREDENTIAL-SENTINEL")

    result = _emit_telemetry(point, unavailable)
    assert result.status is _TelemetryEmitStatus.SINK_UNAVAILABLE
    assert result.emitted is False
    assert "CREDENTIAL-SENTINEL" not in repr(result)


def test_dashboard_projection_is_public_bounded_and_persona_filterable() -> None:
    program = _full_turn(_DemoPersona.PROGRAM_LEAD)
    external = _full_turn(_DemoPersona.EXTERNAL_PARTNER)

    aggregate = _project_telemetry_dashboard((*program, *external))
    persona = _project_telemetry_dashboard(
        (*program, *external), persona=_DemoPersona.EXTERNAL_PARTNER
    )

    assert aggregate["scope"] == "aggregate"
    assert aggregate["persona"] is None
    assert aggregate["request_count"] == aggregate["governed_turns"] == 2
    assert aggregate["useful_answers"] == 2
    assert aggregate["model_invocations"] == aggregate["verified_receipts"] == 2
    assert aggregate["decision_counts"] == {
        "ALLOW": 2,
        "DENY": 0,
        "MODIFY": 0,
        "STEP_UP": 0,
        "DEFER": 0,
    }
    assert persona["scope"] == "persona"
    assert persona["persona"] == "authorized_external_partner"
    assert persona["point_count"] == len(external)
    assert persona["request_count"] == persona["governed_turns"] == 1
    assert all(value not in repr(aggregate) for value in _SENTINELS)


def test_dashboard_outcomes_and_order_are_deterministic() -> None:
    denied = _point(
        _TelemetryStage.GATEWAY_EVALUATION,
        decision=_Decision.DENY,
        reason_code=_ReasonCode.IDENTITY_DENIED,
        status=_TelemetryStatus.DENIED,
    )
    step_up = _point(
        _TelemetryStage.GATEWAY_EVALUATION,
        decision=_Decision.STEP_UP,
        reason_code=_ReasonCode.HUMAN_APPROVAL_REQUIRED,
        status=_TelemetryStatus.PENDING,
    )
    projected = _project_telemetry_dashboard((step_up, denied))

    assert projected == _project_telemetry_dashboard((denied, step_up))
    assert projected["boundary_denials"] == 1
    assert projected["pending_actions"] == 1
    assert list(projected["decision_counts"]) == [  # type: ignore[arg-type]
        decision.value for decision in _Decision
    ]
    assert list(projected["stage_counts"]) == [  # type: ignore[arg-type]
        stage.value for stage in _TelemetryStage
    ]
    assert list(projected["status_counts"]) == [  # type: ignore[arg-type]
        status.value for status in _TelemetryStatus
    ]


def test_dashboard_rejects_unbounded_or_untyped_input() -> None:
    with pytest.raises(TypeError, match="sequence"):
        _project_telemetry_dashboard("RAW-PROMPT-SENTINEL")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="invalid telemetry point"):
        _project_telemetry_dashboard(["RAW-ANSWER-SENTINEL"])  # type: ignore[list-item]
    with pytest.raises(TypeError, match="persona"):
        _project_telemetry_dashboard((), persona="program_lead")  # type: ignore[arg-type]
