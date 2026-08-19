from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from gluevenir._demo_events import (
    _DemoEventSource,
    _DemoEventType,
    _DemoPublicEvent,
    _pre_response_demo_events,
    _project_validated_demo_events,
)

TURN_ID = "90000000-0000-4000-8000-000000000001"
REQUEST_ID = "request-1"
RECEIPT_ID = "40000000-0000-4000-8000-000000000001"
MEMORY_ID = "10000000-0000-4000-8000-000000000001"
HASH = "a" * 64
SUMMARY = "Synthetic HX-17 stability work remains on schedule for this demo."


def _result(decision: str = "ALLOW", **changes: object) -> dict[str, object]:
    included = [MEMORY_ID] if decision in {"ALLOW", "MODIFY"} else []
    value: dict[str, object] = {
        "decision": decision,
        "public_summary": SUMMARY,
        "public_receipt": {
            "receipt_id": RECEIPT_ID,
            "decision": decision,
            "reason_code": f"SYNTHETIC_{decision}",
            "included_memory_ids": included,
            "included_content_sha256": [HASH] if included else [],
            "action_arguments_sha256": HASH,
            "policy_sha256": HASH,
            "exclusion_counts": {"OUT_OF_SCOPE": 2},
            "agent_signing_key_id": "demo-key",
            "signature_verified": True,
        },
    }
    value.update(changes)
    return value


def _types(events: tuple[_DemoPublicEvent, ...]) -> list[_DemoEventType]:
    return [event.event_type for event in events]


def test_pre_response_events_claim_only_client_observable_facts() -> None:
    events = _pre_response_demo_events(turn_id=TURN_ID)

    assert _types(events) == [
        _DemoEventType.TURN_SUBMITTED,
        _DemoEventType.TRANSPORT_WAITING,
    ]
    assert [event.sequence for event in events] == [0, 1]
    assert all(event.source == _DemoEventSource.CLIENT for event in events)
    assert all(event.request_id is None and event.public == () for event in events)
    assert all("timestamp" not in event.as_dict() for event in events)


def test_correlation_identifiers_are_optional() -> None:
    pre = _pre_response_demo_events()
    post = _project_validated_demo_events(_result(), reduced_motion=True)

    assert all(event.turn_id is None and event.request_id is None for event in pre)
    assert all(event.turn_id is None and event.request_id is None for event in post)


@pytest.mark.parametrize("decision", ["ALLOW", "MODIFY"])
def test_authorized_result_projects_only_post_scan_answer_deltas(decision: str) -> None:
    events = _project_validated_demo_events(
        _result(decision),
        turn_id=TURN_ID,
        request_id=REQUEST_ID,
        delta_characters=24,
    )

    assert _types(events)[:4] == [
        _DemoEventType.CONTEXT_BOUND,
        _DemoEventType.POLICY_DECIDED,
        _DemoEventType.MEMORY_AUTHORIZED,
        _DemoEventType.ANSWER_READY,
    ]
    assert _types(events)[-2:] == [
        _DemoEventType.RECEIPT_VERIFIED,
        _DemoEventType.TURN_COMPLETE,
    ]
    deltas = [
        dict(event.public)["text"]
        for event in events
        if event.event_type == _DemoEventType.ANSWER_DELTA
    ]
    assert len(deltas) > 1
    assert "".join(deltas) == SUMMARY
    assert all(
        event.source == _DemoEventSource.PRESENTATION
        for event in events
        if event.event_type == _DemoEventType.ANSWER_DELTA
    )
    rendered = [event.as_dict() for event in events]
    assert HASH not in str(rendered)
    assert MEMORY_ID not in str(rendered)
    assert [event.sequence for event in events] == list(range(2, 2 + len(events)))


def test_reduced_motion_emits_one_complete_presentation_delta() -> None:
    events = _project_validated_demo_events(
        _result(),
        turn_id=TURN_ID,
        reduced_motion=True,
    )

    deltas = [
        event for event in events if event.event_type == _DemoEventType.ANSWER_DELTA
    ]
    assert len(deltas) == 1
    assert dict(deltas[0].public) == {"index": 0, "text": SUMMARY, "final": True}


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        ("DENY", _DemoEventType.BOUNDARY_ENFORCED),
        ("STEP_UP", _DemoEventType.PENDING_CREATED),
        ("DEFER", _DemoEventType.PENDING_CREATED),
    ],
)
def test_non_executable_results_never_emit_answer_events(
    decision: str, expected: _DemoEventType
) -> None:
    changes = (
        {"pending_action_id": "80000000-0000-4000-8000-000000000001"}
        if decision in {"STEP_UP", "DEFER"}
        else {}
    )
    events = _project_validated_demo_events(
        _result(decision, **changes), turn_id=TURN_ID
    )

    assert expected in _types(events)
    assert _DemoEventType.ANSWER_READY not in _types(events)
    assert _DemoEventType.ANSWER_DELTA not in _types(events)
    assert _DemoEventType.MEMORY_AUTHORIZED not in _types(events)


def test_pending_id_is_opaque_and_limited_to_pending_event() -> None:
    pending_id = "80000000-0000-4000-8000-000000000001"
    events = _project_validated_demo_events(
        _result("STEP_UP", pending_action_id=pending_id), turn_id=TURN_ID
    )

    pending = next(
        event for event in events if event.event_type == _DemoEventType.PENDING_CREATED
    )
    assert dict(pending.public) == {
        "kind": "STEP_UP",
        "pending_action_id": pending_id,
    }
    assert sum(pending_id in str(event.as_dict()) for event in events) == 1


def test_projection_is_deterministic_and_events_are_frozen() -> None:
    first = _project_validated_demo_events(_result(), turn_id=TURN_ID)
    second = _project_validated_demo_events(_result(), turn_id=TURN_ID)

    assert first == second
    with pytest.raises(FrozenInstanceError):
        first[0].sequence = 99  # type: ignore[misc]


@pytest.mark.parametrize(
    "value",
    [
        _result("UNKNOWN"),
        _result(public_summary=""),
        _result(public_summary="x" * 501),
        _result(public_receipt={}),
        _result("DENY", pending_action_id=TURN_ID),
        _result("STEP_UP"),
        _result("DEFER"),
    ],
)
def test_invalid_or_unbounded_results_are_rejected(value: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError)):
        _project_validated_demo_events(value, turn_id=TURN_ID)


def test_event_model_rejects_hashes_and_sensitive_payload_keys() -> None:
    with pytest.raises(ValueError, match="string value"):
        _DemoPublicEvent(
            TURN_ID,
            None,
            0,
            _DemoEventSource.PRESENTATION,
            _DemoEventType.ANSWER_DELTA,
            (("index", 0), ("text", f"unsafe {HASH}"), ("final", True)),
        )
    with pytest.raises(ValueError, match="payload key"):
        _DemoPublicEvent(
            TURN_ID,
            None,
            0,
            _DemoEventSource.API,
            _DemoEventType.CONTEXT_BOUND,
            (("raw_prompt", "synthetic"),),
        )


def test_pending_event_requires_a_canonical_pending_action_id() -> None:
    with pytest.raises(ValueError, match="payload does not match"):
        _DemoPublicEvent(
            TURN_ID,
            None,
            2,
            _DemoEventSource.API,
            _DemoEventType.PENDING_CREATED,
            (("kind", "STEP_UP"),),
        )
