"""Bounded presentation events for the buffered public demo response.

The projector deliberately does not model transport or Bedrock token streaming.
Answer deltas are presentation-only slices of an already validated, output-scanned
public summary.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

_SCHEMA = "gluevenir.demo.event.v1"
_DECISIONS = frozenset({"ALLOW", "MODIFY", "STEP_UP", "DEFER", "DENY"})
_ANSWER_DECISIONS = frozenset({"ALLOW", "MODIFY"})
_PENDING_DECISIONS = frozenset({"STEP_UP", "DEFER"})
_REASON = re.compile(r"[A-Z0-9_]{1,48}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_PAYLOAD_KEY = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
_FULL_HASH = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FORBIDDEN_KEYS = (
    "content_hash",
    "credential",
    "detector",
    "excluded_id",
    "prompt",
    "query",
    "restricted",
    "secret",
)

type _PublicScalar = str | int | bool
type _PublicPayload = tuple[tuple[str, _PublicScalar], ...]


class _DemoEventSource(StrEnum):
    CLIENT = "client"
    API = "api"
    PRESENTATION = "presentation"


class _DemoEventType(StrEnum):
    TURN_SUBMITTED = "turn.submitted"
    TRANSPORT_WAITING = "transport.waiting"
    CONTEXT_BOUND = "context.bound"
    POLICY_DECIDED = "policy.decided"
    MEMORY_AUTHORIZED = "memory.authorized"
    BOUNDARY_ENFORCED = "boundary.enforced"
    PENDING_CREATED = "pending.created"
    ANSWER_READY = "answer.ready"
    ANSWER_DELTA = "answer.delta"
    RECEIPT_VERIFIED = "receipt.verified"
    TURN_COMPLETE = "turn.complete"


_EVENT_PAYLOAD_KEYS = {
    _DemoEventType.TURN_SUBMITTED: frozenset(),
    _DemoEventType.TRANSPORT_WAITING: frozenset(),
    _DemoEventType.CONTEXT_BOUND: frozenset(),
    _DemoEventType.POLICY_DECIDED: frozenset({"decision", "reason_code"}),
    _DemoEventType.MEMORY_AUTHORIZED: frozenset({"included_count", "excluded_count"}),
    _DemoEventType.BOUNDARY_ENFORCED: frozenset({"decision", "reason_code"}),
    _DemoEventType.PENDING_CREATED: frozenset({"kind", "pending_action_id"}),
    _DemoEventType.ANSWER_READY: frozenset({"characters"}),
    _DemoEventType.ANSWER_DELTA: frozenset({"index", "text", "final"}),
    _DemoEventType.RECEIPT_VERIFIED: frozenset({"receipt_id", "verified"}),
    _DemoEventType.TURN_COMPLETE: frozenset({"decision"}),
}


@dataclass(frozen=True, slots=True)
class _DemoPublicEvent:
    """One immutable, content-safe event for a single rendered demo turn."""

    turn_id: str | None
    request_id: str | None
    sequence: int
    source: _DemoEventSource
    event_type: _DemoEventType
    public: _PublicPayload = ()

    def __post_init__(self) -> None:
        if self.turn_id is not None:
            _canonical_uuid("turn_id", self.turn_id)
        if self.request_id is not None and not _REQUEST_ID.fullmatch(self.request_id):
            raise ValueError("request_id must be a bounded identifier")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or not 0 <= self.sequence <= 1_000
        ):
            raise ValueError("sequence must be a bounded integer")
        if not isinstance(self.source, _DemoEventSource):
            raise TypeError("source must be a demo event source")
        if not isinstance(self.event_type, _DemoEventType):
            raise TypeError("event_type must be a demo event type")
        if not isinstance(self.public, tuple) or len(self.public) > 8:
            raise TypeError("public payload must be a bounded tuple")
        seen: set[str] = set()
        for item in self.public:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError("public payload items must be key-value tuples")
            name, value = item
            if (
                not isinstance(name, str)
                or not _PAYLOAD_KEY.fullmatch(name)
                or name in seen
                or any(fragment in name for fragment in _FORBIDDEN_KEYS)
            ):
                raise ValueError("public payload key is invalid")
            seen.add(name)
            _public_scalar(value)
        expected = _EVENT_PAYLOAD_KEYS[self.event_type]
        if seen != expected:
            raise ValueError("public payload does not match the event type")

    def as_dict(self) -> dict[str, object]:
        """Return a fresh JSON-compatible representation."""

        return {
            "schema": _SCHEMA,
            "turn_id": self.turn_id,
            "request_id": self.request_id,
            "sequence": self.sequence,
            "source": self.source.value,
            "type": self.event_type.value,
            "state": "complete",
            "public": dict(self.public),
        }


def _pre_response_demo_events(
    *, turn_id: str | None = None, request_id: str | None = None
) -> tuple[_DemoPublicEvent, ...]:
    """Return only facts observable by the client before an API response."""

    return (
        _event(
            turn_id,
            request_id,
            0,
            _DemoEventSource.CLIENT,
            _DemoEventType.TURN_SUBMITTED,
        ),
        _event(
            turn_id,
            request_id,
            1,
            _DemoEventSource.CLIENT,
            _DemoEventType.TRANSPORT_WAITING,
        ),
    )


def _project_validated_demo_events(
    public_result: Mapping[str, object],
    *,
    turn_id: str | None = None,
    request_id: str | None = None,
    reduced_motion: bool = False,
    delta_characters: int = 48,
) -> tuple[_DemoPublicEvent, ...]:
    """Project a validated buffered result into deterministic public UI events."""

    if not isinstance(public_result, Mapping):
        raise TypeError("public_result must be a mapping")
    if type(reduced_motion) is not bool:
        raise TypeError("reduced_motion must be a bool")
    if (
        isinstance(delta_characters, bool)
        or not isinstance(delta_characters, int)
        or not 16 <= delta_characters <= 120
    ):
        raise ValueError("delta_characters must be between 16 and 120")

    decision = public_result.get("decision")
    summary = public_result.get("public_summary")
    receipt = public_result.get("public_receipt")
    if decision not in _DECISIONS:
        raise ValueError("public decision is invalid")
    if (
        type(summary) is not str
        or not summary.strip()
        or len(summary.strip()) > 500
        or _CONTROL_CHARACTER.search(summary)
    ):
        raise ValueError("public summary is invalid")
    if not isinstance(receipt, Mapping):
        raise ValueError("public receipt is invalid")

    reason, receipt_id, included_count, excluded_count = _receipt_facts(
        receipt, decision
    )
    pending_id = public_result.get("pending_action_id")
    if pending_id is not None:
        _canonical_uuid("pending_action_id", pending_id)
    if decision in _PENDING_DECISIONS and pending_id is None:
        raise ValueError("pending decisions require a pending action ID")
    if decision not in _PENDING_DECISIONS and pending_id is not None:
        raise ValueError("only pending decisions may include a pending action ID")

    sequence = 2
    events = [
        _event(
            turn_id,
            request_id,
            sequence,
            _DemoEventSource.API,
            _DemoEventType.CONTEXT_BOUND,
        ),
        _event(
            turn_id,
            request_id,
            sequence + 1,
            _DemoEventSource.API,
            _DemoEventType.POLICY_DECIDED,
            (("decision", decision), ("reason_code", reason)),
        ),
    ]
    sequence += 2

    if decision in _ANSWER_DECISIONS:
        events.append(
            _event(
                turn_id,
                request_id,
                sequence,
                _DemoEventSource.API,
                _DemoEventType.MEMORY_AUTHORIZED,
                (
                    ("included_count", included_count),
                    ("excluded_count", excluded_count),
                ),
            )
        )
        sequence += 1
        normalized = summary.strip()
        events.append(
            _event(
                turn_id,
                request_id,
                sequence,
                _DemoEventSource.API,
                _DemoEventType.ANSWER_READY,
                (("characters", len(normalized)),),
            )
        )
        sequence += 1
        deltas = (
            (normalized,)
            if reduced_motion
            else _presentation_chunks(normalized, delta_characters)
        )
        for index, delta in enumerate(deltas):
            events.append(
                _event(
                    turn_id,
                    request_id,
                    sequence,
                    _DemoEventSource.PRESENTATION,
                    _DemoEventType.ANSWER_DELTA,
                    (
                        ("index", index),
                        ("text", delta),
                        ("final", index == len(deltas) - 1),
                    ),
                )
            )
            sequence += 1
    elif decision in _PENDING_DECISIONS:
        payload: _PublicPayload = (
            ("kind", decision),
            ("pending_action_id", pending_id),
        )
        events.append(
            _event(
                turn_id,
                request_id,
                sequence,
                _DemoEventSource.API,
                _DemoEventType.PENDING_CREATED,
                payload,
            )
        )
        sequence += 1
    else:
        events.append(
            _event(
                turn_id,
                request_id,
                sequence,
                _DemoEventSource.API,
                _DemoEventType.BOUNDARY_ENFORCED,
                (("decision", decision), ("reason_code", reason)),
            )
        )
        sequence += 1

    events.extend(
        (
            _event(
                turn_id,
                request_id,
                sequence,
                _DemoEventSource.API,
                _DemoEventType.RECEIPT_VERIFIED,
                (("receipt_id", receipt_id), ("verified", True)),
            ),
            _event(
                turn_id,
                request_id,
                sequence + 1,
                _DemoEventSource.API,
                _DemoEventType.TURN_COMPLETE,
                (("decision", decision),),
            ),
        )
    )
    return tuple(events)


def _receipt_facts(
    receipt: Mapping[str, object], decision: object
) -> tuple[str, str, int, int]:
    if (
        receipt.get("decision") != decision
        or receipt.get("signature_verified") is not True
    ):
        raise ValueError("public receipt is invalid")
    reason = receipt.get("reason_code")
    receipt_id = receipt.get("receipt_id")
    included_ids = receipt.get("included_memory_ids")
    exclusions = receipt.get("exclusion_counts")
    if type(reason) is not str or not _REASON.fullmatch(reason):
        raise ValueError("public receipt reason is invalid")
    _canonical_uuid("receipt_id", receipt_id)
    if type(included_ids) is not list or len(included_ids) > 5:
        raise ValueError("public included-memory count is invalid")
    if decision in {"DENY", "STEP_UP", "DEFER"} and included_ids:
        raise ValueError("non-executable decisions cannot include memory")
    if type(exclusions) is not dict or len(exclusions) > 4:
        raise ValueError("public exclusion counts are invalid")
    excluded_count = 0
    for name, count in exclusions.items():
        if (
            type(name) is not str
            or not _REASON.fullmatch(name)
            or type(count) is not int
            or not 1 <= count <= 10_000
        ):
            raise ValueError("public exclusion counts are invalid")
        excluded_count += count
    return reason, receipt_id, len(included_ids), excluded_count


def _presentation_chunks(text: str, maximum: int) -> tuple[str, ...]:
    parts = re.findall(r"\S+\s*", text)
    chunks: list[str] = []
    current = ""
    for part in parts:
        if len(part) > maximum:
            if current:
                chunks.append(current)
                current = ""
            chunks.extend(
                part[offset : offset + maximum]
                for offset in range(0, len(part), maximum)
            )
        elif current and len(current) + len(part) > maximum:
            chunks.append(current)
            current = part
        else:
            current += part
    if current:
        chunks.append(current)
    if not chunks or "".join(chunks) != text:
        raise ValueError("public summary could not be projected")
    return tuple(chunks)


def _event(
    turn_id: str | None,
    request_id: str | None,
    sequence: int,
    source: _DemoEventSource,
    event_type: _DemoEventType,
    public: _PublicPayload = (),
) -> _DemoPublicEvent:
    return _DemoPublicEvent(
        turn_id=turn_id,
        request_id=request_id,
        sequence=sequence,
        source=source,
        event_type=event_type,
        public=public,
    )


def _canonical_uuid(name: str, value: object) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be a canonical UUID string")
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError(f"{name} must be a canonical UUID string") from None
    if str(parsed) != value:
        raise ValueError(f"{name} must be a canonical UUID string")
    return value


def _public_scalar(value: object) -> None:
    if type(value) is str:
        if (
            not value
            or len(value) > 500
            or _CONTROL_CHARACTER.search(value)
            or _FULL_HASH.search(value)
        ):
            raise ValueError("public string value is invalid")
    elif type(value) is int:
        if not 0 <= value <= 40_000:
            raise ValueError("public integer value is invalid")
    elif type(value) is not bool:
        raise TypeError("public payload values must be bounded scalars")
