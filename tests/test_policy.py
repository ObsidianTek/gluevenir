from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from gluevenir._policy import (
    _ApprovedDerivative,
    _BioDemoPolicy,
    _Decision,
    _Destination,
    _PolicyAction,
    _PolicyDecision,
    _PolicyFacts,
    _ReasonCode,
)
from gluevenir._ports import MemoryOperation

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
SOURCE_ID = UUID("10000000-0000-4000-8000-000000000001")
DERIVATIVE_ID = UUID("10000000-0000-4000-8000-000000000002")
APPROVAL_ID = UUID("30000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 8, 15, 18, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64


def _action(**changes: object) -> _PolicyAction:
    values: dict[str, object] = {
        "operation": MemoryOperation.RECALL,
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
        "actor_role": "program_lead",
        "purpose": "program_status",
        "audience": "internal-program-lead",
        "destination": _Destination.INTERNAL,
        "policy_version": "bio-demo-v1",
        "requested_memory_ids": (SOURCE_ID,),
        "data_classes": ("IP_CONFIDENTIAL",),
    }
    values.update(changes)
    return _PolicyAction(**values)


def _approval(**changes: object) -> _ApprovedDerivative:
    values: dict[str, object] = {
        "approval_id": APPROVAL_ID,
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
        "source_memory_id": SOURCE_ID,
        "derivative_memory_id": DERIVATIVE_ID,
        "source_sha256": HASH_A,
        "derivative_sha256": HASH_B,
        "purpose": "partner_status",
        "audience": "partner-alpha-synthetic",
        "policy_version": "bio-demo-v1",
        "reviewed_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(days=5),
        "source_active": True,
        "derivative_active": True,
        "reviewed_by": "synthetic-human-reviewer",
        "reviewer_role": "human_reviewer",
    }
    values.update(changes)
    return _ApprovedDerivative(**values)


def _facts(**changes: object) -> _PolicyFacts:
    values: dict[str, object] = {
        "now": NOW,
        "policy_available": True,
        "identity_authorized": True,
    }
    values.update(changes)
    return _PolicyFacts(**values)


def test_all_five_decisions_are_exactly_reachable() -> None:
    policy = _BioDemoPolicy()
    internal = _action()
    external = _action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )
    scenarios = (
        (internal, _facts(), _Decision.ALLOW),
        (internal, _facts(identity_authorized=False), _Decision.DENY),
        (
            external,
            _facts(approved_derivative=_approval()),
            _Decision.MODIFY,
        ),
        (
            external,
            _facts(human_review_allowed=True),
            _Decision.STEP_UP,
        ),
        (
            internal,
            _facts(missing_context=("session_intent",)),
            _Decision.DEFER,
        ),
    )

    decisions = tuple(policy.evaluate(action, facts) for action, facts, _ in scenarios)

    assert tuple(result.decision for result in decisions) == tuple(
        expected for _, _, expected in scenarios
    )
    assert all(isinstance(result.decision, _Decision) for result in decisions)


def test_modify_substitutes_only_exact_approved_derivative() -> None:
    action = _action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )

    result = _BioDemoPolicy().evaluate(
        action,
        _facts(approved_derivative=_approval()),
    )

    assert result == _PolicyDecision(
        _Decision.MODIFY,
        _ReasonCode.EXACT_APPROVED_DERIVATIVE,
        executable_memory_ids=(DERIVATIVE_ID,),
        executable_content_sha256=(HASH_B,),
        approval_resolution_id=APPROVAL_ID,
        resolution_actor_id="synthetic-human-reviewer",
        resolution_actor_role="human_reviewer",
    )
    assert SOURCE_ID not in result.executable_memory_ids


@pytest.mark.parametrize(
    "approval",
    [
        _approval(tenant_id=UUID("22222222-2222-4222-8222-222222222222")),
        _approval(program_id=UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2")),
        _approval(source_memory_id=UUID("10000000-0000-4000-8000-000000000003")),
        _approval(purpose="research_review"),
        _approval(audience="partner-beta-synthetic"),
        _approval(policy_version="other-policy"),
        _approval(reviewed_at=NOW + timedelta(seconds=1)),
        _approval(expires_at=NOW),
        _approval(source_active=False),
        _approval(derivative_active=False),
    ],
)
def test_mismatched_stale_or_future_approval_fails_closed(
    approval: _ApprovedDerivative,
) -> None:
    action = _action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )

    result = _BioDemoPolicy().evaluate(
        action,
        _facts(approved_derivative=approval),
    )

    assert result.decision == _Decision.DENY
    assert result.reason_code == _ReasonCode.APPROVAL_INVALID
    assert not result.executable_memory_ids


def test_unavailable_or_unknown_policy_denies_before_other_outcomes() -> None:
    policy = _BioDemoPolicy()

    unavailable = policy.evaluate(
        _action(),
        _facts(policy_available=False, missing_context=("session_intent",)),
    )
    unknown = policy.evaluate(
        _action(policy_version="unknown"),
        _facts(),
    )

    assert unavailable == _PolicyDecision(
        _Decision.DENY,
        _ReasonCode.POLICY_UNAVAILABLE,
    )
    assert unknown == _PolicyDecision(
        _Decision.DENY,
        _ReasonCode.POLICY_VERSION_INVALID,
    )


def test_external_write_operation_and_unapproved_content_are_denied() -> None:
    external = {
        "audience": "partner-alpha-synthetic",
        "destination": _Destination.EXTERNAL,
        "purpose": "partner_status",
    }
    policy = _BioDemoPolicy()

    write = policy.evaluate(
        _action(operation=MemoryOperation.REMEMBER, **external), _facts()
    )
    unapproved = policy.evaluate(_action(**external), _facts())

    assert write.reason_code == _ReasonCode.EXTERNAL_ACTION_DENIED
    assert unapproved.reason_code == _ReasonCode.EXTERNAL_ACTION_DENIED
    assert write.decision == unapproved.decision == _Decision.DENY


def test_external_allow_is_limited_to_already_approved_memory_class() -> None:
    action = _action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
        requested_memory_ids=(DERIVATIVE_ID,),
        data_classes=("EXTERNAL_APPROVED",),
    )

    result = _BioDemoPolicy().evaluate(action, _facts())

    assert result == _PolicyDecision(
        _Decision.ALLOW,
        _ReasonCode.EXTERNAL_APPROVED_ALLOW,
        executable_memory_ids=(DERIVATIVE_ID,),
    )

    mixed = _BioDemoPolicy().evaluate(
        replace(action, data_classes=("EXTERNAL_APPROVED", "IP_CONFIDENTIAL")),
        _facts(),
    )
    assert mixed.decision == _Decision.DENY


def test_defer_reports_only_sorted_allowlisted_missing_context() -> None:
    result = _BioDemoPolicy().evaluate(
        _action(),
        _facts(
            missing_context=(
                "session_intent",
                "recipient",
                "partner_authorization",
                "destination",
            )
        ),
    )

    assert result.decision == _Decision.DEFER
    assert result.missing_context == (
        "destination",
        "partner_authorization",
        "recipient",
        "session_intent",
    )
    assert not result.executable_memory_ids


def test_policy_values_are_immutable_and_strictly_validated() -> None:
    action = _action()
    with pytest.raises(FrozenInstanceError):
        action.actor_role = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError):
        _action(requested_memory_ids=(SOURCE_ID, SOURCE_ID))
    with pytest.raises(ValueError):
        _action(data_classes=("LEGAL_CONCLUSION",))
    with pytest.raises(ValueError):
        _facts(missing_context=("raw_request",))
    with pytest.raises(ValueError):
        replace(_approval(), derivative_sha256="bad")
    with pytest.raises(ValueError):
        _PolicyDecision(
            _Decision.STEP_UP,
            _ReasonCode.HUMAN_APPROVAL_REQUIRED,
            executable_memory_ids=(DERIVATIVE_ID,),
        )
    with pytest.raises(ValueError):
        _PolicyDecision(
            _Decision.MODIFY,
            _ReasonCode.EXACT_APPROVED_DERIVATIVE,
            executable_memory_ids=(DERIVATIVE_ID,),
        )
