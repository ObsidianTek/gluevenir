from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from gluevenir._gateway import (
    _GatewayAction,
    _GatewayUnavailable,
    _hash_action_arguments,
    _MemoryActionGateway,
    _PreparedAction,
    _ResponseStatus,
    _StepUpResolution,
)
from gluevenir._pending_store import (
    _PendingActionRecord,
    _PendingState,
    _PendingTransition,
)
from gluevenir._policy import (
    _ApprovedDerivative,
    _BioDemoPolicy,
    _Decision,
    _Destination,
    _PolicyAction,
    _PolicyFacts,
    _ReasonCode,
)
from gluevenir._ports import MemoryOperation

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
SOURCE_ID = UUID("10000000-0000-4000-8000-000000000001")
DERIVATIVE_ID = UUID("10000000-0000-4000-8000-000000000002")
APPROVAL_ID = UUID("30000000-0000-4000-8000-000000000001")
REQUEST_ID = UUID("50000000-0000-4000-8000-000000000001")
SESSION_ID = UUID("60000000-0000-4000-8000-000000000001")
INTENT_ID = UUID("70000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 8, 15, 18, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
ARGUMENTS = {"query_sha256": "c" * 64, "top_k": 4}


class _FakeClock:
    def __init__(self) -> None:
        self.current = NOW

    def now(self) -> datetime:
        return self.current


class _FakeExecutor:
    def __init__(self, *, fails: bool = False) -> None:
        self.fails = fails
        self.calls: list[dict[str, object]] = []

    def prepare(
        self,
        *,
        executable_memory_ids: tuple[UUID, ...],
        expected_content_sha256: tuple[str, ...],
        **_values: object,
    ) -> _PreparedAction:
        hashes = expected_content_sha256 or (HASH_A,) * len(executable_memory_ids)
        return _PreparedAction(executable_memory_ids, hashes, "synthetic-prepared")

    def execute(self, **values: object) -> object:
        prepared = values["prepared"]
        assert isinstance(prepared, _PreparedAction)
        self.calls.append(
            {
                **values,
                "executable_memory_ids": prepared.memory_ids,
                "expected_content_sha256": prepared.content_sha256,
            }
        )
        if self.fails:
            raise RuntimeError("raw model failure must not escape")
        return {"status": "synthetic-complete"}


class _FakeReceiptSink:
    def __init__(self, *, fails: bool = False) -> None:
        self.fails = fails
        self.calls: list[dict[str, object]] = []
        self._next_id = 1

    def build(self, **values: object) -> _FakeSignedReceipt:
        if self.fails:
            raise RuntimeError("receipt backend detail")
        receipt = _FakeSignedReceipt(
            _FakeReceiptPayload(UUID(int=self._next_id)),
            dict(values),
        )
        self._next_id += 1
        return receipt

    def persist_in_transaction(
        self,
        _connection: object,
        receipt: _FakeSignedReceipt,
    ) -> None:
        if self.fails:
            raise RuntimeError("receipt backend detail")
        self.calls.append(receipt.values)

    def record(self, **values: object) -> UUID:
        receipt = self.build(**values)
        self.persist_in_transaction(object(), receipt)
        return receipt.payload.receipt_id


@dataclass(frozen=True)
class _FakeReceiptPayload:
    receipt_id: UUID


@dataclass(frozen=True)
class _FakeSignedReceipt:
    payload: _FakeReceiptPayload
    values: dict[str, object]


class _FakePendingStore:
    def __init__(self) -> None:
        self.records: dict[UUID, _PendingActionRecord] = {}
        self.terminal: dict[UUID, _PendingState] = {}

    def create(
        self,
        record: _PendingActionRecord,
        *,
        persist_evaluation_receipt: object,
    ) -> _PendingActionRecord:
        existing = self.records.get(record.pending_action_id)
        if existing is not None:
            if existing == record:
                return existing
            raise RuntimeError("collision")
        persist_evaluation_receipt(object())
        self.records[record.pending_action_id] = record
        return record

    def load_pending(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
        pending_action_id: UUID,
    ) -> _PendingActionRecord | None:
        record = self.records.get(pending_action_id)
        if record is None:
            return None
        if record.tenant_id != tenant_id or record.program_id != program_id:
            return None
        return record

    def list_expired(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
        now: datetime,
        limit: int = 64,
    ) -> tuple[_PendingActionRecord, ...]:
        return tuple(
            sorted(
                (
                    record
                    for record in self.records.values()
                    if record.tenant_id == tenant_id
                    and record.program_id == program_id
                    and record.expires_at <= now
                ),
                key=lambda record: (record.expires_at, record.pending_action_id.int),
            )[:limit]
        )

    def transition(
        self,
        transition: _PendingTransition,
        *,
        persist_transition_receipt: object,
    ) -> None:
        record = transition.record
        if self.records.get(record.pending_action_id) != record:
            raise RuntimeError("transition conflict")
        persist_transition_receipt(object())
        del self.records[record.pending_action_id]
        self.terminal[record.pending_action_id] = transition.state


class _RaisingPolicy(_BioDemoPolicy):
    def evaluate(self, action: _PolicyAction, facts: _PolicyFacts):
        del action, facts
        raise RuntimeError("policy backend detail")


def _policy_action(**changes: object) -> _PolicyAction:
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


def _action(**changes: object) -> _GatewayAction:
    values: dict[str, object] = {
        "request_id": REQUEST_ID,
        "session_id": SESSION_ID,
        "intent_id": INTENT_ID,
        "agent_id": "gluevenir-bio",
        "actor_id": "synthetic-program-lead",
        "evaluated_at": NOW,
        "action_arguments_sha256": _hash_action_arguments(ARGUMENTS),
        "original_intent_sha256": HASH_A,
        "prior_action_context_sha256": HASH_B,
        "policy": _policy_action(),
    }
    values.update(changes)
    return _GatewayAction(**values)


def _approval() -> _ApprovedDerivative:
    return _ApprovedDerivative(
        approval_id=APPROVAL_ID,
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        source_memory_id=SOURCE_ID,
        derivative_memory_id=DERIVATIVE_ID,
        source_sha256=HASH_A,
        derivative_sha256=HASH_B,
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        policy_version="bio-demo-v1",
        reviewed_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(days=5),
        source_active=True,
        derivative_active=True,
        reviewed_by="synthetic-human-reviewer",
        reviewer_role="human_reviewer",
    )


def _resolution(*, approved: bool = True) -> _StepUpResolution:
    return _StepUpResolution(
        approval_id=APPROVAL_ID,
        reviewer_id="synthetic-human-reviewer",
        reviewer_role="human_reviewer",
        approved=approved,
        resolved_at=NOW - timedelta(minutes=1),
    )


def _facts(**changes: object) -> _PolicyFacts:
    values: dict[str, object] = {
        "now": NOW,
        "policy_available": True,
        "identity_authorized": True,
    }
    values.update(changes)
    return _PolicyFacts(**values)


def _gateway(
    *,
    policy: _BioDemoPolicy | None = None,
    executor: _FakeExecutor | None = None,
    sink: _FakeReceiptSink | None = None,
    clock: _FakeClock | None = None,
    pending_store: _FakePendingStore | None = None,
) -> tuple[_MemoryActionGateway, _FakeExecutor, _FakeReceiptSink, _FakeClock]:
    actual_executor = executor or _FakeExecutor()
    actual_sink = sink or _FakeReceiptSink()
    actual_clock = clock or _FakeClock()
    return (
        _MemoryActionGateway(
            policy=policy or _BioDemoPolicy(),
            executor=actual_executor,
            receipt_sink=actual_sink,
            pending_store=pending_store or _FakePendingStore(),
            clock=actual_clock,
        ),
        actual_executor,
        actual_sink,
        actual_clock,
    )


def test_allow_records_before_execution_and_separate_completion() -> None:
    gateway, executor, sink, _ = _gateway()

    result = gateway.execute(
        action=_action(), action_arguments=ARGUMENTS, facts=_facts()
    )

    assert result.decision == _Decision.ALLOW
    assert result.response_status == _ResponseStatus.COMPLETED
    assert result.output == {"status": "synthetic-complete"}
    assert len(executor.calls) == 1
    assert len(sink.calls) == 2
    assert sink.calls[0]["response_status"] == _ResponseStatus.PENDING
    assert sink.calls[0]["decision"].executable_content_sha256 == (HASH_A,)
    assert sink.calls[1]["response_status"] == _ResponseStatus.COMPLETED
    assert sink.calls[1]["resolution_of"] == result.evaluation_receipt_id


def test_allow_receipts_bind_source_hash_and_separate_model_prompt_hash() -> None:
    class _PromptBoundExecutor(_FakeExecutor):
        def prepare(self, **values: object) -> _PreparedAction:
            prepared = super().prepare(**values)
            return _PreparedAction(
                prepared.memory_ids,
                prepared.content_sha256,
                prepared.payload,
                model_prompt_sha256=HASH_B,
            )

    gateway, _, sink, _ = _gateway(executor=_PromptBoundExecutor())

    result = gateway.execute(
        action=_action(), action_arguments=ARGUMENTS, facts=_facts()
    )

    assert result.response_status == _ResponseStatus.COMPLETED
    for call in sink.calls:
        assert call["decision"].executable_content_sha256 == (HASH_A,)
        assert call["decision"].model_prompt_sha256 == HASH_B


def test_prepare_outside_authorized_set_fails_before_execution() -> None:
    class _WrongPreparedExecutor(_FakeExecutor):
        def prepare(self, **_values: object) -> _PreparedAction:
            return _PreparedAction(
                (DERIVATIVE_ID,),
                (HASH_B,),
                "unauthorized-prepared",
            )

    executor = _WrongPreparedExecutor()
    gateway, _, sink, _ = _gateway(executor=executor)

    result = gateway.execute(
        action=_action(), action_arguments=ARGUMENTS, facts=_facts()
    )

    assert result.response_status == _ResponseStatus.FAILED
    assert executor.calls == []
    assert len(sink.calls) == 1
    assert sink.calls[0]["response_status"] == _ResponseStatus.FAILED


def test_modify_executes_only_the_exact_derivative_id() -> None:
    policy_action = _policy_action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )
    gateway, executor, _, _ = _gateway()

    result = gateway.execute(
        action=_action(policy=policy_action),
        action_arguments=ARGUMENTS,
        facts=_facts(approved_derivative=_approval()),
    )

    assert result.decision == _Decision.MODIFY
    assert executor.calls[0]["executable_memory_ids"] == (DERIVATIVE_ID,)
    assert SOURCE_ID not in executor.calls[0]["executable_memory_ids"]


@pytest.mark.parametrize(
    ("facts", "decision"),
    [
        (_facts(identity_authorized=False), _Decision.DENY),
        (_facts(human_review_allowed=True), _Decision.STEP_UP),
        (_facts(missing_context=("session_intent",)), _Decision.DEFER),
    ],
)
def test_non_executable_decisions_have_zero_executor_side_effects(
    facts: _PolicyFacts,
    decision: _Decision,
) -> None:
    action = _action()
    if decision == _Decision.STEP_UP:
        action = _action(
            policy=_policy_action(
                purpose="partner_status",
                audience="partner-alpha-synthetic",
                destination=_Destination.EXTERNAL,
            )
        )
    gateway, executor, sink, _ = _gateway()

    result = gateway.execute(action=action, action_arguments=ARGUMENTS, facts=facts)

    assert result.decision == decision
    assert executor.calls == []
    assert len(sink.calls) == 1
    assert result.output is None


def test_pending_store_never_stores_raw_action_arguments() -> None:
    gateway, _, _, _ = _gateway()
    action = _action()

    gateway.execute(
        action=action,
        action_arguments=ARGUMENTS,
        facts=_facts(missing_context=("session_intent",)),
    )

    stored = gateway._pending_store.records[REQUEST_ID]
    assert not hasattr(stored, "action_arguments")
    assert "query_sha256" not in repr(stored)


def test_pending_timeout_defaults_to_deny_without_execution() -> None:
    gateway, executor, sink, clock = _gateway()
    pending = gateway.execute(
        action=_action(),
        action_arguments=ARGUMENTS,
        facts=_facts(missing_context=("session_intent",)),
    )
    clock.current = NOW + timedelta(minutes=11)

    expired = gateway.expire_pending(tenant_id=TENANT_ID, program_id=PROGRAM_ID)

    assert pending.pending_action_id == REQUEST_ID
    assert len(expired) == 1
    assert expired[0].decision == _Decision.DENY
    assert expired[0].reason_code == _ReasonCode.PENDING_TIMEOUT
    assert executor.calls == []
    assert REQUEST_ID not in gateway._pending_store.records
    assert gateway._pending_store.terminal[REQUEST_ID] == _PendingState.EXPIRED
    assert sink.calls[-1]["resolution_of"] == pending.evaluation_receipt_id


def test_step_up_approval_resumes_only_as_exact_hash_bound_modify() -> None:
    external = _policy_action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )
    gateway, executor, sink, _ = _gateway()
    pending = gateway.execute(
        action=_action(policy=external),
        action_arguments=ARGUMENTS,
        facts=_facts(human_review_allowed=True),
    )

    result = gateway.resolve(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=REQUEST_ID,
        action_arguments=ARGUMENTS,
        facts=_facts(approved_derivative=_approval()),
        step_up_resolution=_resolution(),
    )

    assert pending.decision == _Decision.STEP_UP
    assert result.decision == _Decision.MODIFY
    assert result.response_status == _ResponseStatus.COMPLETED
    assert executor.calls[0]["executable_memory_ids"] == (DERIVATIVE_ID,)
    assert SOURCE_ID not in executor.calls[0]["executable_memory_ids"]
    assert sink.calls[1]["decision"].executable_content_sha256 == (HASH_B,)
    assert executor.calls[0]["expected_content_sha256"] == (HASH_B,)
    assert len(sink.calls) == 3
    assert all(
        call["resolution_of"] == pending.evaluation_receipt_id
        for call in sink.calls[1:]
    )
    assert REQUEST_ID not in gateway._pending_store.records
    assert gateway._pending_store.terminal[REQUEST_ID] == _PendingState.CONSUMED


@pytest.mark.parametrize("step_up_resolution", [_resolution(approved=False), None])
def test_step_up_rejection_or_unresolved_approval_denies_without_execution(
    step_up_resolution: _StepUpResolution | None,
) -> None:
    external = _policy_action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )
    gateway, executor, sink, _ = _gateway()
    pending = gateway.execute(
        action=_action(policy=external),
        action_arguments=ARGUMENTS,
        facts=_facts(human_review_allowed=True),
    )

    result = gateway.resolve(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=REQUEST_ID,
        action_arguments=ARGUMENTS,
        facts=_facts(approved_derivative=_approval()),
        step_up_resolution=step_up_resolution,
    )

    assert result.decision == _Decision.DENY
    assert result.response_status == _ResponseStatus.DENIED
    assert executor.calls == []
    assert sink.calls[-1]["resolution_of"] == pending.evaluation_receipt_id
    assert REQUEST_ID not in gateway._pending_store.records


@pytest.mark.parametrize(
    "facts",
    [
        _facts(),
        _facts(approved_derivative=replace(_approval(), source_active=False)),
        _facts(policy_available=False),
        _facts(human_review_allowed=True),
    ],
)
def test_step_up_invalid_or_unresolved_reevaluation_denies(
    facts: _PolicyFacts,
) -> None:
    external = _policy_action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )
    gateway, executor, _, _ = _gateway()
    gateway.execute(
        action=_action(policy=external),
        action_arguments=ARGUMENTS,
        facts=_facts(human_review_allowed=True),
    )

    result = gateway.resolve(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=REQUEST_ID,
        action_arguments=ARGUMENTS,
        facts=facts,
        step_up_resolution=_resolution(),
    )

    assert result.decision == _Decision.DENY
    assert executor.calls == []
    assert REQUEST_ID not in gateway._pending_store.records


def test_step_up_reviewer_role_must_match_authoritative_approval() -> None:
    external = _policy_action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )
    gateway, executor, _, _ = _gateway()
    gateway.execute(
        action=_action(policy=external),
        action_arguments=ARGUMENTS,
        facts=_facts(human_review_allowed=True),
    )

    result = gateway.resolve(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=REQUEST_ID,
        action_arguments=ARGUMENTS,
        facts=_facts(approved_derivative=_approval()),
        step_up_resolution=replace(_resolution(), reviewer_role="program_lead"),
    )

    assert result.decision == _Decision.DENY
    assert result.reason_code == _ReasonCode.PENDING_UNRESOLVED
    assert executor.calls == []


def test_defer_resumes_only_after_required_context_clears() -> None:
    gateway, executor, sink, _ = _gateway()
    pending = gateway.execute(
        action=_action(),
        action_arguments=ARGUMENTS,
        facts=_facts(missing_context=("session_intent",)),
    )
    gateway._clock.current = NOW + timedelta(minutes=1)

    result = gateway.resolve(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=REQUEST_ID,
        action_arguments=ARGUMENTS,
        facts=_facts(),
    )

    assert result.decision == _Decision.ALLOW
    assert result.response_status == _ResponseStatus.COMPLETED
    assert len(executor.calls) == 1
    assert executor.calls[0]["action"].evaluated_at == NOW + timedelta(minutes=1)
    assert all(
        call["resolution_of"] == pending.evaluation_receipt_id
        for call in sink.calls[1:]
    )
    assert REQUEST_ID not in gateway._pending_store.records


def test_pending_action_resolves_once_after_gateway_restart() -> None:
    pending_store = _FakePendingStore()
    sink = _FakeReceiptSink()
    clock = _FakeClock()
    first, _, _, _ = _gateway(
        pending_store=pending_store,
        sink=sink,
        clock=clock,
    )
    pending = first.execute(
        action=_action(),
        action_arguments=ARGUMENTS,
        facts=_facts(missing_context=("session_intent",)),
    )

    executor = _FakeExecutor()
    restarted, _, _, _ = _gateway(
        pending_store=pending_store,
        sink=sink,
        clock=clock,
        executor=executor,
    )
    result = restarted.resolve(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=REQUEST_ID,
        action_arguments=ARGUMENTS,
        facts=_facts(),
    )

    assert result.response_status == _ResponseStatus.COMPLETED
    assert result.evaluation_receipt_id == pending.evaluation_receipt_id
    assert len(executor.calls) == 1
    assert pending_store.terminal[REQUEST_ID] == _PendingState.CONSUMED
    with pytest.raises(_GatewayUnavailable, match="unavailable"):
        restarted.resolve(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=REQUEST_ID,
            action_arguments=ARGUMENTS,
            facts=_facts(),
        )
    assert len(executor.calls) == 1


def test_defer_with_still_missing_context_denies_without_execution() -> None:
    gateway, executor, sink, _ = _gateway()
    pending = gateway.execute(
        action=_action(),
        action_arguments=ARGUMENTS,
        facts=_facts(missing_context=("session_intent",)),
    )

    result = gateway.resolve(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=REQUEST_ID,
        action_arguments=ARGUMENTS,
        facts=_facts(missing_context=("session_intent",)),
    )

    assert result.decision == _Decision.DENY
    assert result.reason_code == _ReasonCode.PENDING_UNRESOLVED
    assert executor.calls == []
    assert sink.calls[-1]["resolution_of"] == pending.evaluation_receipt_id
    assert REQUEST_ID not in gateway._pending_store.records


def test_defer_argument_change_denies_once_and_cleans_pending_record() -> None:
    gateway, executor, sink, _ = _gateway()
    pending = gateway.execute(
        action=_action(),
        action_arguments=ARGUMENTS,
        facts=_facts(missing_context=("session_intent",)),
    )

    result = gateway.resolve(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=REQUEST_ID,
        action_arguments={"query_sha256": "d" * 64, "top_k": 4},
        facts=_facts(),
    )

    assert result.decision == _Decision.DENY
    assert executor.calls == []
    assert sink.calls[-1]["resolution_of"] == pending.evaluation_receipt_id
    assert REQUEST_ID not in gateway._pending_store.records
    with pytest.raises(_GatewayUnavailable, match="unavailable"):
        gateway.resolve(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=REQUEST_ID,
            action_arguments=ARGUMENTS,
            facts=_facts(),
        )


def test_resolution_receipt_failure_prevents_executor_side_effects() -> None:
    external = _policy_action(
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        destination=_Destination.EXTERNAL,
    )
    sink = _FakeReceiptSink()
    gateway, executor, _, _ = _gateway(sink=sink)
    gateway.execute(
        action=_action(policy=external),
        action_arguments=ARGUMENTS,
        facts=_facts(human_review_allowed=True),
    )
    sink.fails = True

    with pytest.raises(_GatewayUnavailable, match="failed closed"):
        gateway.resolve(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=REQUEST_ID,
            action_arguments=ARGUMENTS,
            facts=_facts(approved_derivative=_approval()),
            step_up_resolution=_resolution(),
        )

    assert executor.calls == []
    assert REQUEST_ID in gateway._pending_store.records


def test_policy_exception_fails_closed_with_denial_receipt() -> None:
    gateway, executor, sink, _ = _gateway(policy=_RaisingPolicy())

    result = gateway.execute(
        action=_action(), action_arguments=ARGUMENTS, facts=_facts()
    )

    assert result.decision == _Decision.DENY
    assert result.reason_code == _ReasonCode.POLICY_UNAVAILABLE
    assert result.response_status == _ResponseStatus.DENIED
    assert executor.calls == []
    assert len(sink.calls) == 1


def test_receipt_failure_prevents_execution_and_is_sanitized() -> None:
    gateway, executor, _, _ = _gateway(sink=_FakeReceiptSink(fails=True))

    with pytest.raises(_GatewayUnavailable, match="failed closed") as error:
        gateway.execute(action=_action(), action_arguments=ARGUMENTS, facts=_facts())

    assert executor.calls == []
    assert error.value.__cause__ is None


def test_executor_failure_records_content_free_failure_resolution() -> None:
    gateway, executor, sink, _ = _gateway(executor=_FakeExecutor(fails=True))

    result = gateway.execute(
        action=_action(), action_arguments=ARGUMENTS, facts=_facts()
    )

    assert len(executor.calls) == 1
    assert result.response_status == _ResponseStatus.FAILED
    assert result.output is None
    assert sink.calls[-1]["response_status"] == _ResponseStatus.FAILED
    assert "raw model failure" not in repr(result)


def test_action_arguments_are_canonical_bounded_and_hash_bound() -> None:
    assert _hash_action_arguments({"b": 2, "a": 1}) == _hash_action_arguments(
        {"a": 1, "b": 2}
    )
    gateway, executor, sink, _ = _gateway()
    with pytest.raises(ValueError, match="do not match"):
        gateway.execute(
            action=_action(),
            action_arguments={"query_sha256": "d" * 64, "top_k": 4},
            facts=_facts(),
        )
    assert executor.calls == []
    assert sink.calls == []
    with pytest.raises(TypeError):
        _hash_action_arguments({"score": 0.5})
    with pytest.raises(ValueError):
        _hash_action_arguments({"text": "x" * 2_001})
