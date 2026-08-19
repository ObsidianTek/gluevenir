"""Private fail-closed Memory Action Gateway orchestration."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from sqlalchemy import Connection

from gluevenir._pending_store import (
    _PendingActionRecord,
    _PendingState,
    _PendingTransition,
)
from gluevenir._policy import (
    _BioDemoPolicy,
    _Decision,
    _PolicyAction,
    _PolicyDecision,
    _PolicyFacts,
    _ReasonCode,
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_MAX_ARGUMENT_BYTES = 16_384
_AUTHORIZED_REVIEWER_ROLES = frozenset({"human_reviewer", "program_lead"})


class _ResponseStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    normalized = value.strip()
    if not _IDENTIFIER_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a bounded identifier")
    return normalized


def _uuid(name: str, value: object) -> UUID:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be a UUID")
    return value


def _digest(name: str, value: object) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _aware(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


@dataclass(frozen=True, slots=True)
class _GatewayAction:
    request_id: UUID
    session_id: UUID
    intent_id: UUID
    agent_id: str
    actor_id: str
    evaluated_at: datetime
    action_arguments_sha256: str
    original_intent_sha256: str
    prior_action_context_sha256: str
    policy: _PolicyAction

    def __post_init__(self) -> None:
        for name in ("request_id", "session_id", "intent_id"):
            _uuid(name, getattr(self, name))
        object.__setattr__(self, "agent_id", _identifier("agent_id", self.agent_id))
        object.__setattr__(self, "actor_id", _identifier("actor_id", self.actor_id))
        _aware("evaluated_at", self.evaluated_at)
        for name in (
            "action_arguments_sha256",
            "original_intent_sha256",
            "prior_action_context_sha256",
        ):
            _digest(name, getattr(self, name))
        if not isinstance(self.policy, _PolicyAction):
            raise TypeError("policy must be a _PolicyAction")


@dataclass(frozen=True, slots=True)
class _GatewayResult:
    decision: _Decision
    reason_code: _ReasonCode
    response_status: _ResponseStatus
    evaluation_receipt_id: UUID
    resolution_receipt_id: UUID | None = None
    pending_action_id: UUID | None = None
    output: object | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, _Decision):
            raise TypeError("decision must be a _Decision")
        if not isinstance(self.reason_code, _ReasonCode):
            raise TypeError("reason_code must be a _ReasonCode")
        if not isinstance(self.response_status, _ResponseStatus):
            raise TypeError("response_status must be a _ResponseStatus")
        _uuid("evaluation_receipt_id", self.evaluation_receipt_id)
        if self.resolution_receipt_id is not None:
            _uuid("resolution_receipt_id", self.resolution_receipt_id)
        if self.pending_action_id is not None:
            _uuid("pending_action_id", self.pending_action_id)
        is_pending = self.decision in {_Decision.STEP_UP, _Decision.DEFER}
        if is_pending != (self.pending_action_id is not None):
            raise ValueError("pending decisions require exactly one pending action ID")
        if self.decision in {_Decision.DENY, _Decision.STEP_UP, _Decision.DEFER}:
            if self.output is not None:
                raise ValueError("non-executable decisions cannot return output")


@dataclass(frozen=True, slots=True)
class _StepUpResolution:
    """Trusted server-side representation of one human approval decision."""

    approval_id: UUID
    reviewer_id: str
    reviewer_role: str
    approved: bool
    resolved_at: datetime

    def __post_init__(self) -> None:
        _uuid("approval_id", self.approval_id)
        object.__setattr__(
            self, "reviewer_id", _identifier("reviewer_id", self.reviewer_id)
        )
        object.__setattr__(
            self, "reviewer_role", _identifier("reviewer_role", self.reviewer_role)
        )
        if self.reviewer_role not in _AUTHORIZED_REVIEWER_ROLES:
            raise ValueError("reviewer_role is not authorized for approval")
        if type(self.approved) is not bool:
            raise TypeError("approved must be a bool")
        _aware("resolved_at", self.resolved_at)


@dataclass(frozen=True, slots=True)
class _PreparedAction:
    """Authorized records prepared before any model/tool/external side effect."""

    memory_ids: tuple[UUID, ...]
    content_sha256: tuple[str, ...]
    payload: object
    model_prompt_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.memory_ids, tuple):
            raise TypeError("memory_ids must be a tuple")
        if not isinstance(self.content_sha256, tuple):
            raise TypeError("content_sha256 must be a tuple")
        if len(self.memory_ids) > 5 or len(self.memory_ids) != len(self.content_sha256):
            raise ValueError("prepared memory IDs and hashes must be bounded and agree")
        if len(set(self.memory_ids)) != len(self.memory_ids):
            raise ValueError("prepared memory IDs must be unique")
        for memory_id in self.memory_ids:
            _uuid("prepared memory ID", memory_id)
        for content_hash in self.content_sha256:
            _digest("prepared content hash", content_hash)
        if self.model_prompt_sha256 is not None:
            _digest("prepared model prompt hash", self.model_prompt_sha256)


@dataclass(frozen=True, slots=True)
class _ReceiptRecord:
    receipt_id: UUID
    action: _GatewayAction
    decision: _PolicyDecision
    response_status: _ResponseStatus
    resolution_of: UUID | None


class _Clock(Protocol):
    def now(self) -> datetime: ...


class _Executor(Protocol):
    def prepare(
        self,
        *,
        action: _GatewayAction,
        executable_memory_ids: tuple[UUID, ...],
        expected_content_sha256: tuple[str, ...],
        action_arguments: Mapping[str, object],
    ) -> _PreparedAction: ...

    def execute(
        self,
        *,
        action: _GatewayAction,
        prepared: _PreparedAction,
        action_arguments: Mapping[str, object],
    ) -> object: ...


class _ReceiptSink(Protocol):
    def record(
        self,
        *,
        action: _GatewayAction,
        decision: _PolicyDecision,
        response_status: _ResponseStatus,
        resolution_of: UUID | None = None,
    ) -> UUID: ...

    def build(
        self,
        *,
        action: _GatewayAction,
        decision: _PolicyDecision,
        response_status: _ResponseStatus,
        resolution_of: UUID | None = None,
    ) -> _BuiltReceipt: ...

    def persist_in_transaction(
        self,
        connection: Connection,
        receipt: _BuiltReceipt,
    ) -> None: ...


class _BuiltReceiptPayload(Protocol):
    receipt_id: UUID


class _BuiltReceipt(Protocol):
    payload: _BuiltReceiptPayload


class _PendingStore(Protocol):
    def create(
        self,
        record: _PendingActionRecord,
        *,
        persist_evaluation_receipt: Callable[[Connection], None],
    ) -> _PendingActionRecord: ...

    def load_pending(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
        pending_action_id: UUID,
    ) -> _PendingActionRecord | None: ...

    def list_expired(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
        now: datetime,
        limit: int = 64,
    ) -> tuple[_PendingActionRecord, ...]: ...

    def transition(
        self,
        transition: _PendingTransition,
        *,
        persist_transition_receipt: Callable[[Connection], None],
    ) -> None: ...


class _GatewayUnavailable(RuntimeError):
    """Sanitized fail-closed error raised before an action can execute."""


class _MemoryActionGateway:
    """Evaluate every supported action once before any executor side effect."""

    def __init__(
        self,
        *,
        policy: _BioDemoPolicy,
        executor: _Executor,
        receipt_sink: _ReceiptSink,
        pending_store: _PendingStore,
        clock: _Clock,
        pending_ttl: timedelta = timedelta(minutes=10),
    ) -> None:
        if not isinstance(policy, _BioDemoPolicy):
            raise TypeError("policy must be a _BioDemoPolicy")
        if pending_ttl <= timedelta(0) or pending_ttl > timedelta(minutes=15):
            raise ValueError("pending_ttl must be between zero and fifteen minutes")
        self._policy = policy
        self._executor = executor
        self._receipt_sink = receipt_sink
        self._pending_store = pending_store
        self._clock = clock
        self._pending_ttl = pending_ttl

    def execute(
        self,
        *,
        action: _GatewayAction,
        action_arguments: Mapping[str, object],
        facts: _PolicyFacts,
    ) -> _GatewayResult:
        if not isinstance(action, _GatewayAction):
            raise TypeError("action must be a _GatewayAction")
        if not isinstance(action_arguments, Mapping):
            raise TypeError("action_arguments must be a mapping")
        if not isinstance(facts, _PolicyFacts):
            raise TypeError("facts must be _PolicyFacts")
        if _hash_action_arguments(action_arguments) != action.action_arguments_sha256:
            raise ValueError("action arguments do not match the bounded action hash")

        trusted_action = replace(
            action,
            evaluated_at=_aware("clock.now", self._clock.now()),
        )
        decision = self._evaluate(trusted_action, facts)

        if decision.decision in {_Decision.STEP_UP, _Decision.DEFER}:
            return self._pend(trusted_action, decision)
        if decision.decision == _Decision.DENY:
            receipt_id = self._record(
                trusted_action,
                decision,
                _ResponseStatus.DENIED,
            )
            return _GatewayResult(
                decision.decision,
                decision.reason_code,
                _ResponseStatus.DENIED,
                receipt_id,
            )
        return self._execute_authorized(trusted_action, action_arguments, decision)

    def expire_pending(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
    ) -> tuple[_GatewayResult, ...]:
        _uuid("tenant_id", tenant_id)
        _uuid("program_id", program_id)
        now = _aware("clock.now", self._clock.now())
        records = self._pending_store.list_expired(
            tenant_id=tenant_id,
            program_id=program_id,
            now=now,
        )
        results: list[_GatewayResult] = []
        for record in records:
            results.append(
                self._deny_pending(
                    record,
                    _PolicyDecision(
                        _Decision.DENY,
                        _ReasonCode.PENDING_TIMEOUT,
                    ),
                    state=_PendingState.EXPIRED,
                )
            )
        return tuple(results)

    def resolve(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
        pending_action_id: UUID,
        action_arguments: Mapping[str, object],
        facts: _PolicyFacts,
        step_up_resolution: _StepUpResolution | None = None,
    ) -> _GatewayResult:
        """Resolve one pending action with a fresh, trusted policy evaluation."""

        _uuid("tenant_id", tenant_id)
        _uuid("program_id", program_id)
        _uuid("pending_action_id", pending_action_id)
        if not isinstance(action_arguments, Mapping):
            raise TypeError("action_arguments must be a mapping")
        if not isinstance(facts, _PolicyFacts):
            raise TypeError("facts must be _PolicyFacts")
        if step_up_resolution is not None and not isinstance(
            step_up_resolution, _StepUpResolution
        ):
            raise TypeError("step_up_resolution must be trusted typed context or None")

        record = self._pending_store.load_pending(
            tenant_id=tenant_id,
            program_id=program_id,
            pending_action_id=pending_action_id,
        )
        if record is None:
            raise _GatewayUnavailable("pending action is unavailable")

        now = _aware("clock.now", self._clock.now())
        action = replace(record.to_gateway_action(), evaluated_at=now)
        if record.expires_at <= now:
            return self._deny_pending(
                record,
                _PolicyDecision(_Decision.DENY, _ReasonCode.PENDING_TIMEOUT),
                state=_PendingState.EXPIRED,
            )

        try:
            supplied_hash = _hash_action_arguments(action_arguments)
        except (TypeError, ValueError):
            return self._deny_pending(
                record,
                _PolicyDecision(
                    _Decision.DENY,
                    _ReasonCode.PENDING_ARGUMENTS_MISMATCH,
                ),
            )
        if supplied_hash != action.action_arguments_sha256:
            return self._deny_pending(
                record,
                _PolicyDecision(
                    _Decision.DENY,
                    _ReasonCode.PENDING_ARGUMENTS_MISMATCH,
                ),
            )

        if record.pending_decision == _Decision.STEP_UP:
            if step_up_resolution is None:
                return self._deny_pending(
                    record,
                    _PolicyDecision(
                        _Decision.DENY,
                        _ReasonCode.PENDING_UNRESOLVED,
                    ),
                )
            if not step_up_resolution.approved:
                return self._deny_pending(
                    record,
                    _PolicyDecision(_Decision.DENY, _ReasonCode.PENDING_REJECTED),
                )
            approval = facts.approved_derivative
            if (
                approval is None
                or approval.approval_id != step_up_resolution.approval_id
                or approval.reviewed_by != step_up_resolution.reviewer_id
                or approval.reviewer_role != step_up_resolution.reviewer_role
                or approval.reviewed_at != step_up_resolution.resolved_at
                or step_up_resolution.resolved_at > now
            ):
                return self._deny_pending(
                    record,
                    _PolicyDecision(_Decision.DENY, _ReasonCode.PENDING_UNRESOLVED),
                )
        elif record.pending_decision == _Decision.DEFER:
            if step_up_resolution is not None:
                return self._deny_pending(
                    record,
                    _PolicyDecision(_Decision.DENY, _ReasonCode.PENDING_UNRESOLVED),
                )
        else:
            return self._deny_pending(
                record,
                _PolicyDecision(_Decision.DENY, _ReasonCode.POLICY_UNAVAILABLE),
            )

        decision = self._evaluate(action, facts)
        if decision.decision in {_Decision.STEP_UP, _Decision.DEFER}:
            return self._deny_pending(
                record,
                _PolicyDecision(_Decision.DENY, _ReasonCode.PENDING_UNRESOLVED),
            )
        if decision.decision == _Decision.DENY:
            return self._deny_pending(record, decision)
        if record.pending_decision == _Decision.STEP_UP and not _is_exact_modify(
            decision
        ):
            return self._deny_pending(
                record,
                _PolicyDecision(_Decision.DENY, _ReasonCode.PENDING_UNRESOLVED),
            )
        if decision.decision == _Decision.MODIFY and not _is_exact_modify(decision):
            return self._deny_pending(
                record,
                _PolicyDecision(_Decision.DENY, _ReasonCode.PENDING_UNRESOLVED),
            )
        return self._execute_resolved_pending(
            record,
            action,
            action_arguments,
            decision,
        )

    def _pend(
        self,
        action: _GatewayAction,
        decision: _PolicyDecision,
    ) -> _GatewayResult:
        signed = self._build_receipt(
            action,
            decision,
            _ResponseStatus.PENDING,
        )
        receipt_id = _receipt_id(signed)
        missing_context = (
            decision.missing_context if decision.decision == _Decision.DEFER else ()
        )
        record = _PendingActionRecord.from_gateway_action(
            action,
            evaluation_receipt_id=receipt_id,
            pending_decision=decision.decision,
            missing_context=missing_context,
            expires_at=action.evaluated_at + self._pending_ttl,
        )
        try:
            stored = self._pending_store.create(
                record,
                persist_evaluation_receipt=lambda connection: (
                    self._receipt_sink.persist_in_transaction(connection, signed)
                ),
            )
        except Exception:
            raise _GatewayUnavailable(
                "pending action persistence failed closed"
            ) from None
        return _GatewayResult(
            decision.decision,
            decision.reason_code,
            _ResponseStatus.PENDING,
            receipt_id,
            pending_action_id=stored.pending_action_id,
        )

    def _execute_authorized(
        self,
        action: _GatewayAction,
        action_arguments: Mapping[str, object],
        decision: _PolicyDecision,
    ) -> _GatewayResult:
        try:
            prepared = self._executor.prepare(
                action=action,
                executable_memory_ids=decision.executable_memory_ids,
                expected_content_sha256=decision.executable_content_sha256,
                action_arguments=action_arguments,
            )
            bound_decision = _bind_prepared_decision(decision, prepared)
        except Exception:
            failed_id = self._record(
                action,
                decision,
                _ResponseStatus.FAILED,
            )
            return _GatewayResult(
                decision.decision,
                decision.reason_code,
                _ResponseStatus.FAILED,
                failed_id,
            )
        evaluation_id = self._record(
            action,
            bound_decision,
            _ResponseStatus.PENDING,
        )
        try:
            output = self._executor.execute(
                action=action,
                prepared=prepared,
                action_arguments=action_arguments,
            )
        except Exception:
            resolution_id = self._record(
                action,
                bound_decision,
                _ResponseStatus.FAILED,
                resolution_of=evaluation_id,
            )
            return _GatewayResult(
                decision.decision,
                decision.reason_code,
                _ResponseStatus.FAILED,
                evaluation_id,
                resolution_receipt_id=resolution_id,
            )
        resolution_id = self._record(
            action,
            bound_decision,
            _ResponseStatus.COMPLETED,
            resolution_of=evaluation_id,
        )
        return _GatewayResult(
            decision.decision,
            decision.reason_code,
            _ResponseStatus.COMPLETED,
            evaluation_id,
            resolution_receipt_id=resolution_id,
            output=output,
        )

    def _deny_pending(
        self,
        record: _PendingActionRecord,
        decision: _PolicyDecision,
        *,
        state: _PendingState = _PendingState.DENIED,
    ) -> _GatewayResult:
        """Atomically record a terminal denial and consume the pending action."""

        action = record.to_gateway_action()
        signed = self._build_receipt(
            action,
            decision,
            _ResponseStatus.DENIED,
            resolution_of=record.evaluation_receipt_id,
        )
        resolution_id = _receipt_id(signed)
        self._transition_pending(record, state, signed, resolution_id)
        return _GatewayResult(
            _Decision.DENY,
            decision.reason_code,
            _ResponseStatus.DENIED,
            record.evaluation_receipt_id,
            resolution_receipt_id=resolution_id,
        )

    def _execute_resolved_pending(
        self,
        record: _PendingActionRecord,
        action: _GatewayAction,
        action_arguments: Mapping[str, object],
        decision: _PolicyDecision,
    ) -> _GatewayResult:
        """Receipt-authorize a resolved action before its single execution."""

        try:
            prepared = self._executor.prepare(
                action=action,
                executable_memory_ids=decision.executable_memory_ids,
                expected_content_sha256=decision.executable_content_sha256,
                action_arguments=action_arguments,
            )
            bound_decision = _bind_prepared_decision(decision, prepared)
        except Exception:
            return self._deny_pending(
                record,
                _PolicyDecision(_Decision.DENY, _ReasonCode.POLICY_UNAVAILABLE),
            )

        signed = self._build_receipt(
            action,
            bound_decision,
            _ResponseStatus.PENDING,
            resolution_of=record.evaluation_receipt_id,
        )
        authorization_id = _receipt_id(signed)
        self._transition_pending(
            record,
            _PendingState.CONSUMED,
            signed,
            authorization_id,
        )
        try:
            output = self._executor.execute(
                action=action,
                prepared=prepared,
                action_arguments=action_arguments,
            )
        except Exception:
            resolution_id = self._record(
                action,
                bound_decision,
                _ResponseStatus.FAILED,
                resolution_of=record.evaluation_receipt_id,
            )
            return _GatewayResult(
                decision.decision,
                decision.reason_code,
                _ResponseStatus.FAILED,
                record.evaluation_receipt_id,
                resolution_receipt_id=resolution_id,
            )
        resolution_id = self._record(
            action,
            bound_decision,
            _ResponseStatus.COMPLETED,
            resolution_of=record.evaluation_receipt_id,
        )
        return _GatewayResult(
            decision.decision,
            decision.reason_code,
            _ResponseStatus.COMPLETED,
            record.evaluation_receipt_id,
            resolution_receipt_id=resolution_id,
            output=output,
        )

    def _transition_pending(
        self,
        record: _PendingActionRecord,
        state: _PendingState,
        signed_receipt: _BuiltReceipt,
        receipt_id: UUID,
    ) -> None:
        try:
            self._pending_store.transition(
                _PendingTransition(
                    record=record,
                    state=state,
                    transition_receipt_id=receipt_id,
                    transitioned_at=_aware("clock.now", self._clock.now()),
                ),
                persist_transition_receipt=lambda connection: (
                    self._receipt_sink.persist_in_transaction(
                        connection,
                        signed_receipt,
                    )
                ),
            )
        except Exception:
            raise _GatewayUnavailable(
                "pending action transition failed closed"
            ) from None

    def _evaluate(
        self,
        action: _GatewayAction,
        facts: _PolicyFacts,
    ) -> _PolicyDecision:
        try:
            trusted_now = _aware("clock.now", self._clock.now())
            return self._policy.evaluate(action.policy, replace(facts, now=trusted_now))
        except Exception:
            return _PolicyDecision(
                _Decision.DENY,
                _ReasonCode.POLICY_UNAVAILABLE,
            )

    def _record(
        self,
        action: _GatewayAction,
        decision: _PolicyDecision,
        response_status: _ResponseStatus,
        *,
        resolution_of: UUID | None = None,
    ) -> UUID:
        try:
            receipt_id = self._receipt_sink.record(
                action=action,
                decision=decision,
                response_status=response_status,
                resolution_of=resolution_of,
            )
            return _uuid("receipt_id", receipt_id)
        except Exception:
            raise _GatewayUnavailable("receipt recording failed closed") from None

    def _build_receipt(
        self,
        action: _GatewayAction,
        decision: _PolicyDecision,
        response_status: _ResponseStatus,
        *,
        resolution_of: UUID | None = None,
    ) -> _BuiltReceipt:
        try:
            return self._receipt_sink.build(
                action=action,
                decision=decision,
                response_status=response_status,
                resolution_of=resolution_of,
            )
        except Exception:
            raise _GatewayUnavailable("receipt building failed closed") from None


def _receipt_id(signed_receipt: _BuiltReceipt) -> UUID:
    try:
        return _uuid("receipt_id", signed_receipt.payload.receipt_id)
    except (AttributeError, TypeError, ValueError):
        raise _GatewayUnavailable("receipt building failed closed") from None


def _hash_action_arguments(arguments: Mapping[str, object]) -> str:
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be a mapping")
    normalized = _normalize_json(arguments)
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _MAX_ARGUMENT_BYTES:
        raise ValueError("action arguments exceed the bounded canonical size")
    return hashlib.sha256(encoded).hexdigest()


def _is_exact_modify(decision: _PolicyDecision) -> bool:
    return (
        decision.decision == _Decision.MODIFY
        and len(decision.executable_memory_ids) == 1
        and len(decision.executable_content_sha256) == 1
    )


def _bind_prepared_decision(
    decision: _PolicyDecision,
    prepared: _PreparedAction,
) -> _PolicyDecision:
    if not isinstance(prepared, _PreparedAction):
        raise TypeError("executor.prepare must return a _PreparedAction")
    if not set(prepared.memory_ids).issubset(decision.executable_memory_ids):
        raise PermissionError("prepared memory is outside the authorized set")
    if decision.decision == _Decision.MODIFY and (
        prepared.memory_ids != decision.executable_memory_ids
        or prepared.content_sha256 != decision.executable_content_sha256
    ):
        raise PermissionError("prepared derivative does not match the approved hash")
    if decision.decision == _Decision.ALLOW and not prepared.memory_ids:
        raise PermissionError("authorized recall prepared no content-bound memory")
    return replace(
        decision,
        executable_memory_ids=prepared.memory_ids,
        executable_content_sha256=prepared.content_sha256,
        model_prompt_sha256=prepared.model_prompt_sha256,
    )


def _normalize_json(value: object, *, depth: int = 0) -> object:
    if depth > 8:
        raise ValueError("action arguments are nested too deeply")
    if value is None or type(value) in {str, bool, int}:
        if isinstance(value, str) and len(value) > 2_000:
            raise ValueError("action argument text is too long")
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, tuple | list):
        if len(value) > 32:
            raise ValueError("action argument collection is too large")
        return [_normalize_json(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        if len(value) > 32:
            raise ValueError("action argument mapping is too large")
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str or not _IDENTIFIER_RE.fullmatch(key):
                raise ValueError("action argument keys must be bounded identifiers")
            if key in normalized:
                raise ValueError("action argument keys must be unique")
            normalized[key] = _normalize_json(item, depth=depth + 1)
        return normalized
    raise TypeError("action arguments contain an unsupported value")
