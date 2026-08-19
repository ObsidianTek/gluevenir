"""Private durable CockroachDB store for unresolved memory actions."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import MultipleResultsFound, NoResultFound, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._memory_store import _SET_TENANT_CONTEXT, _VERIFY_RUNTIME_PRINCIPAL
from gluevenir._policy import (
    _Decision,
    _Destination,
    _PolicyAction,
    _ReasonCode,
)
from gluevenir._ports import MemoryOperation

if TYPE_CHECKING:
    from gluevenir._gateway import _GatewayAction

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_PENDING_TTL = timedelta(minutes=15)
_MAX_EXPIRED_RESULTS = 64

_PENDING_COLUMNS = """
    id,
    tenant_id,
    program_id,
    session_id,
    intent_id,
    evaluation_receipt_id,
    agent_id,
    actor_id,
    actor_role,
    operation,
    purpose,
    audience,
    destination,
    policy_version,
    requested_memory_ids,
    data_classes,
    missing_context,
    action_arguments_sha256,
    original_intent_sha256,
    prior_action_context_sha256,
    pending_decision,
    state,
    evaluated_at,
    expires_at,
    transition_receipt_id,
    transitioned_at
"""

_SELECT_EXISTING = text(
    f"""
    SELECT {_PENDING_COLUMNS}
    FROM pending_memory_actions
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND id = :pending_action_id
    FOR UPDATE
    """
)
_INSERT_PENDING = text(
    """
    INSERT INTO pending_memory_actions (
        id, tenant_id, program_id, session_id, intent_id,
        evaluation_receipt_id, agent_id, actor_id, actor_role, operation,
        purpose, audience, destination, policy_version, requested_memory_ids,
        data_classes, missing_context, action_arguments_sha256,
        original_intent_sha256, prior_action_context_sha256, pending_decision,
        state, evaluated_at, expires_at, transition_receipt_id, transitioned_at
    ) VALUES (
        :pending_action_id, :tenant_id, :program_id, :session_id, :intent_id,
        :evaluation_receipt_id, :agent_id, :actor_id, :actor_role, :operation,
        :purpose, :audience, :destination, :policy_version,
        CAST(:requested_memory_ids AS UUID[]), CAST(:data_classes AS STRING[]),
        CAST(:missing_context AS STRING[]), :action_arguments_sha256,
        :original_intent_sha256, :prior_action_context_sha256,
        :pending_decision, 'pending', :evaluated_at, :expires_at, NULL, NULL
    )
    RETURNING id
    """
)
_LOAD_ACTIVE = text(
    f"""
    SELECT {_PENDING_COLUMNS}
    FROM pending_memory_actions
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND id = :pending_action_id
      AND state = 'pending'
      AND expires_at > :now
    """
)
_LOAD_PENDING = text(
    f"""
    SELECT {_PENDING_COLUMNS}
    FROM pending_memory_actions
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND id = :pending_action_id
      AND state = 'pending'
    """
)
_LIST_EXPIRED = text(
    f"""
    SELECT {_PENDING_COLUMNS}
    FROM pending_memory_actions
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND state = 'pending'
      AND expires_at <= :now
    ORDER BY expires_at, id
    LIMIT :limit
    """
)
_SELECT_FOR_TRANSITION = text(
    f"""
    SELECT {_PENDING_COLUMNS}
    FROM pending_memory_actions
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND id = :pending_action_id
      AND state = 'pending'
    FOR UPDATE
    """
)
_TRANSITION_PENDING = text(
    """
    UPDATE pending_memory_actions
    SET state = :terminal_state,
        transition_receipt_id = :transition_receipt_id,
        transitioned_at = :transitioned_at
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND id = :pending_action_id
      AND session_id = :session_id
      AND intent_id = :intent_id
      AND evaluation_receipt_id = :evaluation_receipt_id
      AND action_arguments_sha256 = :action_arguments_sha256
      AND original_intent_sha256 = :original_intent_sha256
      AND prior_action_context_sha256 = :prior_action_context_sha256
      AND pending_decision = :pending_decision
      AND state = 'pending'
      AND (
          (:terminal_state = 'expired' AND expires_at <= :transitioned_at)
          OR
          (:terminal_state != 'expired' AND expires_at > :transitioned_at)
      )
    RETURNING id
    """
)


class _PendingState(StrEnum):
    PENDING = "pending"
    CONSUMED = "consumed"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class _PendingActionRecord:
    """Content-free action data sufficient to rebuild a gateway action."""

    pending_action_id: UUID
    tenant_id: UUID
    program_id: UUID
    session_id: UUID
    intent_id: UUID
    evaluation_receipt_id: UUID
    agent_id: str
    actor_id: str
    actor_role: str
    operation: MemoryOperation
    purpose: str
    audience: str
    destination: _Destination
    policy_version: str
    requested_memory_ids: tuple[UUID, ...]
    data_classes: tuple[str, ...]
    missing_context: tuple[str, ...]
    action_arguments_sha256: str
    original_intent_sha256: str
    prior_action_context_sha256: str
    pending_decision: _Decision
    evaluated_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for name in (
            "pending_action_id",
            "tenant_id",
            "program_id",
            "session_id",
            "intent_id",
            "evaluation_receipt_id",
        ):
            _uuid(name, getattr(self, name))
        object.__setattr__(self, "agent_id", _identifier("agent_id", self.agent_id))
        object.__setattr__(self, "actor_id", _identifier("actor_id", self.actor_id))
        if not isinstance(self.operation, MemoryOperation):
            raise TypeError("operation must be a MemoryOperation")
        if not isinstance(self.destination, _Destination):
            raise TypeError("destination must be a _Destination")
        if not isinstance(self.pending_decision, _Decision):
            raise TypeError("pending_decision must be a _Decision")
        if self.pending_decision not in {_Decision.STEP_UP, _Decision.DEFER}:
            raise ValueError("pending_decision must be STEP_UP or DEFER")
        if not isinstance(self.missing_context, tuple):
            raise TypeError("missing_context must be a tuple")

        policy = self.to_policy_action()
        if self.pending_decision == _Decision.STEP_UP:
            if self.missing_context:
                raise ValueError("STEP_UP cannot persist missing context")
        else:
            object.__setattr__(
                self,
                "missing_context",
                _validate_missing_context(self.missing_context),
            )
        for name in (
            "action_arguments_sha256",
            "original_intent_sha256",
            "prior_action_context_sha256",
        ):
            _digest(name, getattr(self, name))
        _aware("evaluated_at", self.evaluated_at)
        _aware("expires_at", self.expires_at)
        if self.expires_at <= self.evaluated_at:
            raise ValueError("expires_at must follow evaluated_at")
        if self.expires_at - self.evaluated_at > _MAX_PENDING_TTL:
            raise ValueError("pending action exceeds the fifteen-minute TTL")

        # Reassign the normalized values produced by the policy type.
        for name in (
            "actor_role",
            "purpose",
            "audience",
            "policy_version",
            "requested_memory_ids",
            "data_classes",
        ):
            object.__setattr__(self, name, getattr(policy, name))

    @property
    def pending_reason_code(self) -> _ReasonCode:
        """Return the only valid reason for the persisted pending decision."""

        if self.pending_decision == _Decision.STEP_UP:
            return _ReasonCode.HUMAN_APPROVAL_REQUIRED
        return _ReasonCode.REQUIRED_CONTEXT_MISSING

    @classmethod
    def from_gateway_action(
        cls,
        action: _GatewayAction,
        *,
        evaluation_receipt_id: UUID,
        pending_decision: _Decision,
        missing_context: tuple[str, ...],
        expires_at: datetime,
    ) -> _PendingActionRecord:
        """Freeze one already-evaluated action without retaining its arguments."""

        from gluevenir._gateway import _GatewayAction

        if not isinstance(action, _GatewayAction):
            raise TypeError("action must be a _GatewayAction")
        return cls(
            pending_action_id=action.request_id,
            tenant_id=action.policy.tenant_id,
            program_id=action.policy.program_id,
            session_id=action.session_id,
            intent_id=action.intent_id,
            evaluation_receipt_id=evaluation_receipt_id,
            agent_id=action.agent_id,
            actor_id=action.actor_id,
            actor_role=action.policy.actor_role,
            operation=action.policy.operation,
            purpose=action.policy.purpose,
            audience=action.policy.audience,
            destination=action.policy.destination,
            policy_version=action.policy.policy_version,
            requested_memory_ids=action.policy.requested_memory_ids,
            data_classes=action.policy.data_classes,
            missing_context=missing_context,
            action_arguments_sha256=action.action_arguments_sha256,
            original_intent_sha256=action.original_intent_sha256,
            prior_action_context_sha256=action.prior_action_context_sha256,
            pending_decision=pending_decision,
            evaluated_at=action.evaluated_at,
            expires_at=expires_at,
        )

    def to_policy_action(self) -> _PolicyAction:
        return _PolicyAction(
            operation=self.operation,
            tenant_id=self.tenant_id,
            program_id=self.program_id,
            actor_role=self.actor_role,
            purpose=self.purpose,
            audience=self.audience,
            destination=self.destination,
            policy_version=self.policy_version,
            requested_memory_ids=self.requested_memory_ids,
            data_classes=self.data_classes,
        )

    def to_gateway_action(self) -> _GatewayAction:
        """Rebuild the typed action after a stateless runtime reload."""

        from gluevenir._gateway import _GatewayAction

        return _GatewayAction(
            request_id=self.pending_action_id,
            session_id=self.session_id,
            intent_id=self.intent_id,
            agent_id=self.agent_id,
            actor_id=self.actor_id,
            evaluated_at=self.evaluated_at,
            action_arguments_sha256=self.action_arguments_sha256,
            original_intent_sha256=self.original_intent_sha256,
            prior_action_context_sha256=self.prior_action_context_sha256,
            policy=self.to_policy_action(),
        )


@dataclass(frozen=True, slots=True)
class _PendingTransition:
    """One exact terminal compare-and-set for a loaded pending action."""

    record: _PendingActionRecord
    state: _PendingState
    transition_receipt_id: UUID
    transitioned_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.record, _PendingActionRecord):
            raise TypeError("record must be a _PendingActionRecord")
        if not isinstance(self.state, _PendingState):
            raise TypeError("state must be a _PendingState")
        if self.state == _PendingState.PENDING:
            raise ValueError("transition state must be terminal")
        _uuid("transition_receipt_id", self.transition_receipt_id)
        _aware("transitioned_at", self.transitioned_at)
        if self.state == _PendingState.EXPIRED:
            if self.transitioned_at < self.record.expires_at:
                raise ValueError("an action cannot expire before its deadline")
        elif self.transitioned_at >= self.record.expires_at:
            raise ValueError("a non-expiry transition must precede the deadline")


type _ReceiptPersistenceCallback = Callable[[Connection], None]
type _TransactionRunner = Callable[..., Any]


class _PendingStoreUnavailable(RuntimeError):
    """Sanitized pending-store outage; callers must fail closed."""


class _PendingStoreConflict(RuntimeError):
    """An exact create or one-time transition could not be authorized."""


class _CockroachPendingActionStore:
    """Persist pending actions and terminal receipt transitions atomically."""

    __slots__ = ("_application_principal", "_engine", "_transaction_runner")

    def __init__(
        self,
        engine: Engine,
        *,
        application_principal: str,
        _transaction_runner: _TransactionRunner = run_transaction,
    ) -> None:
        if not isinstance(engine, Engine):
            raise TypeError("engine must be a SQLAlchemy Engine")
        if not engine.hide_parameters:
            raise ValueError("runtime engine must hide SQL parameter values")
        self._engine = engine
        self._application_principal = _identifier(
            "application_principal", application_principal
        )
        if not callable(_transaction_runner):
            raise TypeError("_transaction_runner must be callable")
        self._transaction_runner = _transaction_runner

    def create(
        self,
        record: _PendingActionRecord,
        *,
        persist_evaluation_receipt: _ReceiptPersistenceCallback,
    ) -> _PendingActionRecord:
        """Atomically persist a signed evaluation receipt and pending action."""

        if not isinstance(record, _PendingActionRecord):
            raise TypeError("record must be a _PendingActionRecord")
        _callback("persist_evaluation_receipt", persist_evaluation_receipt)

        def create_pending(connection: Connection) -> _PendingActionRecord:
            self._authorize_transaction(connection, record.tenant_id)
            existing = (
                connection.execute(_SELECT_EXISTING, _identity_parameters(record))
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                stored, state = _record_from_row(existing)
                if state == _PendingState.PENDING and stored == record:
                    return stored
                raise _PendingStoreConflict("pending action create was rejected")

            persist_evaluation_receipt(connection)
            inserted_id = _returned_id(
                connection.execute(_INSERT_PENDING, _record_parameters(record))
            )
            if inserted_id != record.pending_action_id:
                raise _PendingStoreUnavailable("pending action persistence failed")
            return record

        return self._run(create_pending)

    def load(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
        pending_action_id: UUID,
        now: datetime,
    ) -> _PendingActionRecord | None:
        """Load only an unconsumed action strictly before its expiry."""

        _uuid("tenant_id", tenant_id)
        _uuid("program_id", program_id)
        _uuid("pending_action_id", pending_action_id)
        _aware("now", now)

        def load_pending(connection: Connection) -> _PendingActionRecord | None:
            self._authorize_transaction(connection, tenant_id)
            row = (
                connection.execute(
                    _LOAD_ACTIVE,
                    {
                        "tenant_id": str(tenant_id),
                        "program_id": str(program_id),
                        "pending_action_id": str(pending_action_id),
                        "now": now,
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            record, state = _record_from_row(row)
            if state != _PendingState.PENDING or record.expires_at <= now:
                raise _PendingStoreUnavailable("pending action persistence failed")
            return record

        return self._run(load_pending)

    def load_pending(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
        pending_action_id: UUID,
    ) -> _PendingActionRecord | None:
        """Load one unresolved action, including one eligible for timeout denial."""

        _uuid("tenant_id", tenant_id)
        _uuid("program_id", program_id)
        _uuid("pending_action_id", pending_action_id)

        def load_unresolved(connection: Connection) -> _PendingActionRecord | None:
            self._authorize_transaction(connection, tenant_id)
            row = (
                connection.execute(
                    _LOAD_PENDING,
                    {
                        "tenant_id": str(tenant_id),
                        "program_id": str(program_id),
                        "pending_action_id": str(pending_action_id),
                    },
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            record, state = _record_from_row(row)
            if state != _PendingState.PENDING:
                raise _PendingStoreUnavailable("pending action persistence failed")
            return record

        return self._run(load_unresolved)

    def list_expired(
        self,
        *,
        tenant_id: UUID,
        program_id: UUID,
        now: datetime,
        limit: int = _MAX_EXPIRED_RESULTS,
    ) -> tuple[_PendingActionRecord, ...]:
        """List a bounded batch eligible for deterministic timeout denial."""

        _uuid("tenant_id", tenant_id)
        _uuid("program_id", program_id)
        _aware("now", now)
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= _MAX_EXPIRED_RESULTS:
            raise ValueError("limit must be between one and sixty-four")

        def find_expired(connection: Connection) -> tuple[_PendingActionRecord, ...]:
            self._authorize_transaction(connection, tenant_id)
            rows = (
                connection.execute(
                    _LIST_EXPIRED,
                    {
                        "tenant_id": str(tenant_id),
                        "program_id": str(program_id),
                        "now": now,
                        "limit": limit,
                    },
                )
                .mappings()
                .all()
            )
            records: list[_PendingActionRecord] = []
            for row in rows:
                record, state = _record_from_row(row)
                if state != _PendingState.PENDING or record.expires_at > now:
                    raise _PendingStoreUnavailable("pending action persistence failed")
                records.append(record)
            return tuple(records)

        return self._run(find_expired)

    def transition(
        self,
        transition: _PendingTransition,
        *,
        persist_transition_receipt: _ReceiptPersistenceCallback,
    ) -> None:
        """Atomically persist a signed receipt and consume one action exactly once."""

        if not isinstance(transition, _PendingTransition):
            raise TypeError("transition must be a _PendingTransition")
        _callback("persist_transition_receipt", persist_transition_receipt)
        record = transition.record

        def transition_pending(connection: Connection) -> None:
            self._authorize_transaction(connection, record.tenant_id)
            selected = (
                connection.execute(
                    _SELECT_FOR_TRANSITION,
                    _identity_parameters(record),
                )
                .mappings()
                .one_or_none()
            )
            if selected is None:
                raise _PendingStoreConflict("pending action transition was rejected")
            stored, state = _record_from_row(selected)
            if state != _PendingState.PENDING or stored != record:
                raise _PendingStoreConflict("pending action transition was rejected")

            persist_transition_receipt(connection)
            returned_id = _returned_id_or_none(
                connection.execute(
                    _TRANSITION_PENDING,
                    _transition_parameters(transition),
                )
            )
            if returned_id != record.pending_action_id:
                raise _PendingStoreConflict("pending action transition was rejected")

        self._run(transition_pending)

    def _authorize_transaction(self, connection: Connection, tenant_id: UUID) -> None:
        try:
            principal = connection.execute(_VERIFY_RUNTIME_PRINCIPAL).mappings().one()
        except (MultipleResultsFound, NoResultFound, SQLAlchemyError):
            raise _PendingStoreUnavailable(
                "pending action persistence failed"
            ) from None
        if (
            principal.get("principal") != self._application_principal
            or principal.get("bypasses_rls") is not False
            or principal.get("is_app_member") is not True
            or principal.get("can_create_schema_objects") is not False
            or principal.get("can_create_schemas") is not False
        ):
            raise _PendingStoreUnavailable("pending action persistence failed")
        connection.execute(_SET_TENANT_CONTEXT, {"tenant_id": str(tenant_id)})

    def _run(self, callback: Callable[[Connection], Any]) -> Any:
        try:
            return self._transaction_runner(
                self._engine,
                callback,
                max_retries=3,
                max_backoff=1,
            )
        except (_PendingStoreConflict, _PendingStoreUnavailable):
            raise
        except Exception:
            raise _PendingStoreUnavailable(
                "pending action persistence failed"
            ) from None


def _uuid(name: str, value: object) -> UUID:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be a UUID")
    return value


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    normalized = value.strip()
    if not _IDENTIFIER_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a bounded identifier")
    return normalized


def _digest(name: str, value: object) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _aware(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


def _callback(name: str, value: object) -> _ReceiptPersistenceCallback:
    if not callable(value):
        raise TypeError(f"{name} must be callable")
    return value


def _validate_missing_context(values: tuple[str, ...]) -> tuple[str, ...]:
    if not values:
        raise ValueError("DEFER requires missing context")
    if len(values) > 2:
        raise ValueError("missing_context exceeds the bounded set")
    normalized = tuple(_identifier("missing_context", value) for value in values)
    if set(normalized) - {"partner_authorization", "session_intent"}:
        raise ValueError("missing_context contains an unsupported field")
    if len(set(normalized)) != len(normalized):
        raise ValueError("missing_context must not contain duplicates")
    return normalized


def _identity_parameters(record: _PendingActionRecord) -> dict[str, object]:
    return {
        "tenant_id": str(record.tenant_id),
        "program_id": str(record.program_id),
        "pending_action_id": str(record.pending_action_id),
    }


def _record_parameters(record: _PendingActionRecord) -> dict[str, object]:
    parameters = _identity_parameters(record)
    parameters.update(
        {
            "session_id": str(record.session_id),
            "intent_id": str(record.intent_id),
            "evaluation_receipt_id": str(record.evaluation_receipt_id),
            "agent_id": record.agent_id,
            "actor_id": record.actor_id,
            "actor_role": record.actor_role,
            "operation": record.operation.value,
            "purpose": record.purpose,
            "audience": record.audience,
            "destination": record.destination.value,
            "policy_version": record.policy_version,
            "requested_memory_ids": [
                str(memory_id) for memory_id in record.requested_memory_ids
            ],
            "data_classes": list(record.data_classes),
            "missing_context": list(record.missing_context),
            "action_arguments_sha256": record.action_arguments_sha256,
            "original_intent_sha256": record.original_intent_sha256,
            "prior_action_context_sha256": record.prior_action_context_sha256,
            "pending_decision": record.pending_decision.value,
            "evaluated_at": record.evaluated_at,
            "expires_at": record.expires_at,
        }
    )
    return parameters


def _transition_parameters(transition: _PendingTransition) -> dict[str, object]:
    record = transition.record
    parameters = _record_parameters(record)
    parameters.update(
        {
            "terminal_state": transition.state.value,
            "transition_receipt_id": str(transition.transition_receipt_id),
            "transitioned_at": transition.transitioned_at,
        }
    )
    return parameters


def _record_from_row(
    row: Mapping[str, Any],
) -> tuple[_PendingActionRecord, _PendingState]:
    try:
        requested = row["requested_memory_ids"]
        data_classes = row["data_classes"]
        missing_context = row["missing_context"]
        if not isinstance(requested, (list, tuple)):
            raise TypeError
        if not isinstance(data_classes, (list, tuple)):
            raise TypeError
        if not isinstance(missing_context, (list, tuple)):
            raise TypeError
        state = _PendingState(str(row["state"]))
        transition_receipt_id = row["transition_receipt_id"]
        transitioned_at = row["transitioned_at"]
        if state == _PendingState.PENDING:
            if transition_receipt_id is not None or transitioned_at is not None:
                raise ValueError
        elif transition_receipt_id is None or transitioned_at is None:
            raise ValueError
        else:
            UUID(str(transition_receipt_id))
            _aware("transitioned_at", transitioned_at)
        record = _PendingActionRecord(
            pending_action_id=UUID(str(row["id"])),
            tenant_id=UUID(str(row["tenant_id"])),
            program_id=UUID(str(row["program_id"])),
            session_id=UUID(str(row["session_id"])),
            intent_id=UUID(str(row["intent_id"])),
            evaluation_receipt_id=UUID(str(row["evaluation_receipt_id"])),
            agent_id=row["agent_id"],
            actor_id=row["actor_id"],
            actor_role=row["actor_role"],
            operation=MemoryOperation(str(row["operation"])),
            purpose=row["purpose"],
            audience=row["audience"],
            destination=_Destination(str(row["destination"])),
            policy_version=row["policy_version"],
            requested_memory_ids=tuple(UUID(str(value)) for value in requested),
            data_classes=tuple(str(value) for value in data_classes),
            missing_context=tuple(str(value) for value in missing_context),
            action_arguments_sha256=row["action_arguments_sha256"],
            original_intent_sha256=row["original_intent_sha256"],
            prior_action_context_sha256=row["prior_action_context_sha256"],
            pending_decision=_Decision(str(row["pending_decision"])),
            evaluated_at=row["evaluated_at"],
            expires_at=row["expires_at"],
        )
        return record, state
    except (KeyError, TypeError, ValueError):
        raise _PendingStoreUnavailable("pending action persistence failed") from None


def _returned_id(result: Any) -> UUID:
    try:
        return UUID(str(result.mappings().one()["id"]))
    except (KeyError, MultipleResultsFound, NoResultFound, TypeError, ValueError):
        raise _PendingStoreUnavailable("pending action persistence failed") from None


def _returned_id_or_none(result: Any) -> UUID | None:
    try:
        row = result.mappings().one_or_none()
        return None if row is None else UUID(str(row["id"]))
    except (KeyError, MultipleResultsFound, TypeError, ValueError):
        raise _PendingStoreUnavailable("pending action persistence failed") from None
