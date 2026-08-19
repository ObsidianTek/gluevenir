from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import MultipleResultsFound, NoResultFound, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._gateway import _GatewayAction
from gluevenir._pending_store import (
    _CockroachPendingActionStore,
    _PendingActionRecord,
    _PendingState,
    _PendingStoreConflict,
    _PendingStoreUnavailable,
    _PendingTransition,
)
from gluevenir._policy import _Decision, _Destination, _PolicyAction, _ReasonCode
from gluevenir._ports import MemoryOperation

TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
PROGRAM_ID = UUID("20000000-0000-4000-8000-000000000001")
SESSION_ID = UUID("30000000-0000-4000-8000-000000000001")
INTENT_ID = UUID("40000000-0000-4000-8000-000000000001")
PENDING_ID = UUID("50000000-0000-4000-8000-000000000001")
EVALUATION_RECEIPT_ID = UUID("60000000-0000-4000-8000-000000000001")
TRANSITION_RECEIPT_ID = UUID("70000000-0000-4000-8000-000000000001")
MEMORY_ID = UUID("80000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 8, 15, 18, 30, tzinfo=UTC)
EXPIRES = NOW + timedelta(minutes=10)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
APP_PRINCIPAL = "gluevenir_runtime"
RAW_ARGUMENT = "SYNTHETIC restricted source text must never persist"


class _FakeResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows

    def mappings(self) -> _FakeResult:
        return self

    def one(self) -> dict[str, object]:
        if not self.rows:
            raise NoResultFound()
        if len(self.rows) > 1:
            raise MultipleResultsFound()
        return self.rows[0]

    def one_or_none(self) -> dict[str, object] | None:
        if len(self.rows) > 1:
            raise MultipleResultsFound()
        return self.rows[0] if self.rows else None

    def all(self) -> list[dict[str, object]]:
        return self.rows


class _FakeConnection:
    def __init__(
        self,
        row: dict[str, object] | None = None,
        *,
        principal: dict[str, object] | None = None,
        force_cas_miss: bool = False,
    ) -> None:
        self.row = None if row is None else dict(row)
        self.principal = principal or _principal()
        self.force_cas_miss = force_cas_miss
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(
        self,
        statement: object,
        parameters: dict[str, object] | None = None,
    ) -> _FakeResult:
        sql = " ".join(str(statement).split())
        bound = parameters or {}
        self.calls.append((sql, bound))
        lowered = sql.casefold()
        if "current_user as principal" in lowered:
            return _FakeResult([self.principal])
        if "set_config" in lowered:
            return _FakeResult([])
        if lowered.startswith("select") and "from pending_memory_actions" in lowered:
            return _FakeResult(self._select_rows(lowered, bound))
        if lowered.startswith("insert into pending_memory_actions"):
            assert self.row is None
            self.row = _row_from_parameters(bound)
            return _FakeResult([{"id": bound["pending_action_id"]}])
        if lowered.startswith("update pending_memory_actions"):
            if self.force_cas_miss or self.row is None:
                return _FakeResult([])
            if self.row["state"] != _PendingState.PENDING.value:
                return _FakeResult([])
            if not _cas_matches(self.row, bound):
                return _FakeResult([])
            terminal = str(bound["terminal_state"])
            transitioned_at = bound["transitioned_at"]
            expires_at = self.row["expires_at"]
            assert isinstance(transitioned_at, datetime)
            assert isinstance(expires_at, datetime)
            valid_boundary = (
                expires_at <= transitioned_at
                if terminal == _PendingState.EXPIRED.value
                else expires_at > transitioned_at
            )
            if not valid_boundary:
                return _FakeResult([])
            self.row.update(
                {
                    "state": terminal,
                    "transition_receipt_id": bound["transition_receipt_id"],
                    "transitioned_at": transitioned_at,
                }
            )
            return _FakeResult([{"id": bound["pending_action_id"]}])
        raise AssertionError(f"unexpected SQL: {sql}")

    def _select_rows(
        self, sql: str, parameters: dict[str, object]
    ) -> list[dict[str, object]]:
        if self.row is None:
            return []
        if self.row["tenant_id"] != parameters["tenant_id"]:
            return []
        if self.row["program_id"] != parameters["program_id"]:
            return []
        if "id = :pending_action_id" in sql:
            if self.row["id"] != parameters["pending_action_id"]:
                return []
        if "state = 'pending'" in sql:
            if self.row["state"] != _PendingState.PENDING.value:
                return []
        if "expires_at > :now" in sql:
            assert isinstance(parameters["now"], datetime)
            if self.row["expires_at"] <= parameters["now"]:
                return []
        if "expires_at <= :now" in sql:
            assert isinstance(parameters["now"], datetime)
            if self.row["expires_at"] > parameters["now"]:
                return []
        return [dict(self.row)]


class _RecordingRunner:
    def __init__(self, *connections: _FakeConnection) -> None:
        self.connections = connections
        self.options: list[dict[str, object]] = []

    def __call__(self, engine: object, callback: object, **options: object):
        del engine
        self.options.append(options)
        results = [callback(connection) for connection in self.connections]
        assert all(result == results[0] for result in results)
        return results[-1]


def _principal(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "principal": APP_PRINCIPAL,
        "bypasses_rls": False,
        "is_app_member": True,
        "can_create_schema_objects": False,
        "can_create_schemas": False,
    }
    values.update(changes)
    return values


def _action(**changes: object) -> _GatewayAction:
    policy_values: dict[str, object] = {
        "operation": MemoryOperation.RECALL,
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
        "actor_role": "program_lead",
        "purpose": "partner_status",
        "audience": "partner-alpha-synthetic",
        "destination": _Destination.EXTERNAL,
        "policy_version": "bio-demo-v1",
        "requested_memory_ids": (MEMORY_ID,),
        "data_classes": ("IP_CONFIDENTIAL",),
    }
    action_values: dict[str, object] = {
        "request_id": PENDING_ID,
        "session_id": SESSION_ID,
        "intent_id": INTENT_ID,
        "agent_id": "gluevenir-bio",
        "actor_id": "synthetic-program-lead",
        "evaluated_at": NOW,
        "action_arguments_sha256": HASH_A,
        "original_intent_sha256": HASH_B,
        "prior_action_context_sha256": HASH_C,
    }
    policy_changes = changes.pop("policy", {})
    assert isinstance(policy_changes, dict)
    policy_values.update(policy_changes)
    action_values.update(changes)
    return _GatewayAction(policy=_PolicyAction(**policy_values), **action_values)


def _record(**changes: object) -> _PendingActionRecord:
    values: dict[str, object] = {
        "action": _action(),
        "evaluation_receipt_id": EVALUATION_RECEIPT_ID,
        "pending_decision": _Decision.STEP_UP,
        "missing_context": (),
        "expires_at": EXPIRES,
    }
    values.update(changes)
    return _PendingActionRecord.from_gateway_action(**values)


def _row(
    record: _PendingActionRecord | None = None,
    *,
    state: _PendingState = _PendingState.PENDING,
    transitioned_at: datetime | None = None,
) -> dict[str, object]:
    record = record or _record()
    transition_receipt_id = (
        None if state == _PendingState.PENDING else str(TRANSITION_RECEIPT_ID)
    )
    return {
        "id": str(record.pending_action_id),
        "tenant_id": str(record.tenant_id),
        "program_id": str(record.program_id),
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
        "requested_memory_ids": [str(value) for value in record.requested_memory_ids],
        "data_classes": list(record.data_classes),
        "missing_context": list(record.missing_context),
        "action_arguments_sha256": record.action_arguments_sha256,
        "original_intent_sha256": record.original_intent_sha256,
        "prior_action_context_sha256": record.prior_action_context_sha256,
        "pending_decision": record.pending_decision.value,
        "state": state.value,
        "evaluated_at": record.evaluated_at,
        "expires_at": record.expires_at,
        "transition_receipt_id": transition_receipt_id,
        "transitioned_at": transitioned_at,
    }


def _row_from_parameters(parameters: dict[str, object]) -> dict[str, object]:
    row = dict(parameters)
    row["id"] = row.pop("pending_action_id")
    row.update(
        {
            "state": _PendingState.PENDING.value,
            "transition_receipt_id": None,
            "transitioned_at": None,
        }
    )
    return row


def _cas_matches(row: dict[str, object], parameters: dict[str, object]) -> bool:
    names = (
        "tenant_id",
        "program_id",
        "session_id",
        "intent_id",
        "evaluation_receipt_id",
        "action_arguments_sha256",
        "original_intent_sha256",
        "prior_action_context_sha256",
        "pending_decision",
    )
    return row["id"] == parameters["pending_action_id"] and all(
        row[name] == parameters[name] for name in names
    )


def _engine(*, hide_parameters: bool = True):
    return create_engine("sqlite://", hide_parameters=hide_parameters)


def _store(
    connection: _FakeConnection,
) -> tuple[_CockroachPendingActionStore, _RecordingRunner]:
    runner = _RecordingRunner(connection)
    return (
        _CockroachPendingActionStore(
            _engine(),
            application_principal=APP_PRINCIPAL,
            _transaction_runner=runner,
        ),
        runner,
    )


def test_record_reconstructs_gateway_action_after_lambda_style_reload() -> None:
    record = _record()
    connection = _FakeConnection(_row(record))
    store, runner = _store(connection)

    loaded = store.load(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        pending_action_id=PENDING_ID,
        now=NOW + timedelta(minutes=1),
    )

    assert loaded == record
    assert loaded is not None
    assert loaded.to_gateway_action() == _action()
    assert loaded.pending_reason_code == _ReasonCode.HUMAN_APPROVAL_REQUIRED
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]
    assert not hasattr(loaded, "action_arguments")
    assert RAW_ARGUMENT not in repr(loaded)


def test_create_persists_receipt_on_same_connection_before_bounded_insert() -> None:
    connection = _FakeConnection()
    store, runner = _store(connection)
    callback_connections: list[object] = []

    result = store.create(
        _record(),
        persist_evaluation_receipt=lambda current: callback_connections.append(current),
    )

    assert result == _record()
    assert callback_connections == [connection]
    assert len(connection.calls) == 4
    principal, tenant, selected, inserted = connection.calls
    assert "current_user AS principal" in principal[0]
    assert tenant == (
        "SELECT set_config('app.current_tenant', :tenant_id, true)",
        {"tenant_id": str(TENANT_ID)},
    )
    assert "FROM pending_memory_actions" in selected[0]
    assert "FOR UPDATE" in selected[0]
    assert "INSERT INTO pending_memory_actions" in inserted[0]
    assert "ON CONFLICT" not in inserted[0]
    assert inserted[1]["requested_memory_ids"] == [str(MEMORY_ID)]
    assert inserted[1]["data_classes"] == ["IP_CONFIDENTIAL"]
    assert inserted[1]["missing_context"] == []
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]


def test_exact_create_is_idempotent_without_duplicate_receipt_callback() -> None:
    record = _record()
    connection = _FakeConnection(_row(record))
    store, _ = _store(connection)
    callback_calls = 0

    def callback(_: object) -> None:
        nonlocal callback_calls
        callback_calls += 1

    assert store.create(record, persist_evaluation_receipt=callback) == record
    assert callback_calls == 0
    assert len(connection.calls) == 3


def test_create_mismatch_is_rejected_without_receipt_or_write() -> None:
    stored = _record()
    requested = _record(action=_action(action_arguments_sha256="d" * 64))
    connection = _FakeConnection(_row(stored))
    store, _ = _store(connection)
    callback_calls = 0

    def callback(_: object) -> None:
        nonlocal callback_calls
        callback_calls += 1

    with pytest.raises(_PendingStoreConflict, match="create was rejected"):
        store.create(requested, persist_evaluation_receipt=callback)

    assert callback_calls == 0
    assert len(connection.calls) == 3


def test_defer_persists_only_bounded_missing_context() -> None:
    record = _record(
        pending_decision=_Decision.DEFER,
        missing_context=("session_intent", "partner_authorization"),
    )
    assert record.pending_reason_code == _ReasonCode.REQUIRED_CONTEXT_MISSING
    assert record.missing_context == ("session_intent", "partner_authorization")

    with pytest.raises(ValueError, match="unsupported"):
        _record(
            pending_decision=_Decision.DEFER,
            missing_context=("raw_prompt",),
        )


def test_active_load_and_expired_listing_use_exact_timeout_boundary() -> None:
    before = _FakeConnection(_row())
    before_store, _ = _store(before)
    assert (
        before_store.load(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=PENDING_ID,
            now=EXPIRES - timedelta(microseconds=1),
        )
        == _record()
    )

    boundary = _FakeConnection(_row())
    boundary_store, _ = _store(boundary)
    assert (
        boundary_store.load(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=PENDING_ID,
            now=EXPIRES,
        )
        is None
    )
    assert boundary_store.list_expired(
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        now=EXPIRES,
        limit=1,
    ) == (_record(),)
    list_sql, list_parameters = boundary.calls[-1]
    assert "expires_at <= :now" in list_sql
    assert "ORDER BY expires_at, id" in list_sql
    assert "LIMIT :limit" in list_sql
    assert list_parameters["limit"] == 1

    unresolved = _FakeConnection(_row())
    unresolved_store, _ = _store(unresolved)
    assert (
        unresolved_store.load_pending(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=PENDING_ID,
        )
        == _record()
    )
    unresolved_sql, unresolved_parameters = unresolved.calls[-1]
    assert "state = 'pending'" in unresolved_sql
    assert "expires_at" not in unresolved_parameters


def test_transition_is_atomic_exact_cas_and_terminal_replay_is_denied() -> None:
    record = _record()
    connection = _FakeConnection(_row(record))
    store, _ = _store(connection)
    callback_connections: list[object] = []
    transition = _PendingTransition(
        record,
        _PendingState.CONSUMED,
        TRANSITION_RECEIPT_ID,
        NOW + timedelta(minutes=2),
    )

    store.transition(
        transition,
        persist_transition_receipt=lambda current: callback_connections.append(current),
    )

    assert callback_connections == [connection]
    assert connection.row is not None
    assert connection.row["state"] == _PendingState.CONSUMED.value
    update_sql, update_parameters = connection.calls[-1]
    assert "UPDATE pending_memory_actions" in update_sql
    assert "state = 'pending'" in update_sql
    assert "action_arguments_sha256 = :action_arguments_sha256" in update_sql
    assert "original_intent_sha256 = :original_intent_sha256" in update_sql
    assert "prior_action_context_sha256 = :prior_action_context_sha256" in update_sql
    assert "expires_at > :transitioned_at" in update_sql
    assert update_parameters["transition_receipt_id"] == str(TRANSITION_RECEIPT_ID)

    callback_calls = 0

    def replay_callback(_: object) -> None:
        nonlocal callback_calls
        callback_calls += 1

    with pytest.raises(_PendingStoreConflict, match="transition was rejected"):
        store.transition(transition, persist_transition_receipt=replay_callback)
    assert callback_calls == 0


def test_concurrent_cas_miss_rolls_back_transition_receipt_callback() -> None:
    connection = _FakeConnection(_row(), force_cas_miss=True)
    store, _ = _store(connection)
    callback_calls = 0

    def callback(_: object) -> None:
        nonlocal callback_calls
        callback_calls += 1

    transition = _PendingTransition(
        _record(),
        _PendingState.DENIED,
        TRANSITION_RECEIPT_ID,
        NOW + timedelta(minutes=1),
    )
    with pytest.raises(_PendingStoreConflict, match="transition was rejected"):
        store.transition(transition, persist_transition_receipt=callback)

    assert callback_calls == 1
    assert connection.row is not None
    assert connection.row["state"] == _PendingState.PENDING.value


def test_expiry_transition_accepts_equality_and_other_transitions_reject_it() -> None:
    expired = _PendingTransition(
        _record(),
        _PendingState.EXPIRED,
        TRANSITION_RECEIPT_ID,
        EXPIRES,
    )
    connection = _FakeConnection(_row())
    store, _ = _store(connection)
    store.transition(expired, persist_transition_receipt=lambda _: None)
    assert connection.row is not None
    assert connection.row["state"] == _PendingState.EXPIRED.value

    with pytest.raises(ValueError, match="must precede"):
        _PendingTransition(
            _record(),
            _PendingState.DENIED,
            TRANSITION_RECEIPT_ID,
            EXPIRES,
        )
    with pytest.raises(ValueError, match="cannot expire"):
        _PendingTransition(
            _record(),
            _PendingState.EXPIRED,
            TRANSITION_RECEIPT_ID,
            EXPIRES - timedelta(microseconds=1),
        )


@pytest.mark.parametrize(
    "principal",
    [
        _principal(principal="owner"),
        _principal(bypasses_rls=True),
        _principal(is_app_member=False),
        _principal(can_create_schema_objects=True),
        _principal(can_create_schemas=True),
    ],
)
def test_unbounded_runtime_principals_fail_before_tenant_or_data_access(
    principal: dict[str, object],
) -> None:
    connection = _FakeConnection(principal=principal)
    store, _ = _store(connection)

    with pytest.raises(_PendingStoreUnavailable, match="persistence failed"):
        store.load(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=PENDING_ID,
            now=NOW,
        )

    assert len(connection.calls) == 1
    assert "current_user AS principal" in connection.calls[0][0]


def test_retry_reuses_exact_parameters_and_receipt_identity() -> None:
    first = _FakeConnection()
    retry = _FakeConnection()
    runner = _RecordingRunner(first, retry)
    store = _CockroachPendingActionStore(
        _engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=runner,
    )
    callback_connections: list[object] = []

    store.create(
        _record(),
        persist_evaluation_receipt=lambda current: callback_connections.append(current),
    )

    assert first.calls == retry.calls
    assert callback_connections == [first, retry]
    assert first.calls[-1][1]["evaluation_receipt_id"] == str(EVALUATION_RECEIPT_ID)
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]


def test_sql_is_fully_bound_and_parameters_remain_content_safe() -> None:
    connection = _FakeConnection()
    store, _ = _store(connection)
    store.create(_record(), persist_evaluation_receipt=lambda _: None)

    for sql, _ in connection.calls:
        assert str(TENANT_ID) not in sql
        assert str(PROGRAM_ID) not in sql
        assert str(PENDING_ID) not in sql
        assert RAW_ARGUMENT not in sql
    parameter_text = repr([parameters for _, parameters in connection.calls])
    assert RAW_ARGUMENT not in parameter_text
    assert "model_prompt" not in parameter_text
    assert "tool_output" not in parameter_text
    assert "answer" not in parameter_text
    assert set(connection.calls[-1][1]) == {
        "pending_action_id",
        "tenant_id",
        "program_id",
        "session_id",
        "intent_id",
        "evaluation_receipt_id",
        "agent_id",
        "actor_id",
        "actor_role",
        "operation",
        "purpose",
        "audience",
        "destination",
        "policy_version",
        "requested_memory_ids",
        "data_classes",
        "missing_context",
        "action_arguments_sha256",
        "original_intent_sha256",
        "prior_action_context_sha256",
        "pending_decision",
        "evaluated_at",
        "expires_at",
    }


@pytest.mark.parametrize(
    "failure",
    [
        SQLAlchemyError("secret DSN"),
        RuntimeError("restricted source text"),
    ],
)
def test_receipt_callback_errors_are_sanitized(failure: Exception) -> None:
    connection = _FakeConnection()
    store, _ = _store(connection)

    def callback(_: object) -> None:
        raise failure

    with pytest.raises(_PendingStoreUnavailable) as error:
        store.create(_record(), persist_evaluation_receipt=callback)

    assert "secret DSN" not in str(error.value)
    assert "restricted source text" not in str(error.value)


def test_transaction_runner_error_is_sanitized() -> None:
    def failing_runner(engine: object, callback: object, **options: object) -> None:
        del engine, callback, options
        raise SQLAlchemyError("postgresql://user:" + "password@example.invalid")

    store = _CockroachPendingActionStore(
        _engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=failing_runner,
    )
    with pytest.raises(_PendingStoreUnavailable) as error:
        store.load(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=PENDING_ID,
            now=NOW,
        )
    assert "password" not in str(error.value)


def test_constructor_requires_hidden_parameters_and_official_default_runner() -> None:
    with pytest.raises(ValueError, match="hide SQL parameter values"):
        _CockroachPendingActionStore(
            _engine(hide_parameters=False),
            application_principal=APP_PRINCIPAL,
        )
    store = _CockroachPendingActionStore(_engine(), application_principal=APP_PRINCIPAL)
    assert store._transaction_runner is run_transaction


def test_records_and_transitions_are_frozen_and_bounded() -> None:
    record = _record()
    with pytest.raises(FrozenInstanceError):
        record.agent_id = "other"  # type: ignore[misc]
    with pytest.raises(ValueError, match="fifteen-minute"):
        _record(expires_at=NOW + timedelta(minutes=15, microseconds=1))
    with pytest.raises(ValueError, match="STEP_UP"):
        _record(missing_context=("session_intent",))
    with pytest.raises(ValueError, match="terminal"):
        _PendingTransition(
            record,
            _PendingState.PENDING,
            TRANSITION_RECEIPT_ID,
            NOW + timedelta(minutes=1),
        )


def test_terminal_database_row_is_not_loadable_or_recreatable() -> None:
    record = _record()
    connection = _FakeConnection(
        _row(
            record,
            state=_PendingState.DENIED,
            transitioned_at=NOW + timedelta(minutes=1),
        )
    )
    store, _ = _store(connection)
    assert (
        store.load(
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            pending_action_id=PENDING_ID,
            now=NOW + timedelta(seconds=1),
        )
        is None
    )
    with pytest.raises(_PendingStoreConflict, match="create was rejected"):
        store.create(record, persist_evaluation_receipt=lambda _: None)


def test_stale_record_cannot_transition_and_callback_is_not_called() -> None:
    stored = _record()
    stale = replace(stored, action_arguments_sha256="d" * 64)
    connection = _FakeConnection(_row(stored))
    store, _ = _store(connection)
    callback_calls = 0

    def callback(_: object) -> None:
        nonlocal callback_calls
        callback_calls += 1

    with pytest.raises(_PendingStoreConflict, match="transition was rejected"):
        store.transition(
            _PendingTransition(
                stale,
                _PendingState.DENIED,
                TRANSITION_RECEIPT_ID,
                NOW + timedelta(minutes=1),
            ),
            persist_transition_receipt=callback,
        )
    assert callback_calls == 0
