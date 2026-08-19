from __future__ import annotations

import hashlib
import math
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import MultipleResultsFound, NoResultFound, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._memory_lifecycle import (
    _CockroachMemoryLifecycle,
    _LifecycleContext,
    _LifecycleInput,
    _LifecycleResult,
    _RememberInput,
)

TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
PROGRAM_ID = UUID("20000000-0000-4000-8000-000000000001")
MEMORY_ID = UUID("30000000-0000-4000-8000-000000000001")
DERIVATIVE_ID = UUID("30000000-0000-4000-8000-000000000002")
EVENT_ID = UUID("40000000-0000-4000-8000-000000000001")
APP_PRINCIPAL = "gluevenir_runtime"
NOW = datetime(2026, 8, 15, 18, 0, tzinfo=UTC)
CONTENT = "SYNTHETIC DATA: bounded lifecycle test memory."


class _FakeResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows

    def mappings(self) -> _FakeResult:
        return self

    def one(self) -> dict[str, object]:
        if not self.rows:
            raise NoResultFound
        if len(self.rows) > 1:
            raise MultipleResultsFound
        return self.rows[0]

    def all(self) -> list[dict[str, object]]:
        return self.rows


class _FakeConnection:
    def __init__(
        self,
        *,
        eligible: bool = True,
        derivatives: tuple[UUID, ...] = (DERIVATIVE_ID,),
        principal: dict[str, object] | None = None,
        event_succeeds: bool = True,
    ) -> None:
        self.eligible = eligible
        self.derivatives = derivatives
        self.principal = principal or {
            "principal": APP_PRINCIPAL,
            "bypasses_rls": False,
            "is_app_member": True,
            "can_create_schema_objects": False,
            "can_create_schemas": False,
        }
        self.event_succeeds = event_succeeds
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(
        self,
        statement: object,
        parameters: dict[str, object] | None = None,
    ) -> _FakeResult:
        sql = " ".join(str(statement).split())
        self.calls.append((sql, parameters or {}))
        lowered = sql.casefold()
        if "current_user as principal" in lowered:
            return _FakeResult([self.principal])
        if "set_config" in lowered:
            return _FakeResult([])
        if "insert into policy_events" in lowered:
            if not self.event_succeeds:
                raise RuntimeError("event insert failed")
            return _FakeResult([{"id": EVENT_ID}])
        if "source_memory_id = :memory_id" in lowered:
            return _FakeResult([{"id": value} for value in self.derivatives])
        if "insert into memory_records" in lowered:
            return _FakeResult([{"id": MEMORY_ID}] if self.eligible else [])
        if "update memory_records" in lowered:
            return _FakeResult([{"id": MEMORY_ID}] if self.eligible else [])
        raise AssertionError(f"unexpected SQL: {sql}")


class _RecordingRunner:
    def __init__(self, *connections: _FakeConnection) -> None:
        self.connections = connections
        self.options: list[dict[str, object]] = []
        self.committed: list[_LifecycleResult] = []

    def __call__(self, engine: object, callback: object, **options: object):
        del engine
        self.options.append(options)
        results = [callback(connection) for connection in self.connections]
        assert all(result == results[0] for result in results)
        self.committed.append(results[-1])
        return results[-1]


def _context(**changes: object) -> _LifecycleContext:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
        "actor_id": "synthetic-program-lead",
        "actor_role": "program_lead",
        "purpose": "program_status",
        "audience": "internal-program-lead",
        "policy_version": "bio-demo-v1",
    }
    values.update(changes)
    return _LifecycleContext(**values)


def _remember(**changes: object) -> _RememberInput:
    values: dict[str, object] = {
        "context": _context(),
        "memory_id": MEMORY_ID,
        "content": CONTENT,
        "embedding": tuple(float(index) / 256 for index in range(256)),
        "room": "research-confidential",
        "sensitivity": ("IP_CONFIDENTIAL",),
        "purpose_scopes": ("program_status", "research_review"),
        "audience_scopes": ("internal-program-lead", "internal-research"),
        "valid_from": NOW,
        "expires_at": datetime(2027, 8, 15, 18, 0, tzinfo=UTC),
        "created_at": NOW,
        "created_by": "synthetic-program-lead",
        "reason_code": "MEMORY_STORED",
    }
    values.update(changes)
    return _RememberInput(**values)


def _action(**changes: object) -> _LifecycleInput:
    values: dict[str, object] = {
        "context": _context(),
        "memory_id": MEMORY_ID,
        "occurred_at": NOW,
        "reason_code": "SOURCE_WITHDRAWN",
    }
    values.update(changes)
    return _LifecycleInput(**values)


def _store(
    connection: _FakeConnection,
) -> tuple[_CockroachMemoryLifecycle, _RecordingRunner]:
    runner = _RecordingRunner(connection)
    return (
        _CockroachMemoryLifecycle(
            object(),
            application_principal=APP_PRINCIPAL,
            _transaction_runner=runner,
        ),
        runner,
    )


def test_remember_orders_principal_context_memory_and_content_free_event() -> None:
    connection = _FakeConnection(derivatives=())
    store, runner = _store(connection)

    result = store.remember(_remember())

    expected_hash = hashlib.sha256(CONTENT.encode("utf-8")).hexdigest()
    assert result == _LifecycleResult(MEMORY_ID, EVENT_ID, expected_hash)
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]
    assert len(connection.calls) == 4
    principal, context, memory, event = connection.calls
    assert "current_user AS principal" in principal[0]
    assert context == (
        "SELECT set_config('app.current_tenant', :tenant_id, true)",
        {"tenant_id": str(TENANT_ID)},
    )
    memory_sql, memory_params = memory
    lowered = memory_sql.casefold()
    assert "insert into memory_records" in lowered
    assert "cast(:embedding as vector(256))" in lowered
    assert "'active'" in lowered
    assert "source_memory_id" not in lowered
    assert memory_params["tenant_id"] == str(TENANT_ID)
    assert memory_params["program_id"] == str(PROGRAM_ID)
    assert memory_params["content"] == CONTENT
    assert memory_params["content_sha256"] == expected_hash
    assert memory_params["sensitivity"] == ["IP_CONFIDENTIAL"]
    assert memory_params["purpose_scopes"] == ["program_status", "research_review"]
    assert memory_params["audience_scopes"] == [
        "internal-program-lead",
        "internal-research",
    ]
    assert len(str(memory_params["embedding"]).strip("[]").split(",")) == 256
    event_sql, event_params = event
    assert "insert into policy_events" in event_sql.casefold()
    assert event_params["operation"] == "REMEMBER"
    assert event_params["memory_id"] == str(MEMORY_ID)
    forbidden_event_fields = {
        "content",
        "embedding",
        "content_sha256",
        "model_prompt",
        "answer",
    }
    assert forbidden_event_fields.isdisjoint(event_params)
    assert all(
        "on conflict do nothing" not in sql.casefold() for sql, _ in connection.calls
    )


def test_revoke_uses_exact_target_then_quarantines_active_derivatives() -> None:
    connection = _FakeConnection()
    store, _ = _store(connection)

    result = store.revoke(_action())

    assert result == _LifecycleResult(
        MEMORY_ID,
        EVENT_ID,
        quarantined_derivative_ids=(DERIVATIVE_ID,),
    )
    assert len(connection.calls) == 5
    update_sql, update_params = connection.calls[2]
    cascade_sql, cascade_params = connection.calls[3]
    assert "set state = 'revoked', revoked_at = :occurred_at" in update_sql.casefold()
    for exact_filter in (
        "tenant_id = :tenant_id",
        "program_id = :program_id",
        "id = :memory_id",
        "state in ('proposed', 'active', 'quarantined')",
    ):
        assert exact_filter in update_sql.casefold()
    assert update_params == {
        "tenant_id": str(TENANT_ID),
        "program_id": str(PROGRAM_ID),
        "memory_id": str(MEMORY_ID),
        "occurred_at": NOW,
    }
    assert "source_memory_id = :memory_id" in cascade_sql.casefold()
    assert "room = 'external-approved'" in cascade_sql.casefold()
    assert "state = 'active'" in cascade_sql.casefold()
    assert cascade_params == update_params
    assert connection.calls[4][1]["operation"] == "REVOKE"


def test_forget_clears_content_embedding_hash_and_cascades() -> None:
    connection = _FakeConnection()
    store, _ = _store(connection)

    result = store.forget(_action(reason_code="ERASURE_REQUEST"))

    assert result.quarantined_derivative_ids == (DERIVATIVE_ID,)
    update_sql = connection.calls[2][0].casefold()
    for assignment in (
        "state = 'forgotten'",
        "content = null",
        "embedding = null",
        "content_sha256 = null",
    ):
        assert assignment in update_sql
    assert "tenant_id = :tenant_id" in update_sql
    assert "program_id = :program_id" in update_sql
    assert "id = :memory_id" in update_sql
    assert connection.calls[4][1]["operation"] == "FORGET"
    assert connection.calls[4][1]["reason_code"] == "ERASURE_REQUEST"


def test_derivative_ids_are_returned_in_canonical_order() -> None:
    later_id = UUID("30000000-0000-4000-8000-000000000003")
    connection = _FakeConnection(derivatives=(later_id, DERIVATIVE_ID))
    store, _ = _store(connection)

    result = store.revoke(_action())

    assert result.quarantined_derivative_ids == (DERIVATIVE_ID, later_id)


@pytest.mark.parametrize("method_name", ["revoke", "forget"])
def test_ineligible_lifecycle_target_fails_before_cascade_or_event(
    method_name: str,
) -> None:
    connection = _FakeConnection(eligible=False)
    store, runner = _store(connection)

    with pytest.raises(RuntimeError, match="exactly one valid row"):
        getattr(store, method_name)(_action())

    assert len(connection.calls) == 3
    assert runner.committed == []
    assert all("policy_events" not in sql for sql, _ in connection.calls)
    assert all("source_memory_id" not in sql for sql, _ in connection.calls)


def test_event_failure_leaves_the_transaction_without_partial_success() -> None:
    connection = _FakeConnection(event_succeeds=False)
    store, runner = _store(connection)

    with pytest.raises(RuntimeError, match="event insert failed"):
        store.remember(_remember())

    assert runner.committed == []
    assert "insert into memory_records" in connection.calls[2][0].casefold()
    assert "insert into policy_events" in connection.calls[3][0].casefold()


def test_retry_repeats_the_whole_callback_with_stable_parameters() -> None:
    first = _FakeConnection()
    retry = _FakeConnection()
    runner = _RecordingRunner(first, retry)
    store = _CockroachMemoryLifecycle(
        object(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=runner,
    )

    result = store.forget(_action())

    assert result.memory_id == MEMORY_ID
    assert first.calls == retry.calls
    assert [sql for sql, _ in first.calls] == [sql for sql, _ in retry.calls]
    assert len(first.calls) == 5


@pytest.mark.parametrize(
    "principal",
    [
        {
            "principal": "owner",
            "bypasses_rls": True,
            "is_app_member": True,
            "can_create_schema_objects": True,
            "can_create_schemas": False,
        },
        {
            "principal": APP_PRINCIPAL,
            "bypasses_rls": True,
            "is_app_member": True,
            "can_create_schema_objects": False,
            "can_create_schemas": False,
        },
        {
            "principal": APP_PRINCIPAL,
            "bypasses_rls": False,
            "is_app_member": False,
            "can_create_schema_objects": False,
            "can_create_schemas": False,
        },
        {
            "principal": APP_PRINCIPAL,
            "bypasses_rls": False,
            "is_app_member": True,
            "can_create_schema_objects": True,
            "can_create_schemas": False,
        },
        {
            "principal": APP_PRINCIPAL,
            "bypasses_rls": False,
            "is_app_member": True,
            "can_create_schema_objects": False,
            "can_create_schemas": True,
        },
    ],
)
def test_privileged_or_unbounded_principal_is_rejected_before_tenant_access(
    principal: dict[str, object],
) -> None:
    connection = _FakeConnection(principal=principal)
    store, runner = _store(connection)

    with pytest.raises(PermissionError, match="bounded app role"):
        store.revoke(_action())

    assert len(connection.calls) == 1
    assert runner.committed == []


def test_inputs_are_frozen_and_trim_bounded_provenance_fields() -> None:
    context = _context(
        actor_id=" synthetic-actor ",
        actor_role=" lead ",
        policy_version=" demo-v1 ",
    )
    item = _remember(
        context=context,
        created_by=" synthetic-actor ",
        reason_code=" MEMORY_STORED ",
    )

    assert context.actor_id == "synthetic-actor"
    assert item.created_by == "synthetic-actor"
    assert item.reason_code == "MEMORY_STORED"
    with pytest.raises(FrozenInstanceError):
        item.content = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"memory_id": str(MEMORY_ID)}, TypeError),
        ({"content": ""}, ValueError),
        ({"content": "x" * 2_001}, ValueError),
        ({"embedding": (0.0,) * 255}, ValueError),
        ({"embedding": (0.0,) * 255 + (1,)}, TypeError),
        ({"embedding": (0.0,) * 255 + (math.inf,)}, ValueError),
        ({"room": "external-approved"}, ValueError),
        ({"room": "unknown"}, ValueError),
        ({"context": object()}, TypeError),
        ({"sensitivity": []}, TypeError),
        ({"sensitivity": ("EXTERNAL_APPROVED",)}, ValueError),
        ({"sensitivity": ("UNKNOWN",)}, ValueError),
        ({"purpose_scopes": ()}, ValueError),
        ({"purpose_scopes": ("program_status", "program_status")}, ValueError),
        ({"audience_scopes": ("public",)}, ValueError),
        ({"valid_from": datetime(2026, 8, 15)}, ValueError),
        ({"expires_at": NOW}, ValueError),
        ({"created_at": datetime(2026, 8, 15)}, ValueError),
        ({"created_by": " "}, ValueError),
        ({"reason_code": " "}, ValueError),
        ({"reason_code": CONTENT}, ValueError),
    ],
)
def test_remember_rejects_invalid_or_unbounded_input(
    changes: dict[str, object],
    error: type[Exception],
) -> None:
    with pytest.raises(error):
        _remember(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant_id": str(TENANT_ID)},
        {"program_id": str(PROGRAM_ID)},
        {"actor_id": ""},
        {"actor_role": "x" * 257},
        {"purpose": "arbitrary"},
        {"audience": "public"},
        {"policy_version": ""},
    ],
)
def test_context_rejects_invalid_identity_policy_or_scopes(
    changes: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        _context(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"memory_id": str(MEMORY_ID)},
        {"context": object()},
        {"occurred_at": datetime(2026, 8, 15)},
        {"reason_code": ""},
        {"reason_code": CONTENT},
    ],
)
def test_lifecycle_action_rejects_invalid_target_time_or_reason(
    changes: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        _action(**changes)


def test_methods_reject_untyped_inputs_and_default_to_official_runner() -> None:
    store = _CockroachMemoryLifecycle(object(), application_principal=APP_PRINCIPAL)

    assert store._transaction_runner is run_transaction
    with pytest.raises(TypeError, match="_RememberInput"):
        store.remember(object())
    with pytest.raises(TypeError, match="_LifecycleInput"):
        store.revoke(object())
    with pytest.raises(TypeError, match="_LifecycleInput"):
        store.forget(object())


def test_real_runtime_engine_must_hide_parameter_values() -> None:
    unsafe_engine = create_engine("sqlite://")
    safe_engine = create_engine("sqlite://", hide_parameters=True)
    try:
        with pytest.raises(ValueError, match="hide SQL parameter"):
            _CockroachMemoryLifecycle(
                unsafe_engine,
                application_principal=APP_PRINCIPAL,
            )
        _CockroachMemoryLifecycle(
            safe_engine,
            application_principal=APP_PRINCIPAL,
        )
    finally:
        unsafe_engine.dispose()
        safe_engine.dispose()


def test_remember_sanitizes_database_exceptions() -> None:
    def failing_runner(*_args: object, **_kwargs: object) -> _LifecycleResult:
        raise SQLAlchemyError(CONTENT)

    store = _CockroachMemoryLifecycle(
        object(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=failing_runner,
    )

    with pytest.raises(RuntimeError, match="memory transaction failed") as error:
        store.remember(_remember())

    assert CONTENT not in str(error.value)
    assert error.value.__cause__ is None
