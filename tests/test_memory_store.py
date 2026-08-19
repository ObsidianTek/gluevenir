from __future__ import annotations

import hashlib
import math
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._memory_store import (
    RecalledMemory,
    RecallScope,
    _CockroachMemoryStore,
)

TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
PROGRAM_ID = UUID("20000000-0000-4000-8000-000000000001")
MEMORY_ID = UUID("30000000-0000-4000-8000-000000000001")
CONTENT = "SYNTHETIC DATA: bounded status memory."
HASH = hashlib.sha256(CONTENT.encode()).hexdigest()
APP_PRINCIPAL = "gluevenir_runtime"


class _FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def mappings(self) -> _FakeResult:
        return self

    def all(self) -> list[dict[str, Any]]:
        return self._rows

    def one(self) -> dict[str, Any]:
        assert len(self._rows) == 1
        return self._rows[0]


class _FakeConnection:
    def __init__(
        self,
        rows: list[dict[str, Any]],
        *,
        principal: dict[str, object] | None = None,
    ) -> None:
        self.rows = rows
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.principal = principal or {
            "principal": APP_PRINCIPAL,
            "bypasses_rls": False,
            "is_app_member": True,
            "can_create_schema_objects": False,
            "can_create_schemas": False,
        }

    def execute(
        self,
        statement: object,
        parameters: dict[str, object] | None = None,
    ) -> _FakeResult:
        sql = " ".join(str(statement).split())
        self.calls.append((sql, parameters or {}))
        if "current_user AS principal" in sql:
            return _FakeResult([self.principal])
        if "set_config" in sql:
            return _FakeResult([])
        return _FakeResult(self.rows)


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


def _scope(**changes: object) -> RecallScope:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
        "embedding": tuple(float(index) / 256 for index in range(256)),
        "executable_memory_ids": (MEMORY_ID,),
        "now": datetime(2026, 8, 15, 16, 30, tzinfo=UTC),
        "top_k": 4,
        "allowed_rooms": ("clinical-restricted", "research-confidential"),
        "purpose": "program_status",
        "audience": "internal",
    }
    values.update(changes)
    return RecallScope(**values)


def _row() -> dict[str, object]:
    return {
        "memory_id": MEMORY_ID,
        "content": CONTENT,
        "content_sha256": HASH,
    }


def test_recall_sets_local_context_before_one_fully_scoped_vector_query() -> None:
    connection = _FakeConnection([_row()])
    runner = _RecordingRunner(connection)
    scope = _scope()
    store = _CockroachMemoryStore(
        object(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=runner,
    )

    records = store.recall(scope)

    assert records == (RecalledMemory(MEMORY_ID, _row()["content"], HASH),)
    assert len(connection.calls) == 3
    principal_sql, principal_params = connection.calls[0]
    context_sql, context_params = connection.calls[1]
    query_sql, query_params = connection.calls[2]
    assert "current_user AS principal" in principal_sql
    assert "rolbypassrls" in principal_sql
    assert "pg_has_role" in principal_sql
    assert "has_schema_privilege" in principal_sql
    assert "has_database_privilege" in principal_sql
    assert principal_params == {}
    assert context_sql == "SELECT set_config('app.current_tenant', :tenant_id, true)"
    assert context_params == {"tenant_id": str(TENANT_ID)}

    lowered = query_sql.casefold()
    required_filters = (
        "from memory_records as memory",
        "memory.tenant_id = :tenant_id",
        "memory.program_id = :program_id",
        "memory.state = 'active'",
        "memory.content is not null",
        "memory.content_sha256 is not null",
        "memory.embedding is not null",
        "memory.id in (__[postcompile_executable_memory_ids])",
        "memory.room in (__[postcompile_allowed_rooms])",
        "memory.purpose_scopes && array[cast(:purpose as string)]",
        "memory.audience_scopes && array[cast(:audience as string)]",
        "memory.valid_from <= :now",
        "memory.expires_at is null or memory.expires_at > :now",
        "memory.revoked_at is null",
        "memory.room != 'external-approved'",
        "from derivative_approvals as approval",
        "approval.decision = 'approved'",
        "approval.source_memory_id = memory.source_memory_id",
        "approval.reviewed_at <= :now",
        "approval.expires_at = memory.expires_at",
        "approval.expires_at > :now",
        "approval.purpose_scopes = memory.purpose_scopes",
        "approval.audience_scopes = memory.audience_scopes",
        "approval.source_sha256 = source.content_sha256",
        "approval.source_sha256 = sha256(cast(source.content as bytes))",
        "approval.derivative_sha256 = memory.content_sha256",
        "approval.policy_version = memory.policy_version",
        "approval.policy_version = source.policy_version",
        "source.state = 'active'",
        "source.revoked_at is null",
        "order by memory.embedding <=> cast(:query_embedding as vector(256))",
        "limit :top_k",
    )
    for expected in required_filters:
        assert expected in lowered
    assert str(TENANT_ID) not in query_sql
    assert str(PROGRAM_ID) not in query_sql
    assert scope.purpose not in query_sql
    assert scope.audience not in query_sql

    assert query_params["tenant_id"] == str(TENANT_ID)
    assert query_params["program_id"] == str(PROGRAM_ID)
    assert query_params["executable_memory_ids"] == (str(MEMORY_ID),)
    assert query_params["allowed_rooms"] == scope.allowed_rooms
    assert query_params["purpose"] == scope.purpose
    assert query_params["audience"] == scope.audience
    assert query_params["now"] is scope.now
    assert query_params["top_k"] == scope.top_k
    assert query_params["query_embedding"].startswith("[")
    assert len(query_params["query_embedding"].strip("[]").split(",")) == 256
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]


def test_retry_callback_reestablishes_context_without_external_side_effects() -> None:
    first = _FakeConnection([_row()])
    retry = _FakeConnection([_row()])
    runner = _RecordingRunner(first, retry)
    store = _CockroachMemoryStore(
        object(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=runner,
    )

    result = store.recall(_scope())

    assert result[0].memory_id == MEMORY_ID
    assert [call[0] for call in first.calls] == [call[0] for call in retry.calls]
    assert [call[1] for call in first.calls] == [call[1] for call in retry.calls]
    assert "current_user" in first.calls[0][0]
    assert "set_config" in first.calls[1][0]
    assert "memory_records" in first.calls[2][0]


def test_default_transaction_runner_is_the_official_cockroach_helper() -> None:
    store = _CockroachMemoryStore(object(), application_principal=APP_PRINCIPAL)

    assert store._transaction_runner is run_transaction


def test_recall_scope_is_immutable_and_trims_scope_strings() -> None:
    scope = _scope(purpose="  program_status ", audience=" internal  ")

    assert scope.purpose == "program_status"
    assert scope.audience == "internal"
    with pytest.raises(FrozenInstanceError):
        scope.top_k = 3  # type: ignore[misc]


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"tenant_id": str(TENANT_ID)}, TypeError),
        ({"program_id": str(PROGRAM_ID)}, TypeError),
        ({"embedding": (0.0,) * 255}, ValueError),
        ({"embedding": (0.0,) * 255 + (1,)}, TypeError),
        ({"embedding": (0.0,) * 255 + (math.inf,)}, ValueError),
        ({"executable_memory_ids": ()}, ValueError),
        ({"executable_memory_ids": [MEMORY_ID]}, TypeError),
        ({"executable_memory_ids": (str(MEMORY_ID),)}, TypeError),
        ({"executable_memory_ids": (MEMORY_ID, MEMORY_ID)}, ValueError),
        ({"now": datetime(2026, 8, 15)}, ValueError),
        ({"top_k": True}, TypeError),
        ({"top_k": 0}, ValueError),
        ({"top_k": 6}, ValueError),
        ({"allowed_rooms": ()}, ValueError),
        ({"allowed_rooms": ["external-approved"]}, TypeError),
        ({"allowed_rooms": ("not-a-room",)}, ValueError),
        (
            {"allowed_rooms": ("external-approved", "external-approved")},
            ValueError,
        ),
        ({"purpose": " "}, ValueError),
        ({"purpose": "p" * 257}, ValueError),
        ({"audience": ""}, ValueError),
        ({"audience": "a" * 257}, ValueError),
    ],
)
def test_recall_scope_rejects_unbounded_or_invalid_inputs(
    changes: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        _scope(**changes)


@pytest.mark.parametrize(
    "row",
    [
        {"memory_id": "not-a-uuid", "content": "text", "content_sha256": HASH},
        {"memory_id": MEMORY_ID, "content": None, "content_sha256": HASH},
        {"memory_id": MEMORY_ID, "content": "text", "content_sha256": "bad"},
        {"memory_id": MEMORY_ID, "content": "text", "content_sha256": HASH},
    ],
)
def test_recall_fails_closed_on_invalid_database_records(
    row: dict[str, object],
) -> None:
    connection = _FakeConnection([row])
    store = _CockroachMemoryStore(
        object(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=_RecordingRunner(connection),
    )

    with pytest.raises(ValueError, match="database returned"):
        store.recall(_scope())


def test_recall_rejects_non_scope_objects() -> None:
    store = _CockroachMemoryStore(
        object(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=_RecordingRunner(_FakeConnection([])),
    )

    with pytest.raises(TypeError, match="RecallScope"):
        store.recall(object())


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
def test_recall_rejects_privileged_or_unbounded_database_principal(
    principal: dict[str, object],
) -> None:
    connection = _FakeConnection([_row()], principal=principal)
    store = _CockroachMemoryStore(
        object(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=_RecordingRunner(connection),
    )

    with pytest.raises(PermissionError, match="bounded app role"):
        store.recall(_scope())

    assert len(connection.calls) == 1


@pytest.mark.parametrize("principal", ["", "   ", None])
def test_store_requires_an_expected_application_principal(principal: object) -> None:
    with pytest.raises(ValueError, match="application_principal"):
        _CockroachMemoryStore(object(), application_principal=principal)  # type: ignore[arg-type]
