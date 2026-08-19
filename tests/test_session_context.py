from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._session_context import (
    _CandidateLabel,
    _ClassificationCount,
    _CockroachSessionContextWriter,
    _prior_receipt_context_sha256,
    _SessionContextRecord,
)

TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
PROGRAM_ID = UUID("20000000-0000-4000-8000-000000000001")
SESSION_ID = UUID("30000000-0000-4000-8000-000000000001")
INTENT_ID = UUID("40000000-0000-4000-8000-000000000001")
RECEIPT_ID = UUID("50000000-0000-4000-8000-000000000001")
SECOND_RECEIPT_ID = UUID("50000000-0000-4000-8000-000000000002")
APP_PRINCIPAL = "gluevenir_runtime"
RAW_INTENT = "SYNTHETIC restricted formulation request"
INTENT_HASH = hashlib.sha256(RAW_INTENT.encode()).hexdigest()
NOW = datetime(2026, 8, 15, 18, 5, tzinfo=UTC)


class _FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def mappings(self) -> _FakeResult:
        return self

    def one(self) -> dict[str, Any]:
        assert len(self.rows) == 1
        return self.rows[0]

    def one_or_none(self) -> dict[str, Any] | None:
        assert len(self.rows) <= 1
        return self.rows[0] if self.rows else None


class _FakeConnection:
    def __init__(
        self,
        existing: dict[str, Any] | None = None,
        *,
        principal: dict[str, object] | None = None,
        valid_receipt_ids: frozenset[UUID] = frozenset({RECEIPT_ID, SECOND_RECEIPT_ID}),
    ) -> None:
        self.existing = existing
        self.principal = principal or {
            "principal": APP_PRINCIPAL,
            "bypasses_rls": False,
            "is_app_member": True,
            "can_create_schema_objects": False,
            "can_create_schemas": False,
        }
        self.valid_receipt_ids = valid_receipt_ids
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
            return _FakeResult([{}])
        if lowered.startswith("select") and "from session_context" in lowered:
            return _FakeResult([] if self.existing is None else [self.existing])
        if lowered.startswith("select") and "from recall_receipts" in lowered:
            receipt_id = UUID(str(bound["receipt_id"]))
            return _FakeResult(
                [{"id": receipt_id}] if receipt_id in self.valid_receipt_ids else []
            )
        if lowered.startswith("insert into session_context"):
            return _FakeResult([{"session_id": SESSION_ID}])
        if lowered.startswith("update session_context"):
            return _FakeResult([{"session_id": SESSION_ID}])
        raise AssertionError(f"unexpected SQL: {sql}")


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


def _record(**changes: object) -> _SessionContextRecord:
    values: dict[str, object] = {
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
        "session_id": SESSION_ID,
        "intent_id": INTENT_ID,
        "intent_label": "PROGRAM_STATUS",
        "original_intent_sha256": INTENT_HASH,
        "agent_id": "gluevenir-bio",
        "actor_id": "demo-program-lead",
        "actor_role": "program_lead",
        "declared_purpose": "program_status",
        "declared_audience": "internal",
        "classification_summary": (
            _ClassificationCount(_CandidateLabel.IP_CONFIDENTIAL, 2),
            _ClassificationCount(_CandidateLabel.PHI_CANDIDATE, 1),
        ),
        "prior_receipt_ids": (RECEIPT_ID,),
        "created_at": NOW,
        "updated_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
    }
    values.update(changes)
    return _SessionContextRecord(**values)


def _row(record: _SessionContextRecord | None = None) -> dict[str, object]:
    record = record or _record()
    return {
        "tenant_id": record.tenant_id,
        "program_id": record.program_id,
        "session_id": record.session_id,
        "intent_id": record.intent_id,
        "intent_label": record.intent_label,
        "original_intent_sha256": record.original_intent_sha256,
        "agent_id": record.agent_id,
        "actor_id": record.actor_id,
        "actor_role": record.actor_role,
        "declared_purpose": record.declared_purpose,
        "declared_audience": record.declared_audience,
        "classification_summary": {
            item.label.value: item.count for item in record.classification_summary
        },
        "prior_receipt_ids": list(record.prior_receipt_ids),
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "expires_at": record.expires_at,
    }


def _writer(connection: _FakeConnection):
    runner = _RecordingRunner(connection)
    writer = _CockroachSessionContextWriter(
        _safe_engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=runner,
    )
    return writer, runner


def test_absent_session_is_inserted_after_principal_context_and_exact_read() -> None:
    connection = _FakeConnection()
    writer, runner = _writer(connection)
    record = _record()

    assert writer.write(record) is record

    assert len(connection.calls) == 4
    principal, context, select, insert = connection.calls
    assert "current_user AS principal" in principal[0]
    assert "rolbypassrls" in principal[0]
    assert "pg_has_role" in principal[0]
    assert principal[1] == {}
    assert context == (
        "SELECT set_config('app.current_tenant', :tenant_id, true)",
        {"tenant_id": str(TENANT_ID)},
    )
    assert "FROM session_context" in select[0]
    assert "tenant_id = :tenant_id" in select[0]
    assert "program_id = :program_id" in select[0]
    assert "session_id = :session_id" in select[0]
    assert "FOR UPDATE" in select[0]
    assert select[1] == {
        "tenant_id": str(TENANT_ID),
        "program_id": str(PROGRAM_ID),
        "session_id": str(SESSION_ID),
    }
    assert "ON CONFLICT" not in insert[0].upper()
    assert insert[1]["classification_summary"] == (
        '{"IP_CONFIDENTIAL":2,"PHI_CANDIDATE":1}'
    )
    assert insert[1]["prior_receipt_ids"] == [str(RECEIPT_ID)]
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]


def test_exact_existing_session_is_returned_without_write() -> None:
    record = _record()
    connection = _FakeConnection(_row(record))
    writer, _ = _writer(connection)

    assert writer.write(record) == record
    assert len(connection.calls) == 3


def test_prior_receipts_can_only_evolve_by_append_with_later_update() -> None:
    stored = _record()
    requested = replace(
        stored,
        prior_receipt_ids=(RECEIPT_ID, SECOND_RECEIPT_ID),
        updated_at=NOW + timedelta(minutes=1),
    )
    connection = _FakeConnection(_row(stored))
    writer, _ = _writer(connection)

    assert writer.write(requested) == requested
    receipt_sql, receipt_params = connection.calls[-2]
    update_sql, update_params = connection.calls[-1]
    assert "FROM recall_receipts" in receipt_sql
    assert "tenant_id = :tenant_id" in receipt_sql
    assert "program_id = :program_id" in receipt_sql
    assert "session_id = :session_id" in receipt_sql
    assert receipt_params == {
        "tenant_id": str(TENANT_ID),
        "program_id": str(PROGRAM_ID),
        "session_id": str(SESSION_ID),
        "receipt_id": str(SECOND_RECEIPT_ID),
    }
    assert update_sql.startswith("UPDATE session_context")
    assert "stored_updated_at" in update_sql
    assert "stored_prior_receipt_ids" in update_sql
    assert update_params["prior_receipt_ids"] == [
        str(RECEIPT_ID),
        str(SECOND_RECEIPT_ID),
    ]


def test_append_rejects_receipt_outside_exact_session_before_update() -> None:
    stored = _record()
    requested = replace(
        stored,
        prior_receipt_ids=(RECEIPT_ID, SECOND_RECEIPT_ID),
        updated_at=NOW + timedelta(minutes=1),
    )
    connection = _FakeConnection(
        _row(stored),
        valid_receipt_ids=frozenset({RECEIPT_ID}),
    )
    writer, _ = _writer(connection)

    with pytest.raises(PermissionError, match="does not belong"):
        writer.write(requested)

    assert "FROM recall_receipts" in connection.calls[-1][0]
    assert all(
        not sql.startswith("UPDATE session_context") for sql, _ in connection.calls
    )


def test_stale_prefix_retry_returns_newer_stored_history_idempotently() -> None:
    stale = _record()
    stored = replace(
        stale,
        prior_receipt_ids=(RECEIPT_ID, SECOND_RECEIPT_ID),
        updated_at=NOW + timedelta(minutes=1),
    )
    connection = _FakeConnection(_row(stored))
    writer, _ = _writer(connection)

    assert writer.write(stale) == stored
    assert len(connection.calls) == 3


@pytest.mark.parametrize(
    "changes",
    [
        {"intent_id": UUID("40000000-0000-4000-8000-000000000002")},
        {"original_intent_sha256": "a" * 64},
        {"actor_role": "external_partner"},
        {"declared_purpose": "external_update"},
        {"classification_summary": (_ClassificationCount(_CandidateLabel.SECRET, 1),)},
        {"created_at": NOW - timedelta(seconds=1)},
        {"expires_at": NOW + timedelta(hours=2)},
    ],
)
def test_existing_immutable_context_mismatch_is_denied(
    changes: dict[str, object],
) -> None:
    connection = _FakeConnection(_row())
    writer, _ = _writer(connection)

    with pytest.raises(PermissionError, match="does not match"):
        writer.write(_record(**changes))
    assert len(connection.calls) == 3


def test_divergent_prior_receipt_history_is_denied() -> None:
    connection = _FakeConnection(_row())
    writer, _ = _writer(connection)

    with pytest.raises(PermissionError, match="cannot diverge"):
        writer.write(
            _record(
                prior_receipt_ids=(SECOND_RECEIPT_ID,),
                updated_at=NOW + timedelta(minutes=1),
            )
        )


@pytest.mark.parametrize(
    "principal",
    [
        {
            "principal": "owner",
            "bypasses_rls": False,
            "is_app_member": True,
            "can_create_schema_objects": False,
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
def test_unbounded_principal_is_rejected_before_context_or_data_access(
    principal: dict[str, object],
) -> None:
    connection = _FakeConnection(principal=principal)
    writer, _ = _writer(connection)

    with pytest.raises(PermissionError, match="bounded app role"):
        writer.write(_record())
    assert len(connection.calls) == 1


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"tenant_id": str(TENANT_ID)}, TypeError),
        ({"intent_label": "not normalized label"}, ValueError),
        ({"original_intent_sha256": "A" * 64}, ValueError),
        ({"agent_id": RAW_INTENT}, ValueError),
        ({"classification_summary": []}, TypeError),
        (
            {
                "classification_summary": (
                    _ClassificationCount(_CandidateLabel.PII, 1),
                    _ClassificationCount(_CandidateLabel.PII, 2),
                )
            },
            ValueError,
        ),
        ({"prior_receipt_ids": [RECEIPT_ID]}, TypeError),
        ({"prior_receipt_ids": (RECEIPT_ID,) * 2}, ValueError),
        ({"created_at": NOW.replace(tzinfo=None)}, ValueError),
        ({"updated_at": NOW - timedelta(seconds=1)}, ValueError),
        ({"expires_at": NOW}, ValueError),
    ],
)
def test_record_rejects_unbounded_or_invalid_values(
    changes: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        _record(**changes)


@pytest.mark.parametrize("count", [True, 0, 10_001])
def test_classification_counts_are_bounded(count: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _ClassificationCount(_CandidateLabel.PII, count)  # type: ignore[arg-type]


@pytest.mark.parametrize("principal", ["", "   ", None])
def test_writer_requires_exact_bounded_application_principal(principal: object) -> None:
    with pytest.raises((TypeError, ValueError), match="application_principal"):
        _CockroachSessionContextWriter(
            _safe_engine(),
            application_principal=principal,  # type: ignore[arg-type]
        )


def test_record_is_frozen_normalized_and_content_free() -> None:
    record = _record()

    assert record.intent_label == "program_status"
    assert [item.label for item in record.classification_summary] == [
        _CandidateLabel.IP_CONFIDENTIAL,
        _CandidateLabel.PHI_CANDIDATE,
    ]
    assert RAW_INTENT not in repr(record)
    with pytest.raises(FrozenInstanceError):
        record.actor_id = "other"  # type: ignore[misc]


def test_prior_receipt_context_hash_is_canonical_bounded_and_ordered() -> None:
    assert _prior_receipt_context_sha256(()) == hashlib.sha256(b"[]").hexdigest()
    first = _prior_receipt_context_sha256((RECEIPT_ID, SECOND_RECEIPT_ID))
    second = _prior_receipt_context_sha256((SECOND_RECEIPT_ID, RECEIPT_ID))

    assert first != second
    with pytest.raises(ValueError, match="duplicates"):
        _prior_receipt_context_sha256((RECEIPT_ID, RECEIPT_ID))


def test_retry_repeats_stable_content_free_parameters_and_context() -> None:
    first = _FakeConnection()
    retry = _FakeConnection()
    runner = _RecordingRunner(first, retry)
    writer = _CockroachSessionContextWriter(
        _safe_engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=runner,
    )

    writer.write(_record())

    assert first.calls == retry.calls
    captured = repr(first.calls)
    assert RAW_INTENT not in captured
    assert "SYNTHETIC" not in captured
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]


def test_default_runner_and_real_engine_parameter_hiding() -> None:
    unsafe_engine = create_engine("sqlite://")
    safe_engine = _safe_engine()
    try:
        with pytest.raises(TypeError, match="SQLAlchemy Engine"):
            _CockroachSessionContextWriter(
                object(),  # type: ignore[arg-type]
                application_principal=APP_PRINCIPAL,
            )
        with pytest.raises(ValueError, match="hide SQL parameter"):
            _CockroachSessionContextWriter(
                unsafe_engine,
                application_principal=APP_PRINCIPAL,
            )
        writer = _CockroachSessionContextWriter(
            safe_engine,
            application_principal=APP_PRINCIPAL,
        )
        assert writer._transaction_runner is run_transaction
    finally:
        unsafe_engine.dispose()
        safe_engine.dispose()


def _safe_engine():
    return create_engine("sqlite://", hide_parameters=True)


def test_database_error_is_sanitized_without_raw_intent_or_cause() -> None:
    def failing_runner(*_args: object, **_kwargs: object) -> _SessionContextRecord:
        raise SQLAlchemyError(RAW_INTENT)

    writer = _CockroachSessionContextWriter(
        _safe_engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=failing_runner,
    )

    with pytest.raises(
        RuntimeError, match="session context transaction failed"
    ) as error:
        writer.write(_record())

    assert RAW_INTENT not in str(error.value)
    assert error.value.__cause__ is None
