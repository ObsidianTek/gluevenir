from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import MultipleResultsFound, NoResultFound, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._approval_store import (
    _ApprovalStoreUnavailable,
    _CockroachApprovalStore,
    _TrustedReviewerIdentity,
)
from gluevenir._policy import _ApprovedDerivative

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("22222222-2222-4222-8222-222222222222")
PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
OTHER_PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2")
SOURCE_ID = UUID("10000000-0000-4000-8000-000000000001")
DERIVATIVE_ID = UUID("10000000-0000-4000-8000-000000000002")
APPROVAL_ID = UUID("30000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 8, 15, 18, 30, tzinfo=UTC)
REVIEWED_AT = NOW - timedelta(minutes=10)
EXPIRES_AT = NOW + timedelta(days=5)
SOURCE_HASH = "a" * 64
DERIVATIVE_HASH = "b" * 64
REVIEWER_ID = "human-reviewer-synthetic-01"
APP_PRINCIPAL = "gluevenir_runtime"


class _FakeResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self) -> _FakeResult:
        return self

    def one(self) -> dict[str, object]:
        if not self._rows:
            raise NoResultFound()
        if len(self._rows) > 1:
            raise MultipleResultsFound()
        return self._rows[0]

    def one_or_none(self) -> dict[str, object] | None:
        if len(self._rows) > 1:
            raise MultipleResultsFound()
        return self._rows[0] if self._rows else None


class _FakeConnection:
    def __init__(
        self,
        rows: list[dict[str, object]],
        *,
        principal: dict[str, object] | None = None,
    ) -> None:
        self.rows = rows
        self.principal = principal or _principal()
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(
        self,
        statement: object,
        parameters: dict[str, object] | None = None,
    ) -> _FakeResult:
        sql = " ".join(str(statement).split())
        values = parameters or {}
        self.calls.append((sql, values))
        if "current_user AS principal" in sql:
            return _FakeResult([self.principal])
        if "set_config" in sql:
            return _FakeResult([])
        if "FROM derivative_approvals AS approval" in sql:
            return _FakeResult(self.rows)
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


def _reviewer(**changes: object) -> _TrustedReviewerIdentity:
    values: dict[str, object] = {
        "reviewer_id": REVIEWER_ID,
        "reviewer_role": "human_reviewer",
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
    }
    values.update(changes)
    return _TrustedReviewerIdentity(**values)


def _row(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "approval_id": APPROVAL_ID,
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
        "source_memory_id": SOURCE_ID,
        "derivative_memory_id": DERIVATIVE_ID,
        "source_sha256": SOURCE_HASH,
        "derivative_sha256": DERIVATIVE_HASH,
        "purpose_scopes": ["partner_status"],
        "audience_scopes": ["partner-alpha-synthetic"],
        "approval_policy_version": "bio-demo-v1",
        "reviewed_by": REVIEWER_ID,
        "reviewed_at": REVIEWED_AT,
        "approval_expires_at": EXPIRES_AT,
        "source_content_sha256": SOURCE_HASH,
        "source_policy_version": "bio-demo-v1",
        "source_state": "active",
        "source_valid_from": NOW - timedelta(days=1),
        "source_expires_at": None,
        "source_revoked_at": None,
        "derivative_content_sha256": DERIVATIVE_HASH,
        "derivative_policy_version": "bio-demo-v1",
        "derivative_state": "active",
        "derivative_valid_from": NOW - timedelta(days=1),
        "derivative_expires_at": EXPIRES_AT,
        "derivative_revoked_at": None,
        "derivative_source_memory_id": SOURCE_ID,
    }
    values.update(changes)
    return values


def _engine(*, hide_parameters: bool = True):
    return create_engine("sqlite://", hide_parameters=hide_parameters)


def _store(
    connection: _FakeConnection,
) -> tuple[_CockroachApprovalStore, _RecordingRunner]:
    runner = _RecordingRunner(connection)
    return (
        _CockroachApprovalStore(
            _engine(),
            application_principal=APP_PRINCIPAL,
            _transaction_runner=runner,
        ),
        runner,
    )


def _load(
    store: _CockroachApprovalStore,
    *,
    reviewer: _TrustedReviewerIdentity | None = None,
    purpose: str = "partner_status",
    audience: str = "partner-alpha-synthetic",
    policy_version: str = "bio-demo-v1",
) -> _ApprovedDerivative | None:
    return store.load_approved(
        APPROVAL_ID,
        reviewer=reviewer or _reviewer(),
        purpose=purpose,
        audience=audience,
        policy_version=policy_version,
        now=NOW,
    )


def test_load_returns_exact_content_safe_approved_derivative() -> None:
    connection = _FakeConnection([_row()])
    store, runner = _store(connection)

    result = _load(store)

    assert result == _ApprovedDerivative(
        approval_id=APPROVAL_ID,
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        source_memory_id=SOURCE_ID,
        derivative_memory_id=DERIVATIVE_ID,
        source_sha256=SOURCE_HASH,
        derivative_sha256=DERIVATIVE_HASH,
        purpose="partner_status",
        audience="partner-alpha-synthetic",
        policy_version="bio-demo-v1",
        reviewed_at=REVIEWED_AT,
        expires_at=EXPIRES_AT,
        source_active=True,
        derivative_active=True,
        reviewed_by=REVIEWER_ID,
        reviewer_role="human_reviewer",
    )
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]
    assert len(connection.calls) == 3
    principal, tenant, lookup = connection.calls
    assert "current_user AS principal" in principal[0]
    assert tenant == (
        "SELECT set_config('app.current_tenant', :tenant_id, true)",
        {"tenant_id": str(TENANT_ID)},
    )
    assert lookup[1] == {
        "approval_id": str(APPROVAL_ID),
        "tenant_id": str(TENANT_ID),
        "program_id": str(PROGRAM_ID),
        "reviewer_id": REVIEWER_ID,
        "purpose": "partner_status",
        "audience": "partner-alpha-synthetic",
        "policy_version": "bio-demo-v1",
        "now": NOW,
    }


def test_lookup_sql_enforces_exact_approval_scope_hash_and_lifecycle() -> None:
    connection = _FakeConnection([_row()])
    store, _ = _store(connection)

    _load(store)

    sql = connection.calls[2][0].casefold()
    required = (
        "approval.id = :approval_id",
        "approval.tenant_id = :tenant_id",
        "approval.program_id = :program_id",
        "approval.decision = 'approved'",
        "approval.reviewed_by = :reviewer_id",
        "approval.reviewed_at <= :now",
        "approval.expires_at > :now",
        "approval.purpose_scopes = array[cast(:purpose as string)]",
        "approval.audience_scopes = array[cast(:audience as string)]",
        "approval.policy_version = :policy_version",
        "approval.source_sha256 = source.content_sha256",
        "approval.source_sha256 = sha256(cast(source.content as bytes))",
        "approval.derivative_sha256 = derivative.content_sha256",
        "approval.derivative_sha256 = sha256(cast(derivative.content as bytes))",
        "source.policy_version = :policy_version",
        "derivative.policy_version = :policy_version",
        "source.state = 'active'",
        "source.revoked_at is null",
        "derivative.state = 'active'",
        "derivative.room = 'external-approved'",
        "derivative.source_memory_id = source.id",
        "derivative.expires_at = approval.expires_at",
        "derivative.revoked_at is null",
        "derivative.purpose_scopes = approval.purpose_scopes",
        "derivative.audience_scopes = approval.audience_scopes",
    )
    for clause in required:
        assert clause in sql
    assert str(APPROVAL_ID) not in connection.calls[2][0]
    assert REVIEWER_ID not in connection.calls[2][0]
    assert "exact_derivative_text" not in sql


@pytest.mark.parametrize(
    "load_kwargs",
    [
        {"reviewer": _reviewer(reviewer_id="wrong-reviewer")},
        {"reviewer": _reviewer(tenant_id=OTHER_TENANT_ID)},
        {"reviewer": _reviewer(program_id=OTHER_PROGRAM_ID)},
        {"purpose": "research_review"},
        {"audience": "partner-beta-synthetic"},
        {"policy_version": "other-policy"},
    ],
)
def test_ineligible_reviewer_tenant_program_or_scope_returns_no_authority(
    load_kwargs: dict[str, object],
) -> None:
    connection = _FakeConnection([])
    store, _ = _store(connection)

    result = _load(store, **load_kwargs)

    assert result is None
    assert len(connection.calls) == 3


@pytest.mark.parametrize(
    "row_changes",
    [
        {"reviewed_by": "wrong-reviewer"},
        {"tenant_id": OTHER_TENANT_ID},
        {"program_id": OTHER_PROGRAM_ID},
        {"purpose_scopes": ["research_review"]},
        {"audience_scopes": ["partner-beta-synthetic"]},
        {"source_content_sha256": "c" * 64},
        {"derivative_content_sha256": "c" * 64},
        {"source_state": "revoked"},
        {"derivative_state": "quarantined"},
        {"source_revoked_at": NOW - timedelta(minutes=1)},
        {"derivative_revoked_at": NOW - timedelta(minutes=1)},
        {"reviewed_at": NOW + timedelta(seconds=1)},
        {"approval_expires_at": NOW},
        {"derivative_expires_at": EXPIRES_AT + timedelta(seconds=1)},
        {"source_policy_version": "other-policy"},
        {"derivative_policy_version": "other-policy"},
        {"derivative_source_memory_id": DERIVATIVE_ID},
    ],
)
def test_untrusted_hash_scope_or_lifecycle_row_fails_closed(
    row_changes: dict[str, object],
) -> None:
    connection = _FakeConnection([_row(**row_changes)])
    store, _ = _store(connection)

    with pytest.raises(_ApprovalStoreUnavailable, match="lookup is unavailable"):
        _load(store)


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
def test_privileged_or_wrong_principal_fails_before_tenant_context(
    principal: dict[str, object],
) -> None:
    connection = _FakeConnection([_row()], principal=principal)
    store, _ = _store(connection)

    with pytest.raises(_ApprovalStoreUnavailable, match="lookup is unavailable"):
        _load(store)

    assert len(connection.calls) == 1


def test_retry_reestablishes_authority_and_reuses_exact_bound_parameters() -> None:
    first = _FakeConnection([_row()])
    retry = _FakeConnection([_row()])
    runner = _RecordingRunner(first, retry)
    store = _CockroachApprovalStore(
        _engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=runner,
    )

    result = _load(store)

    assert result is not None
    assert first.calls == retry.calls
    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]


def test_database_error_and_invalid_row_do_not_expose_details() -> None:
    def failing_runner(engine: object, callback: object, **options: object) -> None:
        del engine, callback, options
        raise SQLAlchemyError("secret database address and derivative text")

    store = _CockroachApprovalStore(
        _engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=failing_runner,
    )

    with pytest.raises(_ApprovalStoreUnavailable) as error:
        _load(store)

    assert str(error.value) == "approval lookup is unavailable"
    assert "secret" not in str(error.value)
    malformed_store, _ = _store(_FakeConnection([_row(source_sha256="bad")]))
    with pytest.raises(_ApprovalStoreUnavailable) as malformed:
        _load(malformed_store)
    assert str(malformed.value) == "approval lookup is unavailable"


def test_query_parameters_and_results_are_content_safe() -> None:
    connection = _FakeConnection([_row()])
    store, _ = _store(connection)

    result = _load(store)

    all_parameters = repr([values for _, values in connection.calls])
    returned = repr(result)
    forbidden = (
        "restricted source text",
        "exact derivative text",
        "model prompt",
        "detector match",
    )
    assert all(value not in all_parameters for value in forbidden)
    assert all(value not in returned for value in forbidden)
    assert "source.content" not in repr(connection.calls[2][1])
    assert "derivative.content" not in repr(connection.calls[2][1])


def test_trusted_reviewer_is_frozen_and_rejects_unapproved_role() -> None:
    reviewer = _reviewer()

    with pytest.raises(FrozenInstanceError):
        reviewer.reviewer_id = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError, match="not authorized"):
        _reviewer(reviewer_role="browser-user")


def test_constructor_requires_hidden_parameters_and_official_default_runner() -> None:
    with pytest.raises(ValueError, match="hide SQL parameter values"):
        _CockroachApprovalStore(
            _engine(hide_parameters=False),
            application_principal=APP_PRINCIPAL,
        )

    store = _CockroachApprovalStore(
        _engine(),
        application_principal=APP_PRINCIPAL,
    )

    assert store._transaction_runner is run_transaction
