from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.exc import MultipleResultsFound, NoResultFound, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._receipt_store import _CockroachReceiptStore, _ReceiptStoreUnavailable
from gluevenir._receipts import _ReceiptPayload, _ReceiptSigner, _SignedReceipt
from gluevenir._session_context import _prior_receipt_context_sha256

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
INTENT_ID = UUID("33333333-3333-4333-8333-333333333333")
REQUEST_ID = UUID("44444444-4444-4444-8444-444444444444")
RECEIPT_ID = UUID("55555555-5555-4555-8555-555555555555")
MEMORY_ID = UUID("66666666-6666-4666-8666-666666666666")
EVENT_ID = UUID("77777777-7777-4777-8777-777777777777")
APPROVAL_ID = UUID("88888888-8888-4888-8888-888888888888")
NOW = datetime(2026, 8, 15, 18, 30, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
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


class _FakeConnection:
    def __init__(
        self,
        *,
        has_session: bool = True,
        prior_receipt_ids: list[UUID] | None = None,
        principal: dict[str, object] | None = None,
    ) -> None:
        self.has_session = has_session
        self.prior_receipt_ids = prior_receipt_ids or []
        self.principal = principal or {
            "principal": APP_PRINCIPAL,
            "bypasses_rls": False,
            "is_app_member": True,
            "can_create_schema_objects": False,
            "can_create_schemas": False,
        }
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(
        self,
        statement: object,
        parameters: dict[str, object] | None = None,
    ) -> _FakeResult:
        sql = " ".join(str(statement).split())
        values = parameters or {}
        self.calls.append((sql, values))
        lowered = sql.casefold()
        if "current_user as principal" in lowered:
            return _FakeResult([self.principal])
        if "set_config" in lowered:
            return _FakeResult([])
        if "from session_context" in lowered:
            return _FakeResult(
                [
                    {
                        "session_id": SESSION_ID,
                        "prior_receipt_ids": self.prior_receipt_ids,
                    }
                ]
                if self.has_session
                else []
            )
        if "insert into recall_receipts" in lowered:
            return _FakeResult([{"id": RECEIPT_ID}])
        if "insert into policy_events" in lowered:
            return _FakeResult([{"id": EVENT_ID}])
        if "insert into receipt_memory_links" in lowered:
            return _FakeResult([])
        raise AssertionError(f"unexpected SQL: {sql}")


class _RecordingRunner:
    def __init__(self, *connections: _FakeConnection) -> None:
        self.connections = connections
        self.options: list[dict[str, object]] = []

    def __call__(self, engine: object, callback: object, **options: object) -> None:
        del engine
        self.options.append(options)
        for connection in self.connections:
            callback(connection)


def _receipt(
    *,
    decision: str = "MODIFY",
    response_status: str = "completed",
) -> _SignedReceipt:
    included = (MEMORY_ID,) if decision == "MODIFY" else ()
    included_hashes = (HASH_B,) if included else ()
    payload = _ReceiptPayload(
        receipt_id=RECEIPT_ID,
        request_id=REQUEST_ID,
        session_id=SESSION_ID,
        intent_id=INTENT_ID,
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        operation="RECALL",
        action_arguments_sha256=HASH_A,
        decision=decision,
        created_at=NOW,
        policy_version="bio-demo-v1",
        policy_sha256=HASH_A,
        prior_action_context_sha256=_prior_receipt_context_sha256(()),
        app_version="0.1.0",
        app_sha256=HASH_B,
        agent_id="gluevenir-bio",
        agent_signing_key_id="demo-key-v1",
        actor_id="synthetic-program-lead",
        actor_role="program_lead",
        purpose="program_status",
        audience="internal-program-lead",
        destination="internal",
        original_intent_sha256=HASH_A,
        outcome="EXECUTED" if response_status == "completed" else "NOT_EXECUTED",
        response_status=response_status,
        reason_code=(
            "EXACT_APPROVED_DERIVATIVE"
            if decision == "MODIFY"
            else "EXTERNAL_ACTION_DENIED"
        ),
        candidate_count=len(included),
        included_count=len(included),
        exclusion_counts=(),
        included_memory_ids=included,
        included_content_sha256=included_hashes,
        model_prompt_sha256=HASH_A if included else None,
        approval_resolution_id=APPROVAL_ID if decision == "MODIFY" else None,
        resolution_actor_id=(
            "human-reviewer-synthetic-01" if decision == "MODIFY" else None
        ),
        resolution_actor_role="human_reviewer" if decision == "MODIFY" else None,
    )
    signer = _ReceiptSigner(
        agent_id="gluevenir-bio",
        key_id="demo-key-v1",
        private_key=Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32),
    )
    return signer.sign(payload)


def _engine(*, hide_parameters: bool = True):
    return create_engine("sqlite://", hide_parameters=hide_parameters)


def _store(
    connection: _FakeConnection,
) -> tuple[_CockroachReceiptStore, _RecordingRunner]:
    runner = _RecordingRunner(connection)
    return (
        _CockroachReceiptStore(
            _engine(),
            application_principal=APP_PRINCIPAL,
            _transaction_runner=runner,
        ),
        runner,
    )


def test_save_orders_runtime_context_exact_session_receipt_link_and_event() -> None:
    connection = _FakeConnection()
    store, runner = _store(connection)

    store.save(_receipt())

    assert runner.options == [{"max_retries": 3, "max_backoff": 1}]
    assert len(connection.calls) == 6
    principal, tenant, session, receipt, link, event = connection.calls
    assert "current_user AS principal" in principal[0]
    assert tenant == (
        "SELECT set_config('app.current_tenant', :tenant_id, true)",
        {"tenant_id": str(TENANT_ID)},
    )
    assert "from session_context" in session[0].casefold()
    assert session[1] == {
        "tenant_id": str(TENANT_ID),
        "program_id": str(PROGRAM_ID),
        "session_id": str(SESSION_ID),
        "intent_id": str(INTENT_ID),
        "agent_id": "gluevenir-bio",
        "actor_id": "synthetic-program-lead",
        "actor_role": "program_lead",
        "purpose": "program_status",
        "audience": "internal-program-lead",
        "original_intent_sha256": HASH_A,
        "receipt_created_at": NOW,
    }
    lowered_session_sql = session[0].casefold()
    assert "agent_id = :agent_id" in lowered_session_sql
    assert "created_at <= :receipt_created_at" in lowered_session_sql
    assert "expires_at > :receipt_created_at" in lowered_session_sql
    assert "insert into recall_receipts" in receipt[0].casefold()
    assert receipt[1]["receipt_id"] == str(RECEIPT_ID)
    assert receipt[1]["decision_code"] == "MODIFY"
    assert receipt[1]["approval_resolution_id"] == str(APPROVAL_ID)
    assert "raw_query_sha256" not in receipt[1]
    assert "'gateway'" in receipt[0]
    assert receipt[1]["completed_at"] == NOW
    assert receipt[1]["gateway_latency_bucket"] == "not_measured"
    assert receipt[1]["included_memory_ids"] == [str(MEMORY_ID)]
    assert receipt[1]["model_prompt_sha256"] == HASH_A
    assert "insert into receipt_memory_links" in link[0].casefold()
    assert link[1] == {
        "tenant_id": str(TENANT_ID),
        "program_id": str(PROGRAM_ID),
        "receipt_id": str(RECEIPT_ID),
        "memory_id": str(MEMORY_ID),
        "reason_code": "EXACT_APPROVED_DERIVATIVE",
        "content_sha256": HASH_B,
    }
    assert "insert into policy_events" in event[0].casefold()
    assert "'recall_receipt'" in event[0]
    assert event[1]["receipt_id"] == str(RECEIPT_ID)
    assert event[1]["outcome"] == "MODIFY"


def test_modify_action_envelope_is_allowlisted_and_does_not_leak_content() -> None:
    connection = _FakeConnection()
    store, _ = _store(connection)

    store.save(_receipt())

    receipt_parameters = connection.calls[3][1]
    envelope = receipt_parameters["action_envelope"]
    assert isinstance(envelope, str)
    assert "included_memory" not in envelope
    assert "synthetic-program-lead" not in envelope
    assert "raw_query" not in envelope
    assert "model_prompt" not in envelope
    assert "answer" not in envelope
    assert set(json.loads(envelope)) == {
        "action_arguments_sha256",
        "actor_role",
        "audience",
        "destination",
        "operation",
        "original_intent_sha256",
        "policy_version",
        "purpose",
        "resolution_actor_id",
        "resolution_actor_role",
        "schema_version",
    }
    all_parameters = repr([parameters for _, parameters in connection.calls])
    assert "restricted source text" not in all_parameters
    assert "detector match" not in all_parameters


def test_non_executable_decision_creates_no_memory_links() -> None:
    connection = _FakeConnection()
    store, _ = _store(connection)

    store.save(_receipt(decision="DENY", response_status="denied"))

    assert len(connection.calls) == 5
    assert all(
        "receipt_memory_links" not in sql.casefold() for sql, _ in connection.calls
    )
    assert connection.calls[3][1]["included_memory_ids"] == []
    assert connection.calls[3][1]["approval_resolution_id"] is None


def test_missing_exact_session_fails_closed_before_receipt_event_or_links() -> None:
    connection = _FakeConnection(has_session=False)
    store, _ = _store(connection)

    with pytest.raises(
        _ReceiptStoreUnavailable, match="receipt persistence is unavailable"
    ):
        store.save(_receipt())

    assert len(connection.calls) == 3
    assert all(
        name not in sql.casefold()
        for sql, _ in connection.calls
        for name in ("insert into recall_receipts", "insert into policy_events")
    )


def test_mismatched_prior_receipt_context_fails_before_receipt_write() -> None:
    connection = _FakeConnection(prior_receipt_ids=[EVENT_ID])
    store, _ = _store(connection)

    with pytest.raises(
        _ReceiptStoreUnavailable, match="receipt persistence is unavailable"
    ):
        store.save(_receipt())

    assert len(connection.calls) == 3
    assert all(
        "insert into recall_receipts" not in sql.casefold()
        for sql, _ in connection.calls
    )


def test_privileged_principal_fails_before_tenant_access() -> None:
    connection = _FakeConnection(
        principal={
            "principal": APP_PRINCIPAL,
            "bypasses_rls": True,
            "is_app_member": True,
            "can_create_schema_objects": False,
            "can_create_schemas": False,
        }
    )
    store, _ = _store(connection)

    with pytest.raises(
        _ReceiptStoreUnavailable, match="receipt persistence is unavailable"
    ):
        store.save(_receipt())

    assert len(connection.calls) == 1
    assert "current_user AS principal" in connection.calls[0][0]


def test_retry_reuses_the_same_signed_receipt_id_and_parameters() -> None:
    first = _FakeConnection()
    retry = _FakeConnection()
    runner = _RecordingRunner(first, retry)
    store = _CockroachReceiptStore(
        _engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=runner,
    )

    store.save(_receipt())

    assert first.calls == retry.calls
    assert first.calls[3][1]["receipt_id"] == str(RECEIPT_ID)
    assert first.calls[3][1]["signature"] == retry.calls[3][1]["signature"]


def test_database_error_is_sanitized() -> None:
    def failing_runner(engine: object, callback: object, **options: object) -> None:
        del engine, callback, options
        raise SQLAlchemyError("sensitive database detail")

    store = _CockroachReceiptStore(
        _engine(),
        application_principal=APP_PRINCIPAL,
        _transaction_runner=failing_runner,
    )

    with pytest.raises(_ReceiptStoreUnavailable) as error:
        store.save(_receipt())

    assert "sensitive database detail" not in str(error.value)


def test_constructor_requires_hidden_parameters_and_official_default_runner() -> None:
    with pytest.raises(ValueError, match="hide SQL parameter values"):
        _CockroachReceiptStore(
            _engine(hide_parameters=False),
            application_principal=APP_PRINCIPAL,
        )
    store = _CockroachReceiptStore(_engine(), application_principal=APP_PRINCIPAL)
    assert store._transaction_runner is run_transaction
