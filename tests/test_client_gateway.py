from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest

from gluevenir import Gluevenir, MemoryContext, RecallRequest
from gluevenir._client_gateway import (
    _AuthorizedRecallContext,
    _ClientGatewayUnavailable,
    _GovernedRecallGateway,
    _StaticSyntheticRecallAuthority,
)
from gluevenir._gateway import (
    _GatewayAction,
    _MemoryActionGateway,
    _PreparedAction,
    _ResponseStatus,
)
from gluevenir._policy import _BioDemoPolicy, _Decision, _Destination

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
SESSION_ID = UUID("60000000-0000-4000-8000-000000000001")
INTENT_ID = UUID("70000000-0000-4000-8000-000000000001")
REQUEST_ID = UUID("50000000-0000-4000-8000-000000000001")
MEMORY_ID = UUID("10000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 8, 15, 18, tzinfo=UTC)
CONTENT_HASH = "a" * 64


class _Clock:
    def now(self) -> datetime:
        return NOW


class _Executor:
    def __init__(self) -> None:
        self.prepare_actions: list[_GatewayAction] = []
        self.execute_actions: list[_GatewayAction] = []

    def prepare(self, *, action: _GatewayAction, **_values: object) -> _PreparedAction:
        self.prepare_actions.append(action)
        return _PreparedAction((MEMORY_ID,), (CONTENT_HASH,), "authorized")

    def execute(self, *, action: _GatewayAction, **_values: object) -> str:
        self.execute_actions.append(action)
        return "synthetic answer"


class _ReceiptPayload:
    def __init__(self, receipt_id: UUID) -> None:
        self.receipt_id = receipt_id


class _BuiltReceipt:
    def __init__(self, receipt_id: UUID) -> None:
        self.payload = _ReceiptPayload(receipt_id)


class _ReceiptSink:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def record(self, **values: object) -> UUID:
        self.calls.append(values)
        return UUID(int=len(self.calls))

    def build(self, **values: object) -> _BuiltReceipt:
        self.calls.append(values)
        return _BuiltReceipt(UUID(int=len(self.calls)))

    def persist_in_transaction(
        self, _connection: object, _receipt: _BuiltReceipt
    ) -> None:
        return None


def _context() -> MemoryContext:
    return MemoryContext(
        tenant_id=str(TENANT_ID),
        program_id=str(PROGRAM_ID),
        actor_id="synthetic-program-lead",
        actor_role="program_lead",
        agent_id="gluevenir-bio",
        purpose="program_status",
        audience="internal-program-lead",
    )


def _authorization() -> _AuthorizedRecallContext:
    return _AuthorizedRecallContext(
        expected_public_context=_context(),
        tenant_id=TENANT_ID,
        program_id=PROGRAM_ID,
        session_id=SESSION_ID,
        intent_id=INTENT_ID,
        original_intent_sha256=hashlib.sha256(b"synthetic intent").hexdigest(),
        prior_receipt_ids=(),
        requested_memory_ids=(MEMORY_ID,),
        data_classes=("IP_CONFIDENTIAL",),
        destination=_Destination.INTERNAL,
    )


def _client(
    *, authority: object | None = None
) -> tuple[Gluevenir[object], _Executor, _ReceiptSink]:
    executor = _Executor()
    sink = _ReceiptSink()
    private_gateway = _MemoryActionGateway(
        policy=_BioDemoPolicy(),
        executor=executor,
        receipt_sink=sink,
        pending_store=object(),
        clock=_Clock(),
    )
    adapter = _GovernedRecallGateway(
        gateway=private_gateway,
        authority=authority or _StaticSyntheticRecallAuthority(_authorization()),
        clock=_Clock(),
        new_uuid=lambda: REQUEST_ID,
    )
    return Gluevenir(gateway=adapter), executor, sink


def test_public_recall_enters_real_gateway_and_executes_once() -> None:
    client, executor, sink = _client()

    result = client.recall(
        RecallRequest("What changed in HX-17?", top_k=4),
        context=_context(),
    )

    assert result.decision == _Decision.ALLOW
    assert result.response_status == _ResponseStatus.COMPLETED
    assert result.output == "synthetic answer"
    assert len(executor.prepare_actions) == len(executor.execute_actions) == 1
    action = executor.execute_actions[0]
    assert action.policy.tenant_id == TENANT_ID
    assert action.policy.program_id == PROGRAM_ID
    assert len(sink.calls) == 2


def test_untrusted_public_scope_cannot_change_server_authority() -> None:
    client, executor, sink = _client()
    untrusted = replace(_context(), tenant_id="attacker-supplied-tenant")

    result = client.recall(RecallRequest("What changed?"), context=untrusted)

    assert result.decision == _Decision.DENY
    assert result.response_status == _ResponseStatus.DENIED
    assert executor.prepare_actions == executor.execute_actions == []
    assert sink.calls[0]["action"].policy.tenant_id == TENANT_ID


def test_authority_outage_fails_closed_before_gateway_or_receipt() -> None:
    class _FailingAuthority:
        def authorize(self, **_values: object):
            raise RuntimeError("identity provider secret detail")

    client, executor, sink = _client(authority=_FailingAuthority())

    with pytest.raises(_ClientGatewayUnavailable, match="failed closed") as error:
        client.recall(RecallRequest("What changed?"), context=_context())

    assert error.value.__cause__ is None
    assert executor.prepare_actions == executor.execute_actions == []
    assert sink.calls == []


def test_authorization_configuration_rejects_scope_drift() -> None:
    with pytest.raises(ValueError, match="trusted tenant"):
        replace(
            _authorization(),
            expected_public_context=replace(
                _context(),
                tenant_id="22222222-2222-4222-8222-222222222222",
            ),
        )
