from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gluevenir._gateway import (
    _GatewayAction,
    _GatewayUnavailable,
    _hash_action_arguments,
    _MemoryActionGateway,
    _PreparedAction,
    _ResponseStatus,
)
from gluevenir._policy import (
    _ApprovedDerivative,
    _BioDemoPolicy,
    _Decision,
    _Destination,
    _PolicyAction,
    _PolicyDecision,
    _PolicyFacts,
    _ReasonCode,
)
from gluevenir._ports import MemoryOperation
from gluevenir._receipt_sink import _SignedReceiptSink
from gluevenir._receipts import _ReceiptSigner, _ReceiptVerifier, _SignedReceipt

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
SOURCE_ID = UUID("10000000-0000-4000-8000-000000000001")
DERIVATIVE_ID = UUID("10000000-0000-4000-8000-000000000002")
APPROVAL_ID = UUID("30000000-0000-4000-8000-000000000001")
RECEIPT_ID = UUID("40000000-0000-4000-8000-000000000001")
EVALUATION_ID = UUID("40000000-0000-4000-8000-000000000002")
NOW = datetime(2026, 8, 15, 18, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
ARGUMENTS = {"query_sha256": "c" * 64, "top_k": 4}


class _FakeClock:
    def now(self) -> datetime:
        return NOW


class _Store:
    def __init__(self, *, fails: bool = False) -> None:
        self.fails = fails
        self.receipts: list[_SignedReceipt] = []

    def save(self, receipt: _SignedReceipt) -> None:
        if self.fails:
            raise RuntimeError("database detail must be sanitized by the gateway")
        self.receipts.append(receipt)


class _Executor:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[UUID, ...], tuple[str, ...]]] = []

    def prepare(
        self,
        *,
        executable_memory_ids: tuple[UUID, ...],
        expected_content_sha256: tuple[str, ...],
        **_values: object,
    ) -> _PreparedAction:
        hashes = expected_content_sha256 or (HASH_A,) * len(executable_memory_ids)
        return _PreparedAction(executable_memory_ids, hashes, "synthetic-prepared")

    def execute(
        self,
        *,
        action: _GatewayAction,
        prepared: _PreparedAction,
        action_arguments: object,
    ) -> str:
        del action, action_arguments
        self.calls.append((prepared.memory_ids, prepared.content_sha256))
        return "synthetic-complete"


def _action() -> _GatewayAction:
    return _GatewayAction(
        request_id=UUID("50000000-0000-4000-8000-000000000001"),
        session_id=UUID("60000000-0000-4000-8000-000000000001"),
        intent_id=UUID("70000000-0000-4000-8000-000000000001"),
        agent_id="gluevenir-bio",
        actor_id="demo-reviewer",
        evaluated_at=NOW,
        action_arguments_sha256=_hash_action_arguments(ARGUMENTS),
        original_intent_sha256=HASH_A,
        prior_action_context_sha256=HASH_B,
        policy=_PolicyAction(
            operation=MemoryOperation.RECALL,
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            actor_role="external_partner",
            purpose="partner_status",
            audience="partner-alpha-synthetic",
            destination=_Destination.EXTERNAL,
            policy_version="bio-demo-v1",
            requested_memory_ids=(SOURCE_ID,),
            data_classes=("IP_CONFIDENTIAL",),
        ),
    )


def _sink(store: _Store, receipt_id: object = RECEIPT_ID):
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    signer = _ReceiptSigner(
        agent_id="gluevenir-bio",
        key_id="demo-key-v1",
        private_key=private_key,
    )
    sink = _SignedReceiptSink(
        signer=signer,
        store=store,
        clock=_FakeClock(),
        new_receipt_id=lambda: receipt_id,  # type: ignore[return-value]
        key_id="demo-key-v1",
        policy_sha256=HASH_A,
        app_version="0.1.0",
        app_sha256=HASH_B,
    )
    verifier = _ReceiptVerifier.from_public_key_bytes(
        agent_id="gluevenir-bio",
        key_id="demo-key-v1",
        public_key=signer.public_key_bytes(),
    )
    return sink, verifier


def test_modify_receipt_binds_exact_derivative_and_is_offline_verifiable() -> None:
    store = _Store()
    sink, verifier = _sink(store)
    decision = _PolicyDecision(
        _Decision.MODIFY,
        _ReasonCode.EXACT_APPROVED_DERIVATIVE,
        executable_memory_ids=(DERIVATIVE_ID,),
        executable_content_sha256=(HASH_B,),
        approval_resolution_id=APPROVAL_ID,
        resolution_actor_id="synthetic-human-reviewer",
        resolution_actor_role="human_reviewer",
    )

    result = sink.record(
        action=_action(),
        decision=decision,
        response_status=_ResponseStatus.PENDING,
    )

    assert result == RECEIPT_ID
    assert len(store.receipts) == 1
    receipt = store.receipts[0]
    assert verifier.verify(receipt)
    assert receipt.payload.included_memory_ids == (DERIVATIVE_ID,)
    assert receipt.payload.included_content_sha256 == (HASH_B,)
    assert receipt.payload.decision == "MODIFY"
    assert receipt.payload.response_status == "pending"
    assert receipt.payload.candidate_count == 2
    assert receipt.payload.included_count == 1
    assert receipt.payload.exclusion_counts == (("SAFE_DERIVATIVE_SUBSTITUTION", 1),)


def test_resolution_receipt_is_content_safe_and_references_evaluation() -> None:
    store = _Store()
    sink, _ = _sink(store)
    denial = _PolicyDecision(_Decision.DENY, _ReasonCode.PENDING_TIMEOUT)

    sink.record(
        action=_action(),
        decision=denial,
        response_status=_ResponseStatus.DENIED,
        resolution_of=EVALUATION_ID,
    )

    payload = store.receipts[0].payload
    assert payload.resolution_of_receipt_id == EVALUATION_ID
    assert payload.outcome == "NOT_EXECUTED"
    rendered = repr(store.receipts[0].public_view())
    assert "raw query" not in rendered.casefold()
    assert "content" not in rendered.casefold().replace("included_content_sha256", "")


def test_denial_receipt_reports_only_aggregate_omission_reason() -> None:
    store = _Store()
    sink, _ = _sink(store)
    denial = _PolicyDecision(_Decision.DENY, _ReasonCode.IDENTITY_DENIED)

    sink.record(
        action=_action(),
        decision=denial,
        response_status=_ResponseStatus.DENIED,
    )

    payload = store.receipts[0].payload
    assert payload.candidate_count == 1
    assert payload.included_count == 0
    assert payload.exclusion_counts == (("IDENTITY_DENIED", 1),)
    assert payload.included_memory_ids == ()


def test_allow_without_known_hashes_does_not_claim_unbound_inclusions() -> None:
    store = _Store()
    sink, _ = _sink(store)
    allow = _PolicyDecision(
        _Decision.ALLOW,
        _ReasonCode.INTERNAL_POLICY_ALLOW,
        executable_memory_ids=(SOURCE_ID,),
    )

    sink.record(
        action=_action(),
        decision=allow,
        response_status=_ResponseStatus.COMPLETED,
    )

    assert store.receipts[0].payload.included_count == 0
    assert store.receipts[0].payload.included_memory_ids == ()


def test_store_failure_and_invalid_id_propagate_before_gateway_execution() -> None:
    sink, _ = _sink(_Store(fails=True))
    decision = _PolicyDecision(_Decision.DENY, _ReasonCode.IDENTITY_DENIED)
    with pytest.raises(RuntimeError, match="database detail"):
        sink.record(
            action=_action(),
            decision=decision,
            response_status=_ResponseStatus.DENIED,
        )

    invalid_sink, _ = _sink(_Store(), receipt_id="not-a-uuid")
    with pytest.raises(TypeError, match="must return a UUID"):
        invalid_sink.record(
            action=_action(),
            decision=decision,
            response_status=_ResponseStatus.DENIED,
        )


def test_sink_refuses_to_rebind_a_different_agent_to_its_signing_key() -> None:
    store = _Store()
    sink, _ = _sink(store)
    decision = _PolicyDecision(_Decision.DENY, _ReasonCode.IDENTITY_DENIED)

    with pytest.raises(ValueError, match="does not match"):
        sink.record(
            action=replace(_action(), agent_id="other-agent"),
            decision=decision,
            response_status=_ResponseStatus.DENIED,
        )

    assert store.receipts == []


def test_constructor_rejects_invalid_signer_or_id_factory() -> None:
    signer = _ReceiptSigner(
        agent_id="gluevenir-bio",
        key_id="demo-key-v1",
        private_key=Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32),
    )
    values = {
        "signer": signer,
        "store": _Store(),
        "clock": _FakeClock(),
        "new_receipt_id": lambda: RECEIPT_ID,
        "key_id": "demo-key-v1",
        "policy_sha256": HASH_A,
        "app_version": "0.1.0",
        "app_sha256": HASH_B,
    }
    with pytest.raises(TypeError):
        _SignedReceiptSink(**{**values, "signer": object()})
    with pytest.raises(TypeError):
        _SignedReceiptSink(**{**values, "new_receipt_id": None})


def test_gateway_records_signed_modify_and_completion_before_returning_output() -> None:
    store = _Store()
    ids = iter((RECEIPT_ID, EVALUATION_ID))
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    signer = _ReceiptSigner(
        agent_id="gluevenir-bio",
        key_id="demo-key-v1",
        private_key=private_key,
    )
    sink = _SignedReceiptSink(
        signer=signer,
        store=store,
        clock=_FakeClock(),
        new_receipt_id=lambda: next(ids),
        key_id="demo-key-v1",
        policy_sha256=HASH_A,
        app_version="0.1.0",
        app_sha256=HASH_B,
    )
    executor = _Executor()
    gateway = _MemoryActionGateway(
        policy=_BioDemoPolicy(),
        executor=executor,
        receipt_sink=sink,
        pending_store=object(),
        clock=_FakeClock(),
    )
    approval = _ApprovedDerivative(
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
        reviewed_at=datetime(2026, 8, 15, 17, tzinfo=UTC),
        expires_at=datetime(2026, 8, 20, 17, tzinfo=UTC),
        source_active=True,
        derivative_active=True,
        reviewed_by="synthetic-human-reviewer",
        reviewer_role="human_reviewer",
    )

    result = gateway.execute(
        action=_action(),
        action_arguments=ARGUMENTS,
        facts=_PolicyFacts(
            now=NOW,
            policy_available=True,
            identity_authorized=True,
            approved_derivative=approval,
        ),
    )

    verifier = _ReceiptVerifier.from_public_key_bytes(
        agent_id="gluevenir-bio",
        key_id="demo-key-v1",
        public_key=signer.public_key_bytes(),
    )
    assert result.output == "synthetic-complete"
    assert executor.calls == [((DERIVATIVE_ID,), (HASH_B,))]
    assert len(store.receipts) == 2
    assert all(verifier.verify(receipt) for receipt in store.receipts)
    assert store.receipts[0].payload.included_memory_ids == (DERIVATIVE_ID,)
    assert store.receipts[0].payload.approval_resolution_id == APPROVAL_ID
    assert store.receipts[1].payload.resolution_of_receipt_id == RECEIPT_ID


def test_gateway_fails_closed_before_executor_when_signed_store_fails() -> None:
    store = _Store(fails=True)
    sink, _ = _sink(store)
    executor = _Executor()
    gateway = _MemoryActionGateway(
        policy=_BioDemoPolicy(),
        executor=executor,
        receipt_sink=sink,
        pending_store=object(),
        clock=_FakeClock(),
    )
    approval = _ApprovedDerivative(
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
        reviewed_at=datetime(2026, 8, 15, 17, tzinfo=UTC),
        expires_at=datetime(2026, 8, 20, 17, tzinfo=UTC),
        source_active=True,
        derivative_active=True,
        reviewed_by="synthetic-human-reviewer",
        reviewer_role="human_reviewer",
    )

    with pytest.raises(_GatewayUnavailable, match="failed closed"):
        gateway.execute(
            action=_action(),
            action_arguments=ARGUMENTS,
            facts=_PolicyFacts(
                now=NOW,
                policy_available=True,
                identity_authorized=True,
                approved_derivative=approval,
            ),
        )

    assert executor.calls == []
