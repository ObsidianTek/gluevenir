"""Gateway adapter that signs and durably records content-safe receipts."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol
from uuid import UUID

from sqlalchemy import Connection

from gluevenir._gateway import (
    _Clock,
    _GatewayAction,
    _ResponseStatus,
)
from gluevenir._policy import _PolicyDecision
from gluevenir._receipts import _ReceiptPayload, _ReceiptSigner, _SignedReceipt


class _SignedReceiptStore(Protocol):
    """Persistence boundary; production implementations must use CockroachDB."""

    def save(self, receipt: _SignedReceipt) -> None: ...

    def save_in_transaction(
        self,
        connection: Connection,
        receipt: _SignedReceipt,
    ) -> None: ...


class _SignedReceiptSink:
    """Build, sign, and persist one receipt before returning its identifier."""

    __slots__ = (
        "_app_sha256",
        "_app_version",
        "_clock",
        "_key_id",
        "_new_receipt_id",
        "_policy_sha256",
        "_signer",
        "_store",
    )

    def __init__(
        self,
        *,
        signer: _ReceiptSigner,
        store: _SignedReceiptStore,
        clock: _Clock,
        new_receipt_id: Callable[[], UUID],
        key_id: str,
        policy_sha256: str,
        app_version: str,
        app_sha256: str,
    ) -> None:
        if not isinstance(signer, _ReceiptSigner):
            raise TypeError("signer must be a _ReceiptSigner")
        if not callable(new_receipt_id):
            raise TypeError("new_receipt_id must be callable")
        self._signer = signer
        self._store = store
        self._clock = clock
        self._new_receipt_id = new_receipt_id
        self._key_id = key_id
        self._policy_sha256 = policy_sha256
        self._app_version = app_version
        self._app_sha256 = app_sha256

    def record(
        self,
        *,
        action: _GatewayAction,
        decision: _PolicyDecision,
        response_status: _ResponseStatus,
        resolution_of: UUID | None = None,
    ) -> UUID:
        signed = self.build(
            action=action,
            decision=decision,
            response_status=response_status,
            resolution_of=resolution_of,
        )
        self._store.save(signed)
        return signed.payload.receipt_id

    def build(
        self,
        *,
        action: _GatewayAction,
        decision: _PolicyDecision,
        response_status: _ResponseStatus,
        resolution_of: UUID | None = None,
    ) -> _SignedReceipt:
        """Build and sign without persistence for an enclosing DB transaction."""

        if not isinstance(action, _GatewayAction):
            raise TypeError("action must be a _GatewayAction")
        if not isinstance(decision, _PolicyDecision):
            raise TypeError("decision must be a _PolicyDecision")
        if not isinstance(response_status, _ResponseStatus):
            raise TypeError("response_status must be a _ResponseStatus")

        receipt_id = self._new_receipt_id()
        if not isinstance(receipt_id, UUID):
            raise TypeError("new_receipt_id must return a UUID")
        included_ids, included_hashes = _content_bound_inclusions(decision)
        candidate_count, exclusion_counts = _aggregate_counts(
            action,
            decision,
            included_ids=included_ids,
        )
        payload = _ReceiptPayload(
            receipt_id=receipt_id,
            request_id=action.request_id,
            session_id=action.session_id,
            intent_id=action.intent_id,
            tenant_id=action.policy.tenant_id,
            program_id=action.policy.program_id,
            operation=action.policy.operation.value,
            action_arguments_sha256=action.action_arguments_sha256,
            decision=decision.decision.value,
            created_at=self._clock.now(),
            policy_version=action.policy.policy_version,
            policy_sha256=self._policy_sha256,
            prior_action_context_sha256=action.prior_action_context_sha256,
            app_version=self._app_version,
            app_sha256=self._app_sha256,
            agent_id=action.agent_id,
            agent_signing_key_id=self._key_id,
            actor_id=action.actor_id,
            actor_role=action.policy.actor_role,
            purpose=action.policy.purpose,
            audience=action.policy.audience,
            destination=action.policy.destination.value,
            original_intent_sha256=action.original_intent_sha256,
            outcome=_outcome(response_status),
            response_status=response_status.value,
            reason_code=decision.reason_code.value,
            candidate_count=candidate_count,
            included_count=len(included_ids),
            exclusion_counts=exclusion_counts,
            included_memory_ids=included_ids,
            included_content_sha256=included_hashes,
            model_prompt_sha256=decision.model_prompt_sha256,
            resolution_of_receipt_id=resolution_of,
            approval_resolution_id=decision.approval_resolution_id,
            resolution_actor_id=decision.resolution_actor_id,
            resolution_actor_role=decision.resolution_actor_role,
        )
        signed = self._signer.sign(payload)
        return signed

    def persist_in_transaction(
        self,
        connection: Connection,
        receipt: _SignedReceipt,
    ) -> None:
        """Persist a built receipt inside a pending-state transaction."""

        self._store.save_in_transaction(connection, receipt)


def _content_bound_inclusions(
    decision: _PolicyDecision,
) -> tuple[tuple[UUID, ...], tuple[str, ...]]:
    if len(decision.executable_memory_ids) != len(decision.executable_content_sha256):
        return (), ()
    return decision.executable_memory_ids, decision.executable_content_sha256


def _aggregate_counts(
    action: _GatewayAction,
    decision: _PolicyDecision,
    *,
    included_ids: tuple[UUID, ...],
) -> tuple[int, tuple[tuple[str, int], ...]]:
    """Report only aggregate omissions; excluded memory IDs remain private."""

    requested = set(action.policy.requested_memory_ids)
    included = set(included_ids)
    candidate_count = len(requested | included)
    excluded_count = len(requested - included)
    if excluded_count == 0:
        return candidate_count, ()
    if decision.decision.value == "MODIFY":
        reason = "SAFE_DERIVATIVE_SUBSTITUTION"
    elif decision.decision.value == "ALLOW":
        reason = "NOT_INCLUDED"
    else:
        reason = decision.reason_code.value
    return candidate_count, ((reason, excluded_count),)


def _outcome(status: _ResponseStatus) -> str:
    return {
        _ResponseStatus.PENDING: "PENDING",
        _ResponseStatus.COMPLETED: "EXECUTED",
        _ResponseStatus.DENIED: "NOT_EXECUTED",
        _ResponseStatus.FAILED: "FAILED",
    }[status]
