"""Private retry-safe CockroachDB persistence for signed Recall Receipts."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from uuid import UUID

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import MultipleResultsFound, NoResultFound, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._memory_store import _SET_TENANT_CONTEXT, _VERIFY_RUNTIME_PRINCIPAL
from gluevenir._receipts import _ReceiptPayload, _SignedReceipt
from gluevenir._session_context import _prior_receipt_context_sha256

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_LATENCY_NOT_MEASURED = "not_measured"

_REQUIRE_EXACT_SESSION = text(
    """
    SELECT session_id, prior_receipt_ids
    FROM session_context
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND session_id = :session_id
      AND intent_id = :intent_id
      AND agent_id = :agent_id
      AND actor_id = :actor_id
      AND actor_role = :actor_role
      AND declared_purpose = :purpose
      AND declared_audience = :audience
      AND original_intent_sha256 = :original_intent_sha256
      AND created_at <= :receipt_created_at
      AND expires_at > :receipt_created_at
    """
)

_INSERT_RECEIPT = text(
    """
    INSERT INTO recall_receipts (
        id, tenant_id, program_id, request_id, session_id, intent_id, actor_id,
        agent_id, agent_signing_key_id, operation, action_envelope,
        action_arguments_sha256, raw_query_sha256, model_prompt_sha256,
        answer_sha256, decision, decision_code, reason_code, purpose, audience,
        policy_version, policy_sha256, app_version, app_sha256,
        embedding_model_version, embedding_model_sha256,
        prior_action_context_sha256, candidate_count, included_count,
        exclusion_counts, included_memory_ids, included_content_sha256,
        resolution_of_receipt_id, approval_resolution_id, defer_resolution_id,
        retrieval_method, response_status, canonical_receipt_sha256, signature,
        created_at, completed_at, gateway_latency_bucket,
        retrieval_latency_bucket, end_to_end_latency_bucket
    ) VALUES (
        :receipt_id, :tenant_id, :program_id, :request_id, :session_id,
        :intent_id, :actor_id, :agent_id, :agent_signing_key_id, :operation,
        CAST(:action_envelope AS JSONB), :action_arguments_sha256, NULL,
        :model_prompt_sha256,
        NULL, :decision, :decision_code, :reason_code, :purpose, :audience,
        :policy_version, :policy_sha256, :app_version, :app_sha256, NULL, NULL,
        :prior_action_context_sha256, :candidate_count, :included_count,
        CAST(:exclusion_counts AS JSONB), :included_memory_ids,
        :included_content_sha256, :resolution_of_receipt_id,
        :approval_resolution_id, NULL,
        'gateway', :response_status, :canonical_receipt_sha256, :signature,
        :created_at, :completed_at, :gateway_latency_bucket,
        :retrieval_latency_bucket, :end_to_end_latency_bucket
    )
    RETURNING id
    """
)

_INSERT_INCLUDED_LINK = text(
    """
    INSERT INTO receipt_memory_links (
        tenant_id, program_id, receipt_id, memory_id, disposition, reason_code,
        content_sha256
    ) VALUES (
        :tenant_id, :program_id, :receipt_id, :memory_id, 'included',
        :reason_code, :content_sha256
    )
    """
)

_INSERT_POLICY_EVENT = text(
    """
    INSERT INTO policy_events (
        tenant_id, program_id, operation, outcome, reason_code, object_type,
        object_id, actor_id, actor_role, purpose, audience, receipt_id
    ) VALUES (
        :tenant_id, :program_id, :operation, :outcome, :reason_code,
        'recall_receipt', :receipt_id, :actor_id, :actor_role, :purpose,
        :audience, :receipt_id
    )
    RETURNING id
    """
)

type _TransactionCallback = Callable[[Connection], None]
type _TransactionRunner = Callable[..., None]


class _ReceiptStoreUnavailable(RuntimeError):
    """Sanitized persistence failure; callers must fail closed."""


class _CockroachReceiptStore:
    """Persist one already-signed, content-safe receipt in one transaction."""

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
        if not isinstance(application_principal, str) or not _IDENTIFIER_RE.fullmatch(
            application_principal.strip()
        ):
            raise ValueError("application_principal must be a bounded identifier")
        if not callable(_transaction_runner):
            raise TypeError("_transaction_runner must be callable")
        self._engine = engine
        self._application_principal = application_principal.strip()
        self._transaction_runner = _transaction_runner

    def save(self, receipt: _SignedReceipt) -> None:
        """Save one stable signed receipt, its included links, and one event."""

        if type(receipt) is not _SignedReceipt:
            raise TypeError("receipt must be a _SignedReceipt")

        def persist(connection: Connection) -> None:
            self._authorize_transaction(connection, receipt)
            self.save_in_transaction(connection, receipt)

        try:
            self._transaction_runner(
                self._engine,
                persist,
                max_retries=3,
                max_backoff=1,
            )
        except _ReceiptStoreUnavailable:
            raise
        except SQLAlchemyError:
            raise _ReceiptStoreUnavailable(
                "receipt persistence is unavailable"
            ) from None

    def save_in_transaction(
        self,
        connection: Connection,
        receipt: _SignedReceipt,
    ) -> None:
        """Persist after the caller established the bounded RLS transaction."""

        if type(receipt) is not _SignedReceipt:
            raise TypeError("receipt must be a _SignedReceipt")
        _require_exact_session(connection, receipt)
        _require_inserted_receipt(connection, receipt)
        _insert_included_links(connection, receipt)
        _require_inserted_event(connection, receipt)

    def _authorize_transaction(
        self,
        connection: Connection,
        receipt: _SignedReceipt,
    ) -> None:
        try:
            principal = connection.execute(_VERIFY_RUNTIME_PRINCIPAL).mappings().one()
        except (MultipleResultsFound, NoResultFound, SQLAlchemyError):
            raise _ReceiptStoreUnavailable(
                "receipt persistence is unavailable"
            ) from None
        if (
            principal.get("principal") != self._application_principal
            or principal.get("bypasses_rls") is not False
            or principal.get("is_app_member") is not True
            or principal.get("can_create_schema_objects") is not False
            or principal.get("can_create_schemas") is not False
        ):
            raise _ReceiptStoreUnavailable("receipt persistence is unavailable")
        connection.execute(
            _SET_TENANT_CONTEXT,
            {"tenant_id": str(receipt.payload.tenant_id)},
        )


def _require_exact_session(connection: Connection, receipt: _SignedReceipt) -> None:
    payload = receipt.payload
    try:
        row = (
            connection.execute(
                _REQUIRE_EXACT_SESSION,
                {
                    "tenant_id": str(payload.tenant_id),
                    "program_id": str(payload.program_id),
                    "session_id": str(payload.session_id),
                    "intent_id": str(payload.intent_id),
                    "agent_id": payload.agent_id,
                    "actor_id": payload.actor_id,
                    "actor_role": payload.actor_role,
                    "purpose": payload.purpose,
                    "audience": payload.audience,
                    "original_intent_sha256": payload.original_intent_sha256,
                    "receipt_created_at": payload.created_at,
                },
            )
            .mappings()
            .one()
        )
        session_id = UUID(str(row["session_id"]))
        prior_receipt_ids = tuple(
            UUID(str(receipt_id)) for receipt_id in row["prior_receipt_ids"]
        )
    except (KeyError, MultipleResultsFound, NoResultFound, TypeError, ValueError):
        raise _ReceiptStoreUnavailable("receipt persistence is unavailable") from None
    if session_id != payload.session_id:
        raise _ReceiptStoreUnavailable("receipt persistence is unavailable")
    if (
        _prior_receipt_context_sha256(prior_receipt_ids)
        != payload.prior_action_context_sha256
    ):
        raise _ReceiptStoreUnavailable("receipt persistence is unavailable")


def _require_inserted_receipt(connection: Connection, receipt: _SignedReceipt) -> None:
    try:
        row = (
            connection.execute(
                _INSERT_RECEIPT,
                _receipt_parameters(receipt),
            )
            .mappings()
            .one()
        )
        receipt_id = UUID(str(row["id"]))
    except (KeyError, MultipleResultsFound, NoResultFound, TypeError, ValueError):
        raise _ReceiptStoreUnavailable("receipt persistence is unavailable") from None
    if receipt_id != receipt.payload.receipt_id:
        raise _ReceiptStoreUnavailable("receipt persistence is unavailable")


def _insert_included_links(connection: Connection, receipt: _SignedReceipt) -> None:
    payload = receipt.payload
    for memory_id, content_sha256 in zip(
        payload.included_memory_ids,
        payload.included_content_sha256,
        strict=True,
    ):
        connection.execute(
            _INSERT_INCLUDED_LINK,
            {
                "tenant_id": str(payload.tenant_id),
                "program_id": str(payload.program_id),
                "receipt_id": str(payload.receipt_id),
                "memory_id": str(memory_id),
                "reason_code": payload.reason_code,
                "content_sha256": content_sha256,
            },
        )


def _require_inserted_event(connection: Connection, receipt: _SignedReceipt) -> None:
    payload = receipt.payload
    try:
        row = (
            connection.execute(
                _INSERT_POLICY_EVENT,
                {
                    "tenant_id": str(payload.tenant_id),
                    "program_id": str(payload.program_id),
                    "operation": payload.operation,
                    "outcome": payload.decision,
                    "reason_code": payload.reason_code,
                    "receipt_id": str(payload.receipt_id),
                    "actor_id": payload.actor_id,
                    "actor_role": payload.actor_role,
                    "purpose": payload.purpose,
                    "audience": payload.audience,
                },
            )
            .mappings()
            .one()
        )
        UUID(str(row["id"]))
    except (KeyError, MultipleResultsFound, NoResultFound, TypeError, ValueError):
        raise _ReceiptStoreUnavailable("receipt persistence is unavailable") from None


def _receipt_parameters(receipt: _SignedReceipt) -> dict[str, object]:
    payload = receipt.payload
    return {
        "receipt_id": str(payload.receipt_id),
        "tenant_id": str(payload.tenant_id),
        "program_id": str(payload.program_id),
        "request_id": str(payload.request_id),
        "session_id": str(payload.session_id),
        "intent_id": str(payload.intent_id),
        "actor_id": payload.actor_id,
        "agent_id": payload.agent_id,
        "agent_signing_key_id": payload.agent_signing_key_id,
        "operation": payload.operation,
        "action_envelope": _action_envelope(payload),
        "action_arguments_sha256": payload.action_arguments_sha256,
        "model_prompt_sha256": payload.model_prompt_sha256,
        "decision": payload.decision,
        "decision_code": payload.decision,
        "reason_code": payload.reason_code,
        "purpose": payload.purpose,
        "audience": payload.audience,
        "policy_version": payload.policy_version,
        "policy_sha256": payload.policy_sha256,
        "app_version": payload.app_version,
        "app_sha256": payload.app_sha256,
        "prior_action_context_sha256": payload.prior_action_context_sha256,
        "candidate_count": payload.candidate_count,
        "included_count": payload.included_count,
        "exclusion_counts": json.dumps(
            dict(payload.exclusion_counts),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        "included_memory_ids": [str(value) for value in payload.included_memory_ids],
        "included_content_sha256": list(payload.included_content_sha256),
        "resolution_of_receipt_id": (
            str(payload.resolution_of_receipt_id)
            if payload.resolution_of_receipt_id is not None
            else None
        ),
        "approval_resolution_id": (
            str(payload.approval_resolution_id)
            if payload.approval_resolution_id is not None
            else None
        ),
        "response_status": payload.response_status,
        "canonical_receipt_sha256": receipt.canonical_receipt_sha256,
        "signature": receipt.signature,
        "created_at": payload.created_at,
        "completed_at": (
            None if payload.response_status == "pending" else payload.created_at
        ),
        "gateway_latency_bucket": _LATENCY_NOT_MEASURED,
        "retrieval_latency_bucket": _LATENCY_NOT_MEASURED,
        "end_to_end_latency_bucket": _LATENCY_NOT_MEASURED,
    }


def _action_envelope(payload: _ReceiptPayload) -> str:
    """Serialize only signed, allowlisted non-content action metadata."""

    value = {
        "action_arguments_sha256": payload.action_arguments_sha256,
        "actor_role": payload.actor_role,
        "audience": payload.audience,
        "destination": payload.destination,
        "operation": payload.operation,
        "original_intent_sha256": payload.original_intent_sha256,
        "policy_version": payload.policy_version,
        "purpose": payload.purpose,
        "resolution_actor_id": payload.resolution_actor_id,
        "resolution_actor_role": payload.resolution_actor_role,
        "schema_version": "gluevenir.action-envelope.v1",
    }
    return json.dumps(
        value,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
