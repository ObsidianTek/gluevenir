"""Private CockroachDB loader for exact, already-approved Safe Derivatives."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import MultipleResultsFound, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._memory_store import _SET_TENANT_CONTEXT, _VERIFY_RUNTIME_PRINCIPAL
from gluevenir._policy import _ApprovedDerivative

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_AUTHORIZED_REVIEWER_ROLES = frozenset({"human_reviewer", "program_lead"})

_LOAD_APPROVED_DERIVATIVE = text(
    """
    SELECT
        approval.id AS approval_id,
        approval.tenant_id,
        approval.program_id,
        approval.source_memory_id,
        approval.derivative_memory_id,
        approval.source_sha256,
        approval.derivative_sha256,
        approval.purpose_scopes,
        approval.audience_scopes,
        approval.policy_version AS approval_policy_version,
        approval.reviewed_by,
        approval.reviewed_at,
        approval.expires_at AS approval_expires_at,
        source.content_sha256 AS source_content_sha256,
        source.policy_version AS source_policy_version,
        source.state AS source_state,
        source.valid_from AS source_valid_from,
        source.expires_at AS source_expires_at,
        source.revoked_at AS source_revoked_at,
        derivative.content_sha256 AS derivative_content_sha256,
        derivative.policy_version AS derivative_policy_version,
        derivative.state AS derivative_state,
        derivative.valid_from AS derivative_valid_from,
        derivative.expires_at AS derivative_expires_at,
        derivative.revoked_at AS derivative_revoked_at,
        derivative.source_memory_id AS derivative_source_memory_id
    FROM derivative_approvals AS approval
    JOIN memory_records AS source
      ON source.tenant_id = approval.tenant_id
     AND source.program_id = approval.program_id
     AND source.id = approval.source_memory_id
    JOIN memory_records AS derivative
      ON derivative.tenant_id = approval.tenant_id
     AND derivative.program_id = approval.program_id
     AND derivative.id = approval.derivative_memory_id
    WHERE approval.id = :approval_id
      AND approval.tenant_id = :tenant_id
      AND approval.program_id = :program_id
      AND approval.decision = 'approved'
      AND approval.reviewed_by = :reviewer_id
      AND approval.reviewed_at IS NOT NULL
      AND approval.reviewed_at <= :now
      AND approval.expires_at > :now
      AND approval.purpose_scopes = ARRAY[CAST(:purpose AS STRING)]
      AND approval.audience_scopes = ARRAY[CAST(:audience AS STRING)]
      AND approval.policy_version = :policy_version
      AND approval.source_sha256 = source.content_sha256
      AND approval.source_sha256 = sha256(CAST(source.content AS BYTES))
      AND approval.derivative_sha256 = derivative.content_sha256
      AND approval.derivative_sha256 = sha256(CAST(derivative.content AS BYTES))
      AND source.policy_version = :policy_version
      AND derivative.policy_version = :policy_version
      AND source.state = 'active'
      AND source.content IS NOT NULL
      AND source.content_sha256 IS NOT NULL
      AND source.valid_from <= :now
      AND (source.expires_at IS NULL OR source.expires_at > :now)
      AND source.revoked_at IS NULL
      AND derivative.state = 'active'
      AND derivative.room = 'external-approved'
      AND derivative.source_memory_id = source.id
      AND derivative.content IS NOT NULL
      AND derivative.content_sha256 IS NOT NULL
      AND derivative.valid_from <= :now
      AND derivative.expires_at = approval.expires_at
      AND derivative.expires_at > :now
      AND derivative.revoked_at IS NULL
      AND derivative.purpose_scopes = approval.purpose_scopes
      AND derivative.audience_scopes = approval.audience_scopes
    """
)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    normalized = value.strip()
    if not _IDENTIFIER_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a bounded identifier")
    return normalized


def _aware(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


@dataclass(frozen=True, slots=True)
class _TrustedReviewerIdentity:
    """Reviewer authority produced by the server-side identity mapping only."""

    reviewer_id: str
    reviewer_role: str
    tenant_id: UUID
    program_id: UUID

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reviewer_id",
            _identifier("reviewer_id", self.reviewer_id),
        )
        role = _identifier("reviewer_role", self.reviewer_role)
        if role not in _AUTHORIZED_REVIEWER_ROLES:
            raise ValueError("reviewer_role is not authorized for approval")
        object.__setattr__(self, "reviewer_role", role)
        for name in ("tenant_id", "program_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")


type _ApprovalResult = _ApprovedDerivative | None
type _TransactionCallback = Callable[[Connection], _ApprovalResult]
type _TransactionRunner = Callable[..., _ApprovalResult]


class _ApprovalStoreUnavailable(RuntimeError):
    """Sanitized loader failure; callers must fail closed."""


class _CockroachApprovalStore:
    """Load one exact approved derivative through the bounded runtime role."""

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
        principal = _identifier("application_principal", application_principal)
        if not callable(_transaction_runner):
            raise TypeError("_transaction_runner must be callable")
        self._engine = engine
        self._application_principal = principal
        self._transaction_runner = _transaction_runner

    def load_approved(
        self,
        approval_id: UUID,
        *,
        reviewer: _TrustedReviewerIdentity,
        purpose: str,
        audience: str,
        policy_version: str,
        now: datetime,
    ) -> _ApprovalResult:
        """Return the exact active approval, or ``None`` when it is ineligible."""

        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")
        if type(reviewer) is not _TrustedReviewerIdentity:
            raise TypeError("reviewer must be a _TrustedReviewerIdentity")
        purpose = _identifier("purpose", purpose)
        audience = _identifier("audience", audience)
        policy_version = _identifier("policy_version", policy_version)
        now = _aware("now", now)
        parameters = {
            "approval_id": str(approval_id),
            "tenant_id": str(reviewer.tenant_id),
            "program_id": str(reviewer.program_id),
            "reviewer_id": reviewer.reviewer_id,
            "purpose": purpose,
            "audience": audience,
            "policy_version": policy_version,
            "now": now,
        }

        def load(connection: Connection) -> _ApprovalResult:
            self._authorize_transaction(connection, reviewer.tenant_id)
            try:
                row = (
                    connection.execute(_LOAD_APPROVED_DERIVATIVE, parameters)
                    .mappings()
                    .one_or_none()
                )
            except (MultipleResultsFound, SQLAlchemyError):
                raise _ApprovalStoreUnavailable(
                    "approval lookup is unavailable"
                ) from None
            if row is None:
                return None
            return _approved_derivative_from_row(
                row,
                approval_id=approval_id,
                reviewer=reviewer,
                purpose=purpose,
                audience=audience,
                policy_version=policy_version,
                now=now,
            )

        try:
            return self._transaction_runner(
                self._engine,
                load,
                max_retries=3,
                max_backoff=1,
            )
        except _ApprovalStoreUnavailable:
            raise
        except SQLAlchemyError:
            raise _ApprovalStoreUnavailable("approval lookup is unavailable") from None

    def _authorize_transaction(
        self,
        connection: Connection,
        tenant_id: UUID,
    ) -> None:
        try:
            principal = connection.execute(_VERIFY_RUNTIME_PRINCIPAL).mappings().one()
        except (MultipleResultsFound, SQLAlchemyError):
            raise _ApprovalStoreUnavailable("approval lookup is unavailable") from None
        if (
            principal.get("principal") != self._application_principal
            or principal.get("bypasses_rls") is not False
            or principal.get("is_app_member") is not True
            or principal.get("can_create_schema_objects") is not False
            or principal.get("can_create_schemas") is not False
        ):
            raise _ApprovalStoreUnavailable("approval lookup is unavailable")
        connection.execute(
            _SET_TENANT_CONTEXT,
            {"tenant_id": str(tenant_id)},
        )


def _approved_derivative_from_row(
    row: Mapping[str, Any],
    *,
    approval_id: UUID,
    reviewer: _TrustedReviewerIdentity,
    purpose: str,
    audience: str,
    policy_version: str,
    now: datetime,
) -> _ApprovedDerivative:
    try:
        returned_approval_id = UUID(str(row["approval_id"]))
        tenant_id = UUID(str(row["tenant_id"]))
        program_id = UUID(str(row["program_id"]))
        source_memory_id = UUID(str(row["source_memory_id"]))
        derivative_memory_id = UUID(str(row["derivative_memory_id"]))
        derivative_source_memory_id = UUID(str(row["derivative_source_memory_id"]))
        source_sha256 = row["source_sha256"]
        derivative_sha256 = row["derivative_sha256"]
        source_content_sha256 = row["source_content_sha256"]
        derivative_content_sha256 = row["derivative_content_sha256"]
        purpose_scopes = _exact_scopes(row["purpose_scopes"])
        audience_scopes = _exact_scopes(row["audience_scopes"])
        approval_policy_version = row["approval_policy_version"]
        source_policy_version = row["source_policy_version"]
        derivative_policy_version = row["derivative_policy_version"]
        reviewed_by = row["reviewed_by"]
        reviewed_at = _aware("reviewed_at", row["reviewed_at"])
        approval_expires_at = _aware("approval_expires_at", row["approval_expires_at"])
        source_valid_from = _aware("source_valid_from", row["source_valid_from"])
        source_expires_at = row["source_expires_at"]
        if source_expires_at is not None:
            source_expires_at = _aware("source_expires_at", source_expires_at)
        derivative_valid_from = _aware(
            "derivative_valid_from", row["derivative_valid_from"]
        )
        derivative_expires_at = _aware(
            "derivative_expires_at", row["derivative_expires_at"]
        )
    except (KeyError, TypeError, ValueError):
        raise _ApprovalStoreUnavailable("approval lookup is unavailable") from None

    hashes = (
        source_sha256,
        derivative_sha256,
        source_content_sha256,
        derivative_content_sha256,
    )
    valid_hashes = all(
        isinstance(value, str) and _SHA256_RE.fullmatch(value) for value in hashes
    )
    source_is_active = (
        row.get("source_state") == "active"
        and row.get("source_revoked_at") is None
        and source_valid_from <= now
        and (source_expires_at is None or source_expires_at > now)
    )
    derivative_is_active = (
        row.get("derivative_state") == "active"
        and row.get("derivative_revoked_at") is None
        and derivative_valid_from <= now
        and derivative_expires_at > now
    )
    exact_match = (
        returned_approval_id == approval_id
        and tenant_id == reviewer.tenant_id
        and program_id == reviewer.program_id
        and source_memory_id != derivative_memory_id
        and derivative_source_memory_id == source_memory_id
        and reviewed_by == reviewer.reviewer_id
        and reviewed_at <= now < approval_expires_at
        and approval_expires_at == derivative_expires_at
        and purpose_scopes == (purpose,)
        and audience_scopes == (audience,)
        and approval_policy_version
        == source_policy_version
        == derivative_policy_version
        == policy_version
        and valid_hashes
        and source_sha256 == source_content_sha256
        and derivative_sha256 == derivative_content_sha256
        and source_is_active
        and derivative_is_active
    )
    if not exact_match:
        raise _ApprovalStoreUnavailable("approval lookup is unavailable")

    return _ApprovedDerivative(
        approval_id=returned_approval_id,
        tenant_id=tenant_id,
        program_id=program_id,
        source_memory_id=source_memory_id,
        derivative_memory_id=derivative_memory_id,
        source_sha256=source_sha256,
        derivative_sha256=derivative_sha256,
        purpose=purpose,
        audience=audience,
        policy_version=policy_version,
        reviewed_at=reviewed_at,
        expires_at=approval_expires_at,
        source_active=True,
        derivative_active=True,
        reviewed_by=reviewed_by,
        reviewer_role=reviewer.reviewer_role,
    )


def _exact_scopes(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(
        type(item) is not str for item in value
    ):
        raise ValueError("database returned invalid approval scope metadata")
    return tuple(value)
