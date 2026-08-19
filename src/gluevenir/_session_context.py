"""Private CockroachDB writer for bounded session and intent context."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError, OperationalError, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_INTENT_LABEL_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,63}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_PRIOR_RECEIPTS = 32
_MAX_CLASSIFICATION_COUNT = 10_000


class _SessionDatabaseOperationalError(RuntimeError):
    pass


class _SessionDatabaseTimeoutError(_SessionDatabaseOperationalError):
    pass


class _SessionDatabaseDnsError(_SessionDatabaseOperationalError):
    pass


class _SessionDatabaseTlsError(_SessionDatabaseOperationalError):
    pass


class _SessionDatabaseConnectionRefusedError(_SessionDatabaseOperationalError):
    pass


class _SessionDatabaseAuthorizationError(RuntimeError):
    pass


class _SessionDatabaseError(RuntimeError):
    pass


_VERIFY_RUNTIME_PRINCIPAL = text(
    """
    SELECT
        current_user AS principal,
        COALESCE(
            (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user),
            true
        ) AS bypasses_rls,
        pg_has_role(current_user, 'gluevenir_app', 'member') AS is_app_member,
        has_schema_privilege(current_user, 'public', 'CREATE') AS
            can_create_schema_objects,
        has_database_privilege(current_user, current_database(), 'CREATE') AS
            can_create_schemas
    """
)
_SET_TENANT_CONTEXT = text("SELECT set_config('app.current_tenant', :tenant_id, true)")
_SELECT_SESSION = text(
    """
    SELECT
        tenant_id,
        program_id,
        session_id,
        intent_id,
        intent_label,
        original_intent_sha256,
        agent_id,
        actor_id,
        actor_role,
        declared_purpose,
        declared_audience,
        classification_summary,
        prior_receipt_ids,
        created_at,
        updated_at,
        expires_at
    FROM session_context
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND session_id = :session_id
    FOR UPDATE
    """
)
_INSERT_SESSION = text(
    """
    INSERT INTO session_context (
        tenant_id,
        program_id,
        session_id,
        intent_id,
        intent_label,
        original_intent_sha256,
        agent_id,
        actor_id,
        actor_role,
        declared_purpose,
        declared_audience,
        classification_summary,
        prior_receipt_ids,
        created_at,
        updated_at,
        expires_at
    ) VALUES (
        :tenant_id,
        :program_id,
        :session_id,
        :intent_id,
        :intent_label,
        :original_intent_sha256,
        :agent_id,
        :actor_id,
        :actor_role,
        :declared_purpose,
        :declared_audience,
        CAST(:classification_summary AS JSONB),
        CAST(:prior_receipt_ids AS UUID[]),
        :created_at,
        :updated_at,
        :expires_at
    )
    RETURNING session_id
    """
)
_APPEND_PRIOR_RECEIPTS = text(
    """
    UPDATE session_context
    SET prior_receipt_ids = CAST(:prior_receipt_ids AS UUID[]),
        updated_at = :updated_at
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND session_id = :session_id
      AND updated_at = :stored_updated_at
      AND prior_receipt_ids = CAST(:stored_prior_receipt_ids AS UUID[])
    RETURNING session_id
    """
)
_REQUIRE_SCOPED_PRIOR_RECEIPT = text(
    """
    SELECT id
    FROM recall_receipts
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND session_id = :session_id
      AND id = :receipt_id
    """
)


class _CandidateLabel(StrEnum):
    """Project-defined candidate labels allowed in session summaries."""

    PII = "PII"
    PHI_CANDIDATE = "PHI_CANDIDATE"
    IP_CONFIDENTIAL = "IP_CONFIDENTIAL"
    MNPI_CANDIDATE = "MNPI_CANDIDATE"
    SECRET = "SECRET"


@dataclass(frozen=True, slots=True)
class _ClassificationCount:
    """Content-free count for one bounded classification candidate."""

    label: _CandidateLabel
    count: int

    def __post_init__(self) -> None:
        if not isinstance(self.label, _CandidateLabel):
            raise TypeError("label must be a supported candidate label")
        if isinstance(self.count, bool) or not isinstance(self.count, int):
            raise TypeError("classification count must be an integer")
        if not 1 <= self.count <= _MAX_CLASSIFICATION_COUNT:
            raise ValueError("classification count is outside the bounded range")


@dataclass(frozen=True, slots=True)
class _SessionContextRecord:
    """Bounded context persisted without raw requests or conversations."""

    tenant_id: UUID
    program_id: UUID
    session_id: UUID
    intent_id: UUID
    intent_label: str
    original_intent_sha256: str
    agent_id: str
    actor_id: str
    actor_role: str
    declared_purpose: str
    declared_audience: str
    classification_summary: tuple[_ClassificationCount, ...]
    prior_receipt_ids: tuple[UUID, ...]
    created_at: datetime
    updated_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for name in ("tenant_id", "program_id", "session_id", "intent_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")

        if not isinstance(self.intent_label, str):
            raise TypeError("intent_label must be a string")
        intent_label = self.intent_label.strip().casefold()
        if not _INTENT_LABEL_RE.fullmatch(intent_label):
            raise ValueError("intent_label must be a normalized bounded label")
        object.__setattr__(self, "intent_label", intent_label)

        if not isinstance(self.original_intent_sha256, str) or not _SHA256_RE.fullmatch(
            self.original_intent_sha256
        ):
            raise ValueError(
                "original_intent_sha256 must be a lowercase SHA-256 digest"
            )

        for name in (
            "agent_id",
            "actor_id",
            "actor_role",
            "declared_purpose",
            "declared_audience",
        ):
            object.__setattr__(
                self, name, _bounded_identifier(name, getattr(self, name))
            )

        if not isinstance(self.classification_summary, tuple):
            raise TypeError("classification_summary must be a tuple")
        if len(self.classification_summary) > len(_CandidateLabel):
            raise ValueError("classification_summary has too many labels")
        if any(
            not isinstance(item, _ClassificationCount)
            for item in self.classification_summary
        ):
            raise TypeError("classification_summary values must be typed counts")
        labels = tuple(item.label for item in self.classification_summary)
        if len(set(labels)) != len(labels):
            raise ValueError("classification_summary must not repeat labels")
        object.__setattr__(
            self,
            "classification_summary",
            tuple(
                sorted(self.classification_summary, key=lambda item: item.label.value)
            ),
        )

        if not isinstance(self.prior_receipt_ids, tuple):
            raise TypeError("prior_receipt_ids must be a tuple")
        if len(self.prior_receipt_ids) > _MAX_PRIOR_RECEIPTS:
            raise ValueError("prior_receipt_ids exceeds the bounded history")
        if any(
            not isinstance(receipt_id, UUID) for receipt_id in self.prior_receipt_ids
        ):
            raise TypeError("prior_receipt_ids values must be UUIDs")
        if len(set(self.prior_receipt_ids)) != len(self.prior_receipt_ids):
            raise ValueError("prior_receipt_ids must not contain duplicates")

        for name in ("created_at", "updated_at", "expires_at"):
            _aware(name, getattr(self, name))
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.expires_at <= self.updated_at:
            raise ValueError("expires_at must follow updated_at")


type _SessionCallback = Callable[[Connection], _SessionContextRecord]
type _TransactionRunner = Callable[..., _SessionContextRecord]


class _CockroachSessionContextWriter:
    """Internal writer; public callers must enter the action gateway."""

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
        if not callable(_transaction_runner):
            raise TypeError("_transaction_runner must be callable")
        self._engine = engine
        self._application_principal = _bounded_identifier(
            "application_principal", application_principal
        )
        self._transaction_runner = _transaction_runner

    def write(self, record: _SessionContextRecord) -> _SessionContextRecord:
        """Insert once, safely append prior receipts, or return an idempotent row."""

        if not isinstance(record, _SessionContextRecord):
            raise TypeError("record must be a _SessionContextRecord")

        def store_context(connection: Connection) -> _SessionContextRecord:
            self._authorize_transaction(connection, record.tenant_id)
            selected = (
                connection.execute(
                    _SELECT_SESSION,
                    _identity_parameters(record),
                )
                .mappings()
                .one_or_none()
            )
            if selected is None:
                returned_id = _returned_session_id(
                    connection.execute(_INSERT_SESSION, _record_parameters(record))
                )
                if returned_id != record.session_id:
                    raise RuntimeError("database returned an unexpected session ID")
                return record

            stored = _record_from_row(selected)
            if _immutable_values(stored) != _immutable_values(record):
                raise PermissionError(
                    "existing session context does not match bounded context"
                )

            stored_prior = stored.prior_receipt_ids
            requested_prior = record.prior_receipt_ids
            if requested_prior == stored_prior or _is_prefix(
                requested_prior, stored_prior
            ):
                return stored
            if not _is_prefix(stored_prior, requested_prior):
                raise PermissionError("prior receipt history cannot diverge")
            if record.updated_at <= stored.updated_at:
                raise PermissionError(
                    "prior receipt history requires a later update time"
                )

            _require_scoped_prior_receipts(
                connection,
                record,
                requested_prior[len(stored_prior) :],
            )

            parameters = _record_parameters(record)
            parameters.update(
                {
                    "stored_updated_at": stored.updated_at,
                    "stored_prior_receipt_ids": [
                        str(receipt_id) for receipt_id in stored.prior_receipt_ids
                    ],
                }
            )
            returned_id = _returned_session_id(
                connection.execute(_APPEND_PRIOR_RECEIPTS, parameters)
            )
            if returned_id != record.session_id:
                raise RuntimeError("database did not update the exact session context")
            return record

        try:
            return self._transaction_runner(
                self._engine,
                store_context,
                max_retries=3,
                max_backoff=1,
            )
        except SQLAlchemyError as error:
            sqlstate = (
                getattr(error.orig, "sqlstate", None)
                if isinstance(error, DBAPIError)
                else None
            )
            if sqlstate == "42501":
                failure = _SessionDatabaseAuthorizationError
            elif isinstance(error, OperationalError):
                message = str(error).casefold()
                if "timeout" in message:
                    failure = _SessionDatabaseTimeoutError
                elif any(
                    marker in message
                    for marker in (
                        "could not translate host name",
                        "name or service not known",
                        "nodename nor servname",
                    )
                ):
                    failure = _SessionDatabaseDnsError
                elif "ssl" in message or "certificate" in message:
                    failure = _SessionDatabaseTlsError
                elif "connection refused" in message:
                    failure = _SessionDatabaseConnectionRefusedError
                else:
                    failure = _SessionDatabaseOperationalError
            else:
                failure = _SessionDatabaseError
            raise failure("session context transaction failed") from None

    def _authorize_transaction(self, connection: Connection, tenant_id: UUID) -> None:
        principal = connection.execute(_VERIFY_RUNTIME_PRINCIPAL).mappings().one()
        if (
            principal.get("principal") != self._application_principal
            or principal.get("bypasses_rls") is not False
            or principal.get("is_app_member") is not True
            or principal.get("can_create_schema_objects") is not False
            or principal.get("can_create_schemas") is not False
        ):
            raise PermissionError("database principal is not the bounded app role")
        connection.execute(_SET_TENANT_CONTEXT, {"tenant_id": str(tenant_id)})


def _bounded_identifier(name: str, value: object) -> str:
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


def _identity_parameters(record: _SessionContextRecord) -> dict[str, object]:
    return {
        "tenant_id": str(record.tenant_id),
        "program_id": str(record.program_id),
        "session_id": str(record.session_id),
    }


def _record_parameters(record: _SessionContextRecord) -> dict[str, object]:
    parameters = _identity_parameters(record)
    parameters.update(
        {
            "intent_id": str(record.intent_id),
            "intent_label": record.intent_label,
            "original_intent_sha256": record.original_intent_sha256,
            "agent_id": record.agent_id,
            "actor_id": record.actor_id,
            "actor_role": record.actor_role,
            "declared_purpose": record.declared_purpose,
            "declared_audience": record.declared_audience,
            "classification_summary": json.dumps(
                {
                    item.label.value: item.count
                    for item in record.classification_summary
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            "prior_receipt_ids": [
                str(receipt_id) for receipt_id in record.prior_receipt_ids
            ],
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "expires_at": record.expires_at,
        }
    )
    return parameters


def _record_from_row(row: Mapping[str, Any]) -> _SessionContextRecord:
    try:
        summary = row["classification_summary"]
        prior_ids = row["prior_receipt_ids"]
        if not isinstance(summary, Mapping):
            raise TypeError
        if not isinstance(prior_ids, (list, tuple)):
            raise TypeError
        classifications = tuple(
            _ClassificationCount(_CandidateLabel(str(label)), count)
            for label, count in summary.items()
        )
        return _SessionContextRecord(
            tenant_id=UUID(str(row["tenant_id"])),
            program_id=UUID(str(row["program_id"])),
            session_id=UUID(str(row["session_id"])),
            intent_id=UUID(str(row["intent_id"])),
            intent_label=row["intent_label"],
            original_intent_sha256=row["original_intent_sha256"],
            agent_id=row["agent_id"],
            actor_id=row["actor_id"],
            actor_role=row["actor_role"],
            declared_purpose=row["declared_purpose"],
            declared_audience=row["declared_audience"],
            classification_summary=classifications,
            prior_receipt_ids=tuple(UUID(str(receipt_id)) for receipt_id in prior_ids),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            expires_at=row["expires_at"],
        )
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("database returned invalid session context") from None


def _immutable_values(record: _SessionContextRecord) -> tuple[object, ...]:
    return (
        record.tenant_id,
        record.program_id,
        record.session_id,
        record.intent_id,
        record.intent_label,
        record.original_intent_sha256,
        record.agent_id,
        record.actor_id,
        record.actor_role,
        record.declared_purpose,
        record.declared_audience,
        record.classification_summary,
        record.created_at,
        record.expires_at,
    )


def _is_prefix(prefix: tuple[UUID, ...], values: tuple[UUID, ...]) -> bool:
    return len(prefix) <= len(values) and values[: len(prefix)] == prefix


def _prior_receipt_context_sha256(receipt_ids: tuple[UUID, ...]) -> str:
    """Hash the canonical bounded receipt history without loading receipt content."""

    if not isinstance(receipt_ids, tuple):
        raise TypeError("receipt_ids must be a tuple")
    if len(receipt_ids) > _MAX_PRIOR_RECEIPTS:
        raise ValueError("receipt_ids exceeds the bounded history")
    if any(not isinstance(receipt_id, UUID) for receipt_id in receipt_ids):
        raise TypeError("receipt_ids values must be UUIDs")
    if len(set(receipt_ids)) != len(receipt_ids):
        raise ValueError("receipt_ids must not contain duplicates")
    canonical = json.dumps(
        [str(receipt_id) for receipt_id in receipt_ids],
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _require_scoped_prior_receipts(
    connection: Connection,
    record: _SessionContextRecord,
    appended_receipt_ids: tuple[UUID, ...],
) -> None:
    for receipt_id in appended_receipt_ids:
        selected = (
            connection.execute(
                _REQUIRE_SCOPED_PRIOR_RECEIPT,
                {
                    "tenant_id": str(record.tenant_id),
                    "program_id": str(record.program_id),
                    "session_id": str(record.session_id),
                    "receipt_id": str(receipt_id),
                },
            )
            .mappings()
            .one_or_none()
        )
        try:
            returned_id = None if selected is None else UUID(str(selected["id"]))
        except (KeyError, TypeError, ValueError):
            raise PermissionError(
                "prior receipt does not belong to bounded session"
            ) from None
        if returned_id != receipt_id:
            raise PermissionError("prior receipt does not belong to bounded session")


def _returned_session_id(result: Any) -> UUID:
    try:
        row = result.mappings().one()
        return UUID(str(row["session_id"]))
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("database returned an invalid session ID") from None
