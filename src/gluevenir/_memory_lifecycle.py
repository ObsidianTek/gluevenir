"""Private retry-safe CockroachDB memory lifecycle operations."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import MultipleResultsFound, NoResultFound, SQLAlchemyError
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._memory_store import (
    _SET_TENANT_CONTEXT,
    _VERIFY_RUNTIME_PRINCIPAL,
)

_NORMAL_WRITE_ROOMS = frozenset({"clinical-restricted", "research-confidential"})
_PURPOSES = frozenset(
    {"partner_status", "program_status", "research_review", "safety_review"}
)
_AUDIENCES = frozenset(
    {
        "internal-clinical",
        "internal-program-lead",
        "internal-research",
        "partner-alpha-synthetic",
        "partner-beta-synthetic",
    }
)
_SENSITIVITIES = frozenset(
    {
        "IP_CONFIDENTIAL",
        "MNPI_CANDIDATE",
        "PHI_CANDIDATE",
        "PII",
        "SECRET",
    }
)
_REMEMBER_REASON_CODES = frozenset({"MEMORY_STORED"})
_LIFECYCLE_REASON_CODES = frozenset(
    {"ERASURE_REQUEST", "POLICY_REVOKED", "RETENTION_EXPIRED", "SOURCE_WITHDRAWN"}
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_MAX_CONTENT_CHARACTERS = 2_000
_MAX_FIELD_CHARACTERS = 256
_MAX_SCOPES = 8

_INSERT_MEMORY = text(
    """
    INSERT INTO memory_records (
        id, tenant_id, program_id, room, content, embedding, sensitivity,
        purpose_scopes, audience_scopes, state, valid_from, expires_at,
        revoked_at, content_sha256, policy_version, created_at, created_by
    ) VALUES (
        :memory_id, :tenant_id, :program_id, :room, :content,
        CAST(:embedding AS VECTOR(256)), :sensitivity, :purpose_scopes,
        :audience_scopes, 'active', :valid_from, :expires_at, NULL,
        :content_sha256, :policy_version, :created_at, :created_by
    )
    RETURNING id
    """
)
_REVOKE_MEMORY = text(
    """
    UPDATE memory_records
    SET state = 'revoked', revoked_at = :occurred_at
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND id = :memory_id
      AND state IN ('proposed', 'active', 'quarantined')
      AND content IS NOT NULL
      AND content_sha256 IS NOT NULL
    RETURNING id
    """
)
_FORGET_MEMORY = text(
    """
    UPDATE memory_records
    SET state = 'forgotten',
        revoked_at = :occurred_at,
        content = NULL,
        embedding = NULL,
        content_sha256 = NULL
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND id = :memory_id
      AND state IN ('proposed', 'active', 'quarantined', 'revoked')
      AND (content IS NOT NULL OR embedding IS NOT NULL OR content_sha256 IS NOT NULL)
    RETURNING id
    """
)
_QUARANTINE_DEPENDENT_DERIVATIVES = text(
    """
    UPDATE memory_records
    SET state = 'quarantined'
    WHERE tenant_id = :tenant_id
      AND program_id = :program_id
      AND source_memory_id = :memory_id
      AND room = 'external-approved'
      AND state = 'active'
    RETURNING id
    """
)
_INSERT_POLICY_EVENT = text(
    """
    INSERT INTO policy_events (
        tenant_id, program_id, operation, outcome, reason_code,
        object_type, object_id, actor_id, actor_role, purpose, audience
    ) VALUES (
        :tenant_id, :program_id, :operation, 'ALLOW', :reason_code,
        'memory_record', :memory_id, :actor_id, :actor_role, :purpose, :audience
    )
    RETURNING id
    """
)


def _bounded_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > _MAX_FIELD_CHARACTERS:
        raise ValueError(f"{name} is too long")
    return normalized


def _bounded_identifier(name: str, value: object) -> str:
    normalized = _bounded_text(name, value)
    if not _IDENTIFIER_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a bounded identifier")
    return normalized


def _aware_datetime(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


def _uuid(name: str, value: object) -> UUID:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be a UUID")
    return value


def _allowlisted_values(
    name: str,
    values: object,
    allowed: frozenset[str],
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError(f"{name} must be a tuple")
    if not values or len(values) > _MAX_SCOPES:
        raise ValueError(f"{name} must contain between 1 and {_MAX_SCOPES} values")
    if any(type(value) is not str for value in values):
        raise TypeError(f"{name} values must be strings")
    if any(value not in allowed for value in values):
        raise ValueError(f"{name} contains an unsupported value")
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must not contain duplicates")
    return values


@dataclass(frozen=True, slots=True)
class _LifecycleContext:
    """Server-authorized actor and policy context for a lifecycle action."""

    tenant_id: UUID
    program_id: UUID
    actor_id: str
    actor_role: str
    purpose: str
    audience: str
    policy_version: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "program_id"):
            _uuid(name, getattr(self, name))
        for name in ("actor_id", "actor_role", "policy_version"):
            object.__setattr__(
                self,
                name,
                _bounded_identifier(name, getattr(self, name)),
            )
        purpose = _bounded_text("purpose", self.purpose)
        audience = _bounded_text("audience", self.audience)
        if purpose not in _PURPOSES:
            raise ValueError("purpose is not allowlisted")
        if audience not in _AUDIENCES:
            raise ValueError("audience is not allowlisted")
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "audience", audience)


@dataclass(frozen=True, slots=True)
class _RememberInput:
    """Validated exact content for one normal, non-derivative memory write."""

    context: _LifecycleContext
    memory_id: UUID
    content: str
    embedding: tuple[float, ...]
    room: str
    sensitivity: tuple[str, ...]
    purpose_scopes: tuple[str, ...]
    audience_scopes: tuple[str, ...]
    valid_from: datetime
    expires_at: datetime | None
    created_at: datetime
    created_by: str
    reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.context, _LifecycleContext):
            raise TypeError("context must be a _LifecycleContext")
        _uuid("memory_id", self.memory_id)
        if not isinstance(self.content, str) or not self.content.strip():
            raise ValueError("content must be a non-empty string")
        if len(self.content) > _MAX_CONTENT_CHARACTERS:
            raise ValueError("content is too long")
        if not isinstance(self.embedding, tuple):
            raise TypeError("embedding must be a tuple of floats")
        if len(self.embedding) != 256:
            raise ValueError("embedding must contain exactly 256 floats")
        if any(type(value) is not float for value in self.embedding):
            raise TypeError("embedding values must be floats")
        if any(not math.isfinite(value) for value in self.embedding):
            raise ValueError("embedding values must be finite")
        room = _bounded_text("room", self.room)
        if room not in _NORMAL_WRITE_ROOMS:
            raise ValueError("room is not allowed for a normal memory write")
        object.__setattr__(self, "room", room)
        _allowlisted_values("sensitivity", self.sensitivity, _SENSITIVITIES)
        _allowlisted_values("purpose_scopes", self.purpose_scopes, _PURPOSES)
        _allowlisted_values("audience_scopes", self.audience_scopes, _AUDIENCES)
        _aware_datetime("valid_from", self.valid_from)
        _aware_datetime("created_at", self.created_at)
        if self.expires_at is not None:
            _aware_datetime("expires_at", self.expires_at)
            if self.expires_at <= self.valid_from:
                raise ValueError("expires_at must be later than valid_from")
        object.__setattr__(
            self,
            "created_by",
            _bounded_identifier("created_by", self.created_by),
        )
        reason_code = _bounded_identifier("reason_code", self.reason_code)
        if reason_code not in _REMEMBER_REASON_CODES:
            raise ValueError("reason_code is not allowed for remember")
        object.__setattr__(self, "reason_code", reason_code)


@dataclass(frozen=True, slots=True)
class _LifecycleInput:
    """Validated target and reason for a revoke or forget action."""

    context: _LifecycleContext
    memory_id: UUID
    occurred_at: datetime
    reason_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.context, _LifecycleContext):
            raise TypeError("context must be a _LifecycleContext")
        _uuid("memory_id", self.memory_id)
        _aware_datetime("occurred_at", self.occurred_at)
        reason_code = _bounded_identifier("reason_code", self.reason_code)
        if reason_code not in _LIFECYCLE_REASON_CODES:
            raise ValueError("reason_code is not allowed for lifecycle actions")
        object.__setattr__(self, "reason_code", reason_code)


@dataclass(frozen=True, slots=True)
class _LifecycleResult:
    """Content-free result from one committed lifecycle transaction."""

    memory_id: UUID
    event_id: UUID
    content_sha256: str | None = None
    quarantined_derivative_ids: tuple[UUID, ...] = ()


type _LifecycleCallback = Callable[[Connection], _LifecycleResult]
type _TransactionRunner = Callable[..., _LifecycleResult]


class _CockroachMemoryLifecycle:
    """Internal lifecycle adapter; public callers must use the action gateway."""

    def __init__(
        self,
        engine: Engine,
        *,
        application_principal: str,
        _transaction_runner: _TransactionRunner = run_transaction,
    ) -> None:
        if isinstance(engine, Engine) and not engine.hide_parameters:
            raise ValueError("runtime engine must hide SQL parameter values")
        self._engine = engine
        self._application_principal = _bounded_identifier(
            "application_principal", application_principal
        )
        self._transaction_runner = _transaction_runner

    def remember(self, item: _RememberInput) -> _LifecycleResult:
        """Atomically store one normal memory and one content-free event."""

        if not isinstance(item, _RememberInput):
            raise TypeError("item must be a _RememberInput")
        content_sha256 = hashlib.sha256(item.content.encode("utf-8")).hexdigest()
        if not _SHA256_RE.fullmatch(content_sha256):
            raise ValueError("computed content hash is invalid")

        def store_memory(connection: Connection) -> _LifecycleResult:
            self._authorize_transaction(connection, item.context)
            returned_id = _one_id(
                connection.execute(
                    _INSERT_MEMORY,
                    _remember_parameters(item, content_sha256),
                ),
                expected=item.memory_id,
                operation="remember",
            )
            event_id = _insert_event(
                connection,
                context=item.context,
                memory_id=returned_id,
                operation="REMEMBER",
                reason_code=item.reason_code,
            )
            return _LifecycleResult(
                memory_id=returned_id,
                event_id=event_id,
                content_sha256=content_sha256,
            )

        try:
            return self._run(store_memory)
        except SQLAlchemyError:
            raise RuntimeError("memory transaction failed") from None

    def revoke(self, action: _LifecycleInput) -> _LifecycleResult:
        """Revoke exactly one eligible memory and quarantine active derivatives."""

        return self._change_lifecycle(action, operation="REVOKE")

    def forget(self, action: _LifecycleInput) -> _LifecycleResult:
        """Clear exactly one eligible memory and quarantine active derivatives."""

        return self._change_lifecycle(action, operation="FORGET")

    def _change_lifecycle(
        self,
        action: _LifecycleInput,
        *,
        operation: str,
    ) -> _LifecycleResult:
        if not isinstance(action, _LifecycleInput):
            raise TypeError("action must be a _LifecycleInput")
        target_statement = _REVOKE_MEMORY if operation == "REVOKE" else _FORGET_MEMORY

        def change_memory(connection: Connection) -> _LifecycleResult:
            self._authorize_transaction(connection, action.context)
            parameters = {
                "tenant_id": str(action.context.tenant_id),
                "program_id": str(action.context.program_id),
                "memory_id": str(action.memory_id),
                "occurred_at": action.occurred_at,
            }
            returned_id = _one_id(
                connection.execute(target_statement, parameters),
                expected=action.memory_id,
                operation=operation.casefold(),
            )
            derivative_ids = _all_ids(
                connection.execute(_QUARANTINE_DEPENDENT_DERIVATIVES, parameters)
            )
            event_id = _insert_event(
                connection,
                context=action.context,
                memory_id=returned_id,
                operation=operation,
                reason_code=action.reason_code,
            )
            return _LifecycleResult(
                memory_id=returned_id,
                event_id=event_id,
                quarantined_derivative_ids=derivative_ids,
            )

        return self._run(change_memory)

    def _authorize_transaction(
        self,
        connection: Connection,
        context: _LifecycleContext,
    ) -> None:
        principal = connection.execute(_VERIFY_RUNTIME_PRINCIPAL).mappings().one()
        if (
            principal.get("principal") != self._application_principal
            or principal.get("bypasses_rls") is not False
            or principal.get("is_app_member") is not True
            or principal.get("can_create_schema_objects") is not False
            or principal.get("can_create_schemas") is not False
        ):
            raise PermissionError("database principal is not the bounded app role")
        connection.execute(
            _SET_TENANT_CONTEXT,
            {"tenant_id": str(context.tenant_id)},
        )

    def _run(self, callback: _LifecycleCallback) -> _LifecycleResult:
        return self._transaction_runner(
            self._engine,
            callback,
            max_retries=3,
            max_backoff=1,
        )


def _remember_parameters(
    item: _RememberInput,
    content_sha256: str,
) -> dict[str, object]:
    return {
        "memory_id": str(item.memory_id),
        "tenant_id": str(item.context.tenant_id),
        "program_id": str(item.context.program_id),
        "room": item.room,
        "content": item.content,
        "embedding": json.dumps(item.embedding, allow_nan=False, separators=(",", ":")),
        "sensitivity": list(item.sensitivity),
        "purpose_scopes": list(item.purpose_scopes),
        "audience_scopes": list(item.audience_scopes),
        "valid_from": item.valid_from,
        "expires_at": item.expires_at,
        "content_sha256": content_sha256,
        "policy_version": item.context.policy_version,
        "created_at": item.created_at,
        "created_by": item.created_by,
    }


def _insert_event(
    connection: Connection,
    *,
    context: _LifecycleContext,
    memory_id: UUID,
    operation: str,
    reason_code: str,
) -> UUID:
    parameters = {
        "tenant_id": str(context.tenant_id),
        "program_id": str(context.program_id),
        "operation": operation,
        "reason_code": reason_code,
        "memory_id": str(memory_id),
        "actor_id": context.actor_id,
        "actor_role": context.actor_role,
        "purpose": context.purpose,
        "audience": context.audience,
    }
    return _one_id(
        connection.execute(_INSERT_POLICY_EVENT, parameters),
        operation=f"{operation.casefold()} event",
    )


def _one_id(
    result: Any,
    *,
    operation: str,
    expected: UUID | None = None,
) -> UUID:
    try:
        row = result.mappings().one()
        returned_id = UUID(str(row["id"]))
    except (
        KeyError,
        MultipleResultsFound,
        NoResultFound,
        TypeError,
        ValueError,
    ) as error:
        raise RuntimeError(
            f"{operation} did not affect exactly one valid row"
        ) from error
    if expected is not None and returned_id != expected:
        raise RuntimeError(f"{operation} returned an unexpected memory id")
    return returned_id


def _all_ids(result: Any) -> tuple[UUID, ...]:
    try:
        ids = tuple(UUID(str(row["id"])) for row in result.mappings().all())
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("derivative quarantine returned an invalid id") from error
    if len(ids) != len(set(ids)):
        raise RuntimeError("derivative quarantine returned duplicate ids")
    return tuple(sorted(ids, key=lambda value: value.int))
