"""Private CockroachDB adapter for bounded, policy-scoped vector recall."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Engine, bindparam, text
from sqlalchemy_cockroachdb.transaction import run_transaction

_ALLOWED_ROOMS = frozenset(
    {"clinical-restricted", "research-confidential", "external-approved"}
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CONTEXT_CHARACTERS = 256

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
_SCOPED_RECALL = text(
    """
    SELECT
        id AS memory_id,
        content,
        content_sha256
    FROM memory_records AS memory
    WHERE memory.tenant_id = :tenant_id
      AND memory.program_id = :program_id
      AND memory.state = 'active'
      AND memory.content IS NOT NULL
      AND memory.content_sha256 IS NOT NULL
      AND memory.embedding IS NOT NULL
      AND memory.id IN :executable_memory_ids
      AND memory.room IN :allowed_rooms
      AND memory.purpose_scopes && ARRAY[CAST(:purpose AS STRING)]
      AND memory.audience_scopes && ARRAY[CAST(:audience AS STRING)]
      AND memory.valid_from <= :now
      AND (memory.expires_at IS NULL OR memory.expires_at > :now)
      AND memory.revoked_at IS NULL
      AND (
          memory.room != 'external-approved'
          OR EXISTS (
              SELECT 1
              FROM derivative_approvals AS approval
              JOIN memory_records AS source
                ON source.tenant_id = approval.tenant_id
               AND source.program_id = approval.program_id
               AND source.id = approval.source_memory_id
              WHERE approval.tenant_id = memory.tenant_id
                AND approval.program_id = memory.program_id
                AND approval.source_memory_id = memory.source_memory_id
                AND approval.derivative_memory_id = memory.id
                AND approval.decision = 'approved'
                AND approval.reviewed_by IS NOT NULL
                AND approval.reviewed_at IS NOT NULL
                AND approval.reviewed_at <= :now
                AND approval.expires_at = memory.expires_at
                AND approval.expires_at > :now
                AND approval.purpose_scopes = memory.purpose_scopes
                AND approval.audience_scopes = memory.audience_scopes
                AND approval.source_sha256 = source.content_sha256
                AND approval.source_sha256 = sha256(CAST(source.content AS BYTES))
                AND approval.derivative_sha256 = memory.content_sha256
                AND approval.policy_version = memory.policy_version
                AND approval.policy_version = source.policy_version
                AND source.state = 'active'
                AND source.content IS NOT NULL
                AND source.content_sha256 IS NOT NULL
                AND source.valid_from <= :now
                AND (source.expires_at IS NULL OR source.expires_at > :now)
                AND source.revoked_at IS NULL
          )
      )
    ORDER BY memory.embedding <=> CAST(:query_embedding AS VECTOR(256))
    LIMIT :top_k
    """
).bindparams(
    bindparam("executable_memory_ids", expanding=True),
    bindparam("allowed_rooms", expanding=True),
)


@dataclass(frozen=True, slots=True)
class RecallScope:
    """Server-authorized inputs for exactly one bounded recall transaction."""

    tenant_id: UUID
    program_id: UUID
    embedding: tuple[float, ...]
    executable_memory_ids: tuple[UUID, ...]
    now: datetime
    top_k: int
    allowed_rooms: tuple[str, ...]
    purpose: str
    audience: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "program_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")

        if not isinstance(self.embedding, tuple):
            raise TypeError("embedding must be a tuple of floats")
        if len(self.embedding) != 256:
            raise ValueError("embedding must contain exactly 256 floats")
        if any(type(value) is not float for value in self.embedding):
            raise TypeError("embedding values must be floats")
        if any(not math.isfinite(value) for value in self.embedding):
            raise ValueError("embedding values must be finite")

        if not isinstance(self.executable_memory_ids, tuple):
            raise TypeError("executable_memory_ids must be a tuple")
        if not 1 <= len(self.executable_memory_ids) <= 5:
            raise ValueError("executable_memory_ids must contain one to five IDs")
        if any(not isinstance(value, UUID) for value in self.executable_memory_ids):
            raise TypeError("executable_memory_ids values must be UUIDs")
        if len(set(self.executable_memory_ids)) != len(self.executable_memory_ids):
            raise ValueError("executable_memory_ids must not contain duplicates")

        if not isinstance(self.now, datetime) or self.now.utcoffset() is None:
            raise ValueError("now must be a timezone-aware datetime")
        if isinstance(self.top_k, bool) or not isinstance(self.top_k, int):
            raise TypeError("top_k must be an integer")
        if not 1 <= self.top_k <= 5:
            raise ValueError("top_k must be between 1 and 5")

        if not isinstance(self.allowed_rooms, tuple):
            raise TypeError("allowed_rooms must be a tuple")
        if not self.allowed_rooms:
            raise ValueError("allowed_rooms must not be empty")
        if any(type(room) is not str for room in self.allowed_rooms):
            raise TypeError("allowed_rooms values must be strings")
        unknown_rooms = set(self.allowed_rooms) - _ALLOWED_ROOMS
        if unknown_rooms:
            raise ValueError("allowed_rooms contains an unsupported room")
        if len(set(self.allowed_rooms)) != len(self.allowed_rooms):
            raise ValueError("allowed_rooms must not contain duplicates")

        for name in ("purpose", "audience"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            normalized = value.strip()
            if len(normalized) > _MAX_CONTEXT_CHARACTERS:
                raise ValueError(f"{name} is too long")
            object.__setattr__(self, name, normalized)


@dataclass(frozen=True, slots=True)
class RecalledMemory:
    """Authorized content and its content-binding hash."""

    memory_id: UUID
    content: str
    content_sha256: str


type _RecallResult = tuple[RecalledMemory, ...]
type _TransactionCallback = Callable[[Connection], _RecallResult]
type _TransactionRunner = Callable[..., _RecallResult]


class _CockroachMemoryStore:
    """Internal storage port; public callers must enter the action gateway."""

    def __init__(
        self,
        engine: Engine,
        *,
        application_principal: str,
        _transaction_runner: _TransactionRunner = run_transaction,
    ) -> None:
        if (
            not isinstance(application_principal, str)
            or not application_principal.strip()
        ):
            raise ValueError("application_principal must be a non-empty string")
        self._engine = engine
        self._application_principal = application_principal.strip()
        # This injection seam exists only so offline tests need no live database.
        self._transaction_runner = _transaction_runner

    def recall(self, scope: RecallScope) -> _RecallResult:
        """Return authorized memories through an officially retried transaction."""

        if not isinstance(scope, RecallScope):
            raise TypeError("scope must be a RecallScope")

        def scoped_recall(connection: Connection) -> _RecallResult:
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
                {"tenant_id": str(scope.tenant_id)},
            )
            result = connection.execute(_SCOPED_RECALL, _query_parameters(scope))
            return tuple(_memory_from_row(row) for row in result.mappings().all())

        callback: _TransactionCallback = scoped_recall
        return self._transaction_runner(
            self._engine,
            callback,
            max_retries=3,
            max_backoff=1,
        )


def _query_parameters(scope: RecallScope) -> dict[str, object]:
    return {
        "tenant_id": str(scope.tenant_id),
        "program_id": str(scope.program_id),
        "executable_memory_ids": tuple(
            str(value) for value in scope.executable_memory_ids
        ),
        "allowed_rooms": scope.allowed_rooms,
        "purpose": scope.purpose,
        "audience": scope.audience,
        "now": scope.now,
        "query_embedding": json.dumps(
            scope.embedding,
            allow_nan=False,
            separators=(",", ":"),
        ),
        "top_k": scope.top_k,
    }


def _memory_from_row(row: Mapping[str, Any]) -> RecalledMemory:
    try:
        memory_id = UUID(str(row["memory_id"]))
        content = row["content"]
        content_sha256 = row["content_sha256"]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("database returned an invalid memory record") from error

    if not isinstance(content, str):
        raise ValueError("database returned memory without text content")
    if not isinstance(content_sha256, str) or not _SHA256_RE.fullmatch(content_sha256):
        raise ValueError("database returned memory without a valid content hash")
    if hashlib.sha256(content.encode("utf-8")).hexdigest() != content_sha256:
        raise ValueError("database returned content that does not match its hash")
    return RecalledMemory(
        memory_id=memory_id,
        content=content,
        content_sha256=content_sha256,
    )
