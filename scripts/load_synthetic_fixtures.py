"""Load the bounded synthetic demo fixtures through a retry-safe transaction."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, bindparam, create_engine, text
from sqlalchemy.pool import NullPool
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._database import cockroach_url

ROOT = Path(__file__).resolve().parents[1]
MEMORY_FIXTURE = ROOT / "fixtures" / "synthetic" / "memory_records.json"
APPROVAL_FIXTURE = ROOT / "fixtures" / "synthetic" / "derivative_approvals.json"
POLICY_VERSION = "bio-demo-v1"

MEMORY_INSERT = text(
    """
    INSERT INTO memory_records (
        id, tenant_id, program_id, room, content, sensitivity,
        purpose_scopes, audience_scopes, source_memory_id, state,
        valid_from, expires_at, revoked_at, content_sha256,
        policy_version, created_at, created_by
    ) VALUES (
        :id, :tenant_id, :program_id, :room, :content, :sensitivity,
        :purpose_scopes, :audience_scopes, :source_memory_id, :state,
        :valid_from, :expires_at, :revoked_at, :content_sha256,
        :policy_version, :created_at, :created_by
    )
    """
)
APPROVAL_INSERT = text(
    """
    INSERT INTO derivative_approvals (
        id, tenant_id, program_id, source_memory_id, derivative_memory_id,
        decision, reviewed_by, reviewed_at, reason_code, source_sha256,
        derivative_sha256, purpose_scopes, audience_scopes, expires_at,
        policy_version, created_at
    ) VALUES (
        :id, :tenant_id, :program_id, :source_memory_id, :derivative_memory_id,
        :decision, :reviewed_by, :reviewed_at, :reason_code, :source_sha256,
        :derivative_sha256, :purpose_scopes, :audience_scopes, :expires_at,
        :policy_version, :created_at
    )
    """
)
MEMORY_SELECT = text(
    """
    SELECT id, tenant_id, program_id, room, content, sensitivity,
           purpose_scopes, audience_scopes, source_memory_id, state,
           valid_from, expires_at, revoked_at, content_sha256, policy_version,
           created_at, created_by
      FROM memory_records
     WHERE id IN :fixture_ids
    """
).bindparams(bindparam("fixture_ids", expanding=True))
APPROVAL_SELECT = text(
    """
    SELECT id, tenant_id, program_id, source_memory_id,
           derivative_memory_id, decision, reviewed_by, reviewed_at,
           reason_code, source_sha256, derivative_sha256, purpose_scopes,
           audience_scopes, expires_at, policy_version, created_at
      FROM derivative_approvals
     WHERE id IN :fixture_ids
    """
).bindparams(bindparam("fixture_ids", expanding=True))


def _document(path: Path, collection: str) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("synthetic_data") is not True:
        raise ValueError(f"{path.name} is not explicitly synthetic")
    rows = document.get(collection)
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{path.name} has no {collection}")
    return rows


def _memory_rows() -> list[dict[str, Any]]:
    rows = _document(MEMORY_FIXTURE, "records")
    prepared: list[dict[str, Any]] = []
    for row in rows:
        content = row["content"]
        expected_hash = (
            hashlib.sha256(content.encode("utf-8")).hexdigest()
            if content is not None
            else None
        )
        if row["content_sha256"] != expected_hash:
            raise ValueError("synthetic memory content hash mismatch")
        prepared.append(
            {
                "id": row["memory_id"],
                "tenant_id": row["tenant_id"],
                "program_id": row["program_id"],
                "room": row["room"],
                "content": content,
                "sensitivity": row["data_classes"],
                "purpose_scopes": row["purpose_scopes"],
                "audience_scopes": row["audience_scopes"],
                "source_memory_id": row["source_memory_id"],
                "state": row["state"],
                "valid_from": row["valid_from"],
                "expires_at": row["expires_at"],
                "revoked_at": row.get("revoked_at") or row.get("forgotten_at"),
                "content_sha256": expected_hash,
                "policy_version": POLICY_VERSION,
                "created_at": row["valid_from"],
                "created_by": "synthetic-fixture-loader",
            }
        )
    return prepared


def _approval_rows() -> list[dict[str, Any]]:
    rows = _document(APPROVAL_FIXTURE, "approvals")
    return [
        {
            "id": row["approval_id"],
            "tenant_id": row["tenant_id"],
            "program_id": row["program_id"],
            "source_memory_id": row["source_memory_id"],
            "derivative_memory_id": row["derivative_memory_id"],
            "decision": "approved",
            "reviewed_by": row["reviewer"]["reviewer_handle"],
            "reviewed_at": row["approved_at"],
            "reason_code": "SYNTHETIC_HUMAN_APPROVAL",
            "source_sha256": row["source_content_sha256"],
            "derivative_sha256": row["derivative_content_sha256"],
            "purpose_scopes": row["purpose_scopes"],
            "audience_scopes": row["audience_scopes"],
            "expires_at": row["expires_at"],
            "policy_version": POLICY_VERSION,
            "created_at": row["approved_at"],
        }
        for row in rows
    ]


def _instant(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise TypeError("fixture timestamp has an unexpected type")
    return parsed.astimezone(UTC).isoformat()


def _memory_fingerprint(row: dict[str, Any]) -> tuple[object, ...]:
    return (
        str(row["id"]),
        str(row["tenant_id"]),
        str(row["program_id"]),
        row["room"],
        row["content"],
        tuple(row["sensitivity"]),
        tuple(row["purpose_scopes"]),
        tuple(row["audience_scopes"]),
        str(row["source_memory_id"]) if row["source_memory_id"] else None,
        row["state"],
        _instant(row["valid_from"]),
        _instant(row["expires_at"]),
        _instant(row["revoked_at"]),
        row["content_sha256"],
        row["policy_version"],
        _instant(row["created_at"]),
        row["created_by"],
    )


def _approval_fingerprint(row: dict[str, Any]) -> tuple[object, ...]:
    return (
        str(row["id"]),
        str(row["tenant_id"]),
        str(row["program_id"]),
        str(row["source_memory_id"]),
        str(row["derivative_memory_id"]),
        row["decision"],
        row["reviewed_by"],
        _instant(row["reviewed_at"]),
        row["reason_code"],
        row["source_sha256"],
        row["derivative_sha256"],
        tuple(row["purpose_scopes"]),
        tuple(row["audience_scopes"]),
        _instant(row["expires_at"]),
        row["policy_version"],
        _instant(row["created_at"]),
    )


def _expected_rows(
    rows: list[dict[str, Any]],
    fingerprint: Any,
    *,
    label: str,
) -> dict[str, tuple[object, ...]]:
    expected: dict[str, tuple[object, ...]] = {}
    for row in rows:
        row_id = str(row["id"])
        if row_id in expected:
            raise ValueError(f"duplicate synthetic {label} fixture id")
        expected[row_id] = fingerprint(row)
    return expected


def _selected_rows(
    connection: Connection,
    statement: Any,
    fixture_ids: tuple[str, ...],
    fingerprint: Any,
) -> dict[str, tuple[object, ...]]:
    rows = connection.execute(statement, {"fixture_ids": fixture_ids}).mappings().all()
    return {str(row["id"]): fingerprint(dict(row)) for row in rows}


def _verify_existing(
    existing: dict[str, tuple[object, ...]],
    expected: dict[str, tuple[object, ...]],
    *,
    label: str,
) -> None:
    drifted = {
        row_id
        for row_id, fingerprint in existing.items()
        if expected.get(row_id) != fingerprint
    }
    if drifted:
        raise RuntimeError(f"live synthetic {label} fixture rows differ from source")


def _load(connection: Connection) -> tuple[int, int]:
    memory_rows = _memory_rows()
    approval_rows = _approval_rows()
    expected_memory = _expected_rows(memory_rows, _memory_fingerprint, label="memory")
    expected_approvals = _expected_rows(
        approval_rows, _approval_fingerprint, label="approval"
    )
    memory_ids = tuple(expected_memory)
    approval_ids = tuple(expected_approvals)

    existing_memory = _selected_rows(
        connection,
        MEMORY_SELECT,
        memory_ids,
        _memory_fingerprint,
    )
    existing_approvals = _selected_rows(
        connection,
        APPROVAL_SELECT,
        approval_ids,
        _approval_fingerprint,
    )
    _verify_existing(existing_memory, expected_memory, label="memory")
    _verify_existing(existing_approvals, expected_approvals, label="approval")

    for row in memory_rows:
        if str(row["id"]) not in existing_memory:
            connection.execute(MEMORY_INSERT, row)
    for row in approval_rows:
        if str(row["id"]) not in existing_approvals:
            connection.execute(APPROVAL_INSERT, row)

    verified_memory = _selected_rows(
        connection,
        MEMORY_SELECT,
        memory_ids,
        _memory_fingerprint,
    )
    verified_approvals = _selected_rows(
        connection,
        APPROVAL_SELECT,
        approval_ids,
        _approval_fingerprint,
    )
    if verified_memory != expected_memory or verified_approvals != expected_approvals:
        raise RuntimeError("live synthetic fixture rows failed post-load verification")
    return len(expected_memory), len(expected_approvals)


def main() -> None:
    raw_url = os.environ.get("DATABASE_URL")
    if not raw_url:
        raise SystemExit("DATABASE_URL is required")
    url = cockroach_url(
        raw_url,
        database_name=os.environ.get("GLUEVENIR_DATABASE"),
    )
    engine = create_engine(url, poolclass=NullPool)
    try:
        memory_count, approval_count = run_transaction(
            engine,
            _load,
            max_retries=3,
            max_backoff=1,
        )
    finally:
        engine.dispose()
    print(
        "synthetic fixtures verified: "
        f"{memory_count} memories, {approval_count} approvals"
    )


if __name__ == "__main__":
    main()
