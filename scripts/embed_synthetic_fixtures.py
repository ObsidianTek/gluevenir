"""Populate or release-refresh Titan embeddings for exact synthetic fixtures."""

from __future__ import annotations

import hashlib
import json
import math
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import Connection, bindparam, create_engine, text
from sqlalchemy.pool import NullPool
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._bedrock import _TitanTextEmbeddingsV2
from gluevenir._database import cockroach_url

ROOT = Path(__file__).resolve().parents[1]
MEMORY_FIXTURE = ROOT / "fixtures" / "synthetic" / "memory_records.json"

_SELECT_FIXTURES = text(
    """
    SELECT id, tenant_id, program_id, content, content_sha256, state,
           embedding IS NOT NULL AS has_embedding
      FROM memory_records
     WHERE id IN :fixture_ids
    """
).bindparams(bindparam("fixture_ids", expanding=True))
_SET_EMBEDDING = text(
    """
    UPDATE memory_records
       SET embedding = CAST(:embedding AS VECTOR(256))
     WHERE id = :id
       AND tenant_id = :tenant_id
       AND program_id = :program_id
       AND state = 'active'
       AND content_sha256 = :content_sha256
    RETURNING id
    """
)


class _Embedder(Protocol):
    def embed(self, text: str) -> tuple[float, ...]: ...


@dataclass(frozen=True, slots=True, repr=False)
class _EmbeddingCandidate:
    memory_id: str
    tenant_id: str
    program_id: str
    content: str
    content_sha256: str


type _ReadResult = tuple[_EmbeddingCandidate, ...]
type _ReadRunner = Callable[..., _ReadResult]
type _WriteRunner = Callable[..., int]


def _fixture_rows() -> dict[str, dict[str, object]]:
    document = json.loads(MEMORY_FIXTURE.read_text(encoding="utf-8"))
    if document.get("synthetic_data") is not True:
        raise ValueError("memory fixture is not explicitly synthetic")
    rows = document.get("records")
    if not isinstance(rows, list) or not rows:
        raise ValueError("memory fixture has no records")
    expected: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("memory fixture row is invalid")
        memory_id = row.get("memory_id")
        if not isinstance(memory_id, str) or memory_id in expected:
            raise ValueError("memory fixture ID is invalid")
        content = row.get("content")
        content_hash = (
            hashlib.sha256(content.encode("utf-8")).hexdigest()
            if isinstance(content, str)
            else None
        )
        if row.get("content_sha256") != content_hash:
            raise ValueError("memory fixture content hash mismatch")
        expected[memory_id] = row
    return expected


def _selected_rows(
    connection: Connection, fixture_ids: tuple[str, ...]
) -> list[Mapping[str, Any]]:
    return (
        connection.execute(_SELECT_FIXTURES, {"fixture_ids": fixture_ids})
        .mappings()
        .all()
    )


def _verify_rows(
    rows: list[Mapping[str, Any]], expected: dict[str, dict[str, object]]
) -> dict[str, Mapping[str, Any]]:
    actual = {str(row["id"]): row for row in rows}
    if set(actual) != set(expected):
        raise RuntimeError("live synthetic memory fixtures are incomplete")
    for memory_id, fixture in expected.items():
        row = actual[memory_id]
        values = (
            str(row["tenant_id"]),
            str(row["program_id"]),
            row["content"],
            row["content_sha256"],
            row["state"],
        )
        source = (
            fixture["tenant_id"],
            fixture["program_id"],
            fixture["content"],
            fixture["content_sha256"],
            fixture["state"],
        )
        if values != source:
            raise RuntimeError("live synthetic memory fixtures differ from source")
    return actual


def _read_missing(
    engine: object,
    *,
    refresh_existing: bool = False,
    _transaction_runner: _ReadRunner = run_transaction,
) -> _ReadResult:
    expected = _fixture_rows()
    fixture_ids = tuple(expected)

    def read(connection: Connection) -> _ReadResult:
        actual = _verify_rows(_selected_rows(connection, fixture_ids), expected)
        return tuple(
            _EmbeddingCandidate(
                memory_id,
                str(row["tenant_id"]),
                str(row["program_id"]),
                row["content"],
                row["content_sha256"],
            )
            for memory_id, row in actual.items()
            if row["state"] == "active"
            and isinstance(row["content"], str)
            and (refresh_existing or row["has_embedding"] is False)
        )

    return _transaction_runner(engine, read, max_retries=3, max_backoff=1)


def _vector_json(vector: tuple[float, ...]) -> str:
    if not isinstance(vector, tuple) or len(vector) != 256:
        raise ValueError("embedding must contain exactly 256 values")
    if any(type(value) is not float or not math.isfinite(value) for value in vector):
        raise ValueError("embedding values must be finite floats")
    return json.dumps(vector, allow_nan=False, separators=(",", ":"))


def _write(
    engine: object,
    vectors: tuple[tuple[_EmbeddingCandidate, str], ...],
    *,
    _transaction_runner: _WriteRunner = run_transaction,
) -> int:
    expected = _fixture_rows()
    fixture_ids = tuple(expected)

    def write(connection: Connection) -> int:
        for candidate, vector in vectors:
            returned = (
                connection.execute(
                    _SET_EMBEDDING,
                    {
                        "id": candidate.memory_id,
                        "tenant_id": candidate.tenant_id,
                        "program_id": candidate.program_id,
                        "content_sha256": candidate.content_sha256,
                        "embedding": vector,
                    },
                )
                .mappings()
                .all()
            )
            if [str(row.get("id")) for row in returned] != [candidate.memory_id]:
                raise RuntimeError("synthetic fixture embedding update was rejected")
        actual = _verify_rows(_selected_rows(connection, fixture_ids), expected)
        missing = [
            memory_id
            for memory_id, row in actual.items()
            if row["state"] == "active"
            and isinstance(row["content"], str)
            and row["has_embedding"] is not True
        ]
        if missing:
            raise RuntimeError("synthetic fixture embeddings failed verification")
        return len(vectors)

    return _transaction_runner(engine, write, max_retries=3, max_backoff=1)


def populate_missing_embeddings(
    engine: object,
    embedder: _Embedder,
    *,
    refresh_existing: bool = False,
    _read_runner: _ReadRunner = run_transaction,
    _write_runner: _WriteRunner = run_transaction,
) -> int:
    """Embed outside transactions, then apply one short guarded write.

    Release preparation sets ``refresh_existing`` so every active vector is
    recomputed by the pinned embedder. Ordinary fixture loading remains an
    idempotent missing-only backfill.
    """

    missing = _read_missing(
        engine,
        refresh_existing=refresh_existing,
        _transaction_runner=_read_runner,
    )
    vectors = tuple(
        (candidate, _vector_json(embedder.embed(candidate.content)))
        for candidate in missing
    )
    return _write(engine, vectors, _transaction_runner=_write_runner)


def main() -> None:
    import boto3

    raw_url = os.environ.get("DATABASE_URL")
    if not raw_url:
        raise SystemExit("DATABASE_URL is required")
    engine = create_engine(
        cockroach_url(raw_url, database_name=os.environ.get("GLUEVENIR_DATABASE")),
        poolclass=NullPool,
        hide_parameters=True,
    )
    try:
        count = populate_missing_embeddings(
            engine,
            _TitanTextEmbeddingsV2(
                boto3.client(
                    "bedrock-runtime",
                    region_name=os.environ.get("AWS_REGION", "us-east-1"),
                )
            ),
        )
    finally:
        engine.dispose()
    print(f"synthetic fixture embeddings verified: {count} populated")


if __name__ == "__main__":
    main()
