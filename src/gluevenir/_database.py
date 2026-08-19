"""Private CockroachDB connection helpers shared by runtime and migrations."""

from __future__ import annotations

from sqlalchemy.engine import URL, make_url


def cockroach_url(raw_url: str, *, database_name: str | None = None) -> URL:
    """Normalize an environment DSN for CockroachDB's Psycopg 3 dialect."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("database URL must be a non-empty string")

    url = make_url(raw_url)
    if database_name:
        url = url.set(database=database_name)
    if url.drivername in {"postgres", "postgresql", "cockroachdb"}:
        url = url.set(drivername="cockroachdb+psycopg")
    if url.drivername != "cockroachdb+psycopg":
        raise ValueError("database URL must use CockroachDB with Psycopg 3")
    if not url.database:
        raise ValueError("database URL must name a database")
    return url
