"""Read-only preflight for the non-transactional initial Cockroach migration."""

from __future__ import annotations

import argparse
import os
from collections.abc import Collection

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from gluevenir._database import cockroach_url

REVISION = "0003_pending_memory_actions"
PROJECT_TABLES = frozenset(
    {
        "memory_records",
        "derivative_approvals",
        "session_context",
        "recall_receipts",
        "receipt_memory_links",
        "policy_events",
        "pending_memory_actions",
    }
)


def classify_migration_state(
    tables: Collection[str],
    *,
    revision: str | None,
    role_exists: bool,
) -> str:
    """Classify only exact clean/current states; everything else is partial."""
    table_set = set(tables)
    if table_set <= {"alembic_version"} and revision is None and not role_exists:
        return "clean"
    if (
        table_set == PROJECT_TABLES | {"alembic_version"}
        and revision == REVISION
        and role_exists
    ):
        return "current"
    return "partial"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", choices=("clean", "current"), required=True)
    expected = parser.parse_args().expect
    raw_url = os.environ.get("DATABASE_URL")
    if not raw_url:
        raise SystemExit("DATABASE_URL is required")
    engine = create_engine(
        cockroach_url(
            raw_url,
            database_name=os.environ.get("GLUEVENIR_DATABASE"),
        ),
        poolclass=NullPool,
    )
    try:
        with engine.connect() as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
                    )
                )
            }
            revision = (
                connection.execute(text("SELECT version_num FROM alembic_version"))
                .scalars()
                .one_or_none()
                if "alembic_version" in tables
                else None
            )
            role_exists = bool(
                connection.execute(
                    text(
                        "SELECT count(*) FROM pg_catalog.pg_roles "
                        "WHERE rolname = 'gluevenir_app'"
                    )
                ).scalar_one()
            )
    finally:
        engine.dispose()

    state = classify_migration_state(
        tables,
        revision=revision,
        role_exists=role_exists,
    )
    if state != expected:
        raise SystemExit(
            f"migration preflight expected {expected} but found {state}; "
            "do not run migrations over a partial state"
        )
    print(f"migration state verified: {state}")


if __name__ == "__main__":
    main()
