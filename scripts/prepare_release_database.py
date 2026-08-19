"""Prepare, but never select, a dedicated Wave E release database.

This command is intentionally not a database creator or cutover tool.  It accepts
two credential files for one explicitly acknowledged, versioned database, applies
the checked-in Alembic history only from an exact clean state, loads the exact
synthetic fixture set, refreshes active embeddings outside retry callbacks, and
verifies the non-owner runtime boundary.  It never drops, recreates, renames, or
selects a database and never mutates AWS secrets.
"""

from __future__ import annotations

import argparse
import os
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DatabaseError
from sqlalchemy.pool import NullPool
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._bedrock import _TitanTextEmbeddingsV2
from gluevenir._database import cockroach_url
from gluevenir._memory_store import _VERIFY_RUNTIME_PRINCIPAL
from scripts.check_live_migration_state import (
    PROJECT_TABLES,
    classify_migration_state,
)

_RELEASE_DATABASE = re.compile(r"gluevenir_release_[0-9]{8}_[a-z0-9]{4,24}\Z")
_FORBIDDEN_DATABASES = frozenset(
    {
        "defaultdb",
        "postgres",
        "system",
        "template0",
        "template1",
        "gluevenir",
    }
)
_EXPECTED_MEMORIES = 30
_EXPECTED_APPROVALS = 3
_EMPTY_OPERATIONAL_TABLES = PROJECT_TABLES - {
    "memory_records",
    "derivative_approvals",
}
_PLAN = (
    "validate an explicitly acknowledged versioned target",
    "classify the exact Alembic state as clean, current, or partial",
    "apply checked-in migrations only from an exact clean state",
    "bind and harden the reviewed non-owner runtime principal",
    "load the exact retry-safe synthetic fixture set",
    "regenerate exact active embeddings outside database transactions",
    "verify exact fixture counts, embeddings, catalog, and forced RLS",
    "verify the bounded non-owner runtime principal",
    "stop without selecting the database or changing a secret",
)


class _Embedder(Protocol):
    def embed(self, value: str) -> tuple[float, ...]: ...


class PreparationError(RuntimeError):
    """A deliberately content-free release preparation failure."""


@dataclass(frozen=True, slots=True, repr=False)
class ReleaseTarget:
    database_name: str
    admin_url: URL
    runtime_url: URL


@dataclass(frozen=True, slots=True)
class VerificationSummary:
    memories: int
    approvals: int
    embedded_active_memories: int
    runtime_principal_verified: bool


@dataclass(frozen=True, slots=True)
class PreparationResult:
    initial_state: str
    migrated: bool
    memories: int
    approvals: int
    embeddings_populated: int
    verified: bool


@dataclass(frozen=True, slots=True, repr=False)
class PreparationOperations:
    inspect: Callable[[ReleaseTarget], str]
    migrate: Callable[[ReleaseTarget], None]
    bind_runtime: Callable[[ReleaseTarget], None]
    load: Callable[[ReleaseTarget], tuple[int, int]]
    embed: Callable[[ReleaseTarget, _Embedder], int]
    verify: Callable[[ReleaseTarget], VerificationSummary]


def plan_release_database() -> tuple[str, ...]:
    """Return the mutation-free preparation plan."""

    return _PLAN


def validate_target(
    admin_url: str,
    runtime_url: str,
    *,
    acknowledged_database: str,
) -> ReleaseTarget:
    """Bind two credentials to one exact, reviewed versioned database."""

    try:
        admin = cockroach_url(admin_url)
        runtime = cockroach_url(runtime_url)
    except (TypeError, ValueError):
        raise PreparationError("target database URLs are invalid") from None

    database_name = admin.database or ""
    if (
        database_name in _FORBIDDEN_DATABASES
        or _RELEASE_DATABASE.fullmatch(database_name) is None
        or acknowledged_database != database_name
    ):
        raise PreparationError("target database name is not explicitly reviewed")
    if runtime.database != database_name:
        raise PreparationError("target credentials name different databases")
    if (admin.host, admin.port) != (runtime.host, runtime.port):
        raise PreparationError("target credentials name different clusters")
    if (
        not admin.host
        or not admin.username
        or not admin.password
        or not runtime.username
        or not runtime.password
    ):
        raise PreparationError("target database identity is incomplete")
    if any(dict(url.query).get("sslmode") != "verify-full" for url in (admin, runtime)):
        raise PreparationError("release database credentials require verified TLS")
    if admin.username == runtime.username:
        raise PreparationError("migration and runtime principals must differ")
    if runtime.username != "gluevenir_runtime":
        raise PreparationError("runtime credential is not the reviewed principal")
    return ReleaseTarget(database_name, admin, runtime)


def prepare_release_database(
    target: ReleaseTarget,
    embedder: _Embedder,
    *,
    operations: PreparationOperations | None = None,
) -> PreparationResult:
    """Prepare and verify a target, stopping before any cutover operation."""

    selected = operations or production_operations()
    initial_state = _stage("migration preflight", lambda: selected.inspect(target))
    if initial_state not in {"clean", "current"}:
        raise PreparationError("migration preflight rejected a partial state")

    migrated = False
    if initial_state == "clean":
        _stage("migration", lambda: selected.migrate(target))
        migrated = True
        state_after_migration = _stage(
            "migration verification", lambda: selected.inspect(target)
        )
        if state_after_migration != "current":
            raise PreparationError("migration did not reach the current revision")

    _stage("runtime principal binding", lambda: selected.bind_runtime(target))
    memories, approvals = _stage("fixture loading", lambda: selected.load(target))
    if (memories, approvals) != (_EXPECTED_MEMORIES, _EXPECTED_APPROVALS):
        raise PreparationError("fixture loading returned unexpected counts")

    populated = _stage("embedding refresh", lambda: selected.embed(target, embedder))
    if type(populated) is not int or populated != _active_count():
        raise PreparationError("embedding refresh returned an invalid count")

    verification = _stage("release verification", lambda: selected.verify(target))
    if verification != VerificationSummary(memories, approvals, _active_count(), True):
        raise PreparationError("release database verification did not match fixtures")
    return PreparationResult(
        initial_state=initial_state,
        migrated=migrated,
        memories=memories,
        approvals=approvals,
        embeddings_populated=populated,
        verified=True,
    )


def production_operations() -> PreparationOperations:
    return PreparationOperations(
        inspect=_inspect_migration_state,
        migrate=_apply_migrations,
        bind_runtime=_bind_runtime_principal,
        load=_load_fixtures,
        embed=_embed_fixtures,
        verify=_verify_release_database,
    )


def _stage(label: str, action: Callable[[], Any]) -> Any:
    try:
        return action()
    except PreparationError:
        raise
    except Exception:
        raise PreparationError(f"{label} failed") from None


def _engine(url: URL) -> Engine:
    return create_engine(url, poolclass=NullPool, hide_parameters=True)


def _inspect_migration_state(target: ReleaseTarget) -> str:
    engine = _engine(target.admin_url)
    try:
        with engine.connect() as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public' "
                        "AND table_type = 'BASE TABLE'"
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
    return classify_migration_state(
        tables,
        revision=revision,
        role_exists=role_exists,
    )


@contextmanager
def _migration_environment(target: ReleaseTarget):
    previous_url = os.environ.get("DATABASE_URL")
    previous_database = os.environ.get("GLUEVENIR_DATABASE")
    os.environ["DATABASE_URL"] = target.admin_url.render_as_string(hide_password=False)
    os.environ["GLUEVENIR_DATABASE"] = target.database_name
    try:
        yield
    finally:
        if previous_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_url
        if previous_database is None:
            os.environ.pop("GLUEVENIR_DATABASE", None)
        else:
            os.environ["GLUEVENIR_DATABASE"] = previous_database


def _apply_migrations(target: ReleaseTarget) -> None:
    with _migration_environment(target):
        command.upgrade(Config("alembic.ini"), "head")


def _bind_runtime_principal(target: ReleaseTarget) -> None:
    engine = _engine(target.admin_url)

    def bind(connection: Connection) -> None:
        statements = (
            "ALTER ROLE gluevenir_runtime NOBYPASSRLS",
            "REVOKE admin FROM gluevenir_runtime",
            "GRANT gluevenir_app TO gluevenir_runtime",
            f"REVOKE CREATE ON DATABASE {target.database_name} FROM PUBLIC",
            f"REVOKE CREATE ON DATABASE {target.database_name} FROM gluevenir_runtime",
            "REVOKE CREATE ON SCHEMA public FROM gluevenir_runtime",
        )
        for statement in statements:
            connection.exec_driver_sql(statement)

    try:
        # CockroachDB role DDL invalidates the ``cockroach_restart`` savepoint
        # used by sqlalchemy-cockroachdb's retry helper.  These statements are
        # idempotent privilege declarations, so execute them atomically in one
        # ordinary transaction and reserve the retry helper for data writes.
        with engine.begin() as connection:
            bind(connection)
    finally:
        engine.dispose()


def _table_counts(connection: Connection) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in sorted(PROJECT_TABLES):
        counts[table] = int(
            connection.exec_driver_sql(f"SELECT count(*) FROM {table}").scalar_one()
        )
    return counts


def _load_fixtures(target: ReleaseTarget) -> tuple[int, int]:
    from scripts.load_synthetic_fixtures import _load

    engine = _engine(target.admin_url)

    def load_if_dedicated(connection: Connection) -> tuple[int, int]:
        before = _table_counts(connection)
        pair = (before["memory_records"], before["derivative_approvals"])
        if pair not in {(0, 0), (_EXPECTED_MEMORIES, _EXPECTED_APPROVALS)}:
            raise RuntimeError("dedicated fixture state is neither empty nor current")
        if any(before[table] for table in _EMPTY_OPERATIONAL_TABLES):
            raise RuntimeError("dedicated release database has operational data")
        result = _load(connection)
        after = _table_counts(connection)
        if (after["memory_records"], after["derivative_approvals"]) != (
            _EXPECTED_MEMORIES,
            _EXPECTED_APPROVALS,
        ) or any(after[table] for table in _EMPTY_OPERATIONAL_TABLES):
            raise RuntimeError("dedicated fixture state is not exact")
        return result

    try:
        return run_transaction(
            engine,
            load_if_dedicated,
            max_retries=3,
            max_backoff=1,
        )
    finally:
        engine.dispose()


def _embed_fixtures(target: ReleaseTarget, embedder: _Embedder) -> int:
    from scripts.embed_synthetic_fixtures import populate_missing_embeddings

    engine = _engine(target.admin_url)
    try:
        return populate_missing_embeddings(
            engine,
            embedder,
            refresh_existing=True,
        )
    finally:
        engine.dispose()


def _active_tenants() -> Mapping[str, int]:
    from scripts.load_synthetic_fixtures import _memory_rows

    return Counter(str(row["tenant_id"]) for row in _memory_rows())


def _active_count() -> int:
    from scripts.load_synthetic_fixtures import _memory_rows

    return sum(
        row["state"] == "active" and isinstance(row["content"], str)
        for row in _memory_rows()
    )


def _verify_release_database(target: ReleaseTarget) -> VerificationSummary:
    from scripts.verify_live_memory_core import _verify_catalog

    admin_engine = _engine(target.admin_url)
    try:
        with admin_engine.connect() as connection:
            _verify_catalog(connection)
            counts = _table_counts(connection)
            embedded_active = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM memory_records "
                        "WHERE state = 'active' AND content IS NOT NULL "
                        "AND embedding IS NOT NULL"
                    )
                ).scalar_one()
            )
            missing_active = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM memory_records "
                        "WHERE state = 'active' AND content IS NOT NULL "
                        "AND embedding IS NULL"
                    )
                ).scalar_one()
            )
        if (
            counts["memory_records"] != _EXPECTED_MEMORIES
            or counts["derivative_approvals"] != _EXPECTED_APPROVALS
            or any(counts[table] for table in _EMPTY_OPERATIONAL_TABLES)
            or embedded_active != _active_count()
            or missing_active != 0
        ):
            raise RuntimeError("release database contents are not exact")
    finally:
        admin_engine.dispose()

    _verify_runtime_boundary(target.runtime_url)
    return VerificationSummary(
        _EXPECTED_MEMORIES,
        _EXPECTED_APPROVALS,
        embedded_active,
        True,
    )


def _verify_runtime_boundary(runtime_url: URL) -> None:
    engine = _engine(runtime_url)
    try:
        with engine.connect() as connection:
            principal = connection.execute(_VERIFY_RUNTIME_PRINCIPAL).mappings().one()
            if (
                principal.get("principal") != "gluevenir_runtime"
                or principal.get("bypasses_rls") is not False
                or principal.get("is_app_member") is not True
                or principal.get("can_create_schema_objects") is not False
                or principal.get("can_create_schemas") is not False
            ):
                raise PermissionError("database principal is not the bounded app role")

        for tenant_id, expected in _active_tenants().items():
            with engine.connect() as connection, connection.begin():
                connection.execute(
                    text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
                    {"tenant_id": tenant_id},
                )
                visible = int(
                    connection.execute(
                        text("SELECT count(*) FROM memory_records")
                    ).scalar_one()
                )
                if visible != expected:
                    raise PermissionError("runtime tenant visibility is not exact")

        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(text("SELECT count(*) FROM memory_records"))
            except DatabaseError:
                pass
            else:
                raise PermissionError("missing tenant context did not fail closed")
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def _read_secret_file(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        raise PreparationError("credential file is unavailable") from None
    if not value or "\n" in value or len(value) > 8192:
        raise PreparationError("credential file has an invalid value")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare a dedicated release database without cutting over."
    )
    parser.add_argument("mode", choices=("plan", "prepare"))
    parser.add_argument("--admin-url-file", type=Path, required=True)
    parser.add_argument("--runtime-url-file", type=Path, required=True)
    parser.add_argument("--acknowledge-database", required=True)
    parser.add_argument("--aws-region", default="us-east-1")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        admin_url = _read_secret_file(args.admin_url_file)
        runtime_url = _read_secret_file(args.runtime_url_file)
        target = validate_target(
            admin_url,
            runtime_url,
            acknowledged_database=args.acknowledge_database,
        )
        if args.mode == "plan":
            print("release database plan (no network or mutation):")
            for index, step in enumerate(plan_release_database(), start=1):
                print(f"{index}. {step}")
            return

        import boto3

        client = _stage(
            "Bedrock client creation",
            lambda: boto3.client("bedrock-runtime", region_name=args.aws_region),
        )
        result = prepare_release_database(
            target,
            _TitanTextEmbeddingsV2(client),
        )
    except PreparationError as error:
        raise SystemExit(str(error)) from None
    print(
        "release database prepared and verified: "
        f"{result.memories} memories, {result.approvals} approvals, "
        f"{result.embeddings_populated} embeddings populated; no cutover performed"
    )


if __name__ == "__main__":
    main()
