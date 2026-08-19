"""Deterministic bootstrap for Gluevenir's development-only Compose modes."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.pool import NullPool
from sqlalchemy_cockroachdb.transaction import run_transaction

from gluevenir._bedrock import _TitanTextEmbeddingsV2
from gluevenir._database import cockroach_url
from gluevenir._local_server import (
    _bedrock_client_from_file,
    _database_url,
    _ensure_private_key,
    _read_secret_file,
)
from gluevenir._memory_store import _VERIFY_RUNTIME_PRINCIPAL

_PROJECT_TABLES = frozenset(
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
_EXPECTED_REVISION = "0003_pending_memory_actions"
_LOCAL_ADMIN_URL = "postgresql://root@cockroach:26257/defaultdb?sslmode=disable"
_LOCAL_RUNTIME_URL = (
    "postgresql://gluevenir_runtime@cockroach:26257/gluevenir?sslmode=disable"
)


def _engine(url: URL | str) -> Engine:
    return create_engine(url, poolclass=NullPool, hide_parameters=True)


def _create_local_database(admin_url: str = _LOCAL_ADMIN_URL) -> None:
    url = cockroach_url(admin_url)
    if (
        url.username != "root"
        or url.host != "cockroach"
        or url.port != 26257
        or url.database != "defaultdb"
        or url.password is not None
        or dict(url.query) != {"sslmode": "disable"}
    ):
        raise ValueError("local administrator database URL is invalid")
    engine = _engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE DATABASE IF NOT EXISTS gluevenir"))
    finally:
        engine.dispose()


def _migration_state(engine: Engine) -> str:
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
        app_role = bool(
            connection.execute(
                text(
                    "SELECT count(*) FROM pg_catalog.pg_roles "
                    "WHERE rolname = 'gluevenir_app'"
                )
            ).scalar_one()
        )
    if tables <= {"alembic_version"} and revision is None and not app_role:
        return "clean"
    if (
        tables == _PROJECT_TABLES | {"alembic_version"}
        and revision == _EXPECTED_REVISION
        and app_role
    ):
        return "current"
    return "partial"


@contextmanager
def _migration_environment(url: str):
    previous_url = os.environ.get("DATABASE_URL")
    previous_database = os.environ.get("GLUEVENIR_DATABASE")
    os.environ["DATABASE_URL"] = url
    os.environ["GLUEVENIR_DATABASE"] = "gluevenir"
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


def _apply_migrations(admin_database_url: str) -> None:
    engine = _engine(cockroach_url(admin_database_url, database_name="gluevenir"))
    try:
        state = _migration_state(engine)
    finally:
        engine.dispose()
    if state == "partial":
        raise RuntimeError("local migration state is partial; refusing to continue")
    if state == "clean":
        with _migration_environment(admin_database_url):
            command.upgrade(Config("alembic.ini"), "head")
    verify = _engine(cockroach_url(admin_database_url, database_name="gluevenir"))
    try:
        if _migration_state(verify) != "current":
            raise RuntimeError("local migrations did not reach the expected revision")
    finally:
        verify.dispose()


def _load_and_embed_fixtures(
    admin_database_url: str,
    *,
    bedrock_token_path: Path,
    region: str,
) -> tuple[int, int, int]:
    from scripts.embed_synthetic_fixtures import populate_missing_embeddings
    from scripts.load_synthetic_fixtures import _load

    engine = _engine(cockroach_url(admin_database_url, database_name="gluevenir"))
    try:
        memories, approvals = run_transaction(
            engine,
            _load,
            max_retries=3,
            max_backoff=1,
        )
        embedded = populate_missing_embeddings(
            engine,
            _TitanTextEmbeddingsV2(
                _bedrock_client_from_file(bedrock_token_path, region=region)
            ),
        )
    finally:
        engine.dispose()
    return memories, approvals, embedded


def _provision_runtime_principal(admin_database_url: str) -> None:
    engine = _engine(cockroach_url(admin_database_url, database_name="gluevenir"))

    def provision(connection: Connection) -> None:
        statements = (
            "CREATE USER IF NOT EXISTS gluevenir_runtime",
            "ALTER ROLE gluevenir_runtime NOBYPASSRLS",
            "REVOKE admin FROM gluevenir_runtime",
            "GRANT gluevenir_app TO gluevenir_runtime",
            "REVOKE CREATE ON DATABASE gluevenir FROM PUBLIC",
            "REVOKE CREATE ON DATABASE gluevenir FROM gluevenir_runtime",
            "REVOKE CREATE ON SCHEMA public FROM gluevenir_runtime",
        )
        for statement in statements:
            connection.execute(text(statement))

    try:
        run_transaction(engine, provision, max_retries=3, max_backoff=1)
    finally:
        engine.dispose()


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
            rls = {
                str(row[0]): (bool(row[1]), bool(row[2]))
                for row in connection.execute(
                    text(
                        "SELECT relname, relrowsecurity, relforcerowsecurity "
                        "FROM pg_catalog.pg_class "
                        "WHERE relname IN ("
                        "'memory_records','derivative_approvals','session_context',"
                        "'recall_receipts','receipt_memory_links','policy_events',"
                        "'pending_memory_actions')"
                    )
                )
            }
        incorrect_rls = any(value != (True, True) for value in rls.values())
        if set(rls) != _PROJECT_TABLES or incorrect_rls:
            raise PermissionError("required row-level security is not forced")
        if _migration_state(engine) != "current":
            raise RuntimeError("runtime database migration state is not current")
    finally:
        engine.dispose()


def _owner(value: str) -> tuple[int, int]:
    try:
        user, group = (int(part) for part in value.split(":"))
    except (TypeError, ValueError):
        raise ValueError("signing-key owner must be numeric user:group") from None
    if user < 1 or group < 1:
        raise ValueError("signing-key owner must be numeric user:group")
    return user, group


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("local", "hybrid"), required=True)
    args = parser.parse_args(argv)
    token_path = Path(
        os.environ.get(
            "GLUEVENIR_BEDROCK_TOKEN_FILE",
            "/run/secrets/bedrock_api_key",
        )
    )
    signing_path = Path(
        os.environ.get(
            "GLUEVENIR_SIGNING_KEY_FILE",
            "/run/gluevenir-signing/receipt-ed25519.key",
        )
    )
    owner = _owner(os.environ.get("GLUEVENIR_SIGNING_KEY_OWNER", "10001:10001"))
    region = os.environ.get("AWS_REGION", "us-east-1")
    _ensure_private_key(signing_path, owner=owner)
    if args.mode == "local":
        _read_secret_file(token_path, label="Bedrock API key")
        _create_local_database()
        admin_database_url = _LOCAL_ADMIN_URL
        _apply_migrations(admin_database_url)
        memories, approvals, embedded = _load_and_embed_fixtures(
            admin_database_url,
            bedrock_token_path=token_path,
            region=region,
        )
        _provision_runtime_principal(admin_database_url)
        _verify_runtime_boundary(_database_url(_LOCAL_RUNTIME_URL, mode="local"))
        print(
            "local database verified: "
            f"{memories} synthetic memories, {approvals} approvals, "
            f"{embedded} new embeddings"
        )
        return
    raw_url = _read_secret_file(
        Path(os.environ.get("GLUEVENIR_DATABASE_URL_FILE", "")),
        label="database URL",
    )
    _verify_runtime_boundary(_database_url(raw_url, mode="hybrid"))
    print("hybrid runtime boundary verified")


if __name__ == "__main__":
    main()
