"""Verify the H6 CockroachDB schema, RLS, fixtures, and context safety live."""

from __future__ import annotations

import os

from sqlalchemy import Connection, create_engine, text
from sqlalchemy.exc import DatabaseError

from gluevenir._database import cockroach_url

TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "22222222-2222-4222-8222-222222222222"
PROBE_ID = "90000000-0000-4000-8000-000000000001"
TENANT_TABLES = (
    "memory_records",
    "derivative_approvals",
    "recall_receipts",
    "receipt_memory_links",
    "policy_events",
    "session_context",
    "pending_memory_actions",
)


class LiveVerificationError(RuntimeError):
    """A content-free live boundary verification failure."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LiveVerificationError(message)


def _set_app_context(connection: Connection, tenant_id: str) -> None:
    connection.execute(text("SET LOCAL ROLE gluevenir_app"))
    connection.execute(
        text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )


def _verify_catalog(connection: Connection) -> None:
    revision = connection.execute(
        text("SELECT version_num FROM alembic_version")
    ).scalar_one()
    _require(
        revision == "0003_pending_memory_actions", "schema revision is not current"
    )

    role = connection.execute(
        text(
            "SELECT rolcanlogin, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname = 'gluevenir_app'"
        )
    ).one()
    _require(tuple(role) == (False, False), "application role boundary is invalid")

    schema_privileges = connection.execute(
        text(
            "SELECT "
            "has_schema_privilege('gluevenir_app', 'public', 'USAGE'), "
            "has_schema_privilege('gluevenir_app', 'public', 'CREATE')"
        )
    ).one()
    _require(
        tuple(schema_privileges) == (True, False),
        "application schema privileges are invalid",
    )

    grants = set(
        connection.execute(
            text(
                "SELECT table_name, privilege_type "
                "FROM information_schema.role_table_grants "
                "WHERE grantee = 'gluevenir_app'"
            )
        ).all()
    )
    expected_grants = {
        (table, privilege)
        for table in TENANT_TABLES
        if table != "pending_memory_actions"
        for privilege in {"SELECT", "INSERT", "UPDATE", "DELETE"}
    }
    expected_grants.update(
        ("pending_memory_actions", privilege)
        for privilege in {"SELECT", "INSERT", "UPDATE"}
    )
    _require(grants == expected_grants, "application table grants are not exact")

    owners = dict(
        connection.execute(
            text(
                "SELECT tablename, tableowner FROM pg_catalog.pg_tables "
                "WHERE schemaname = 'public'"
            )
        ).all()
    )
    for table in TENANT_TABLES:
        _require(
            owners.get(table) not in {None, "gluevenir_app"},
            "tenant table ownership boundary is invalid",
        )

    for table in TENANT_TABLES:
        ddl = connection.exec_driver_sql(f"SHOW CREATE TABLE {table}").one()[-1]
        _require(
            "ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY" in ddl,
            "forced row-level security is missing",
        )
        _require(
            f"CREATE POLICY {table}_tenant_isolation" in ddl,
            "tenant isolation policy is missing",
        )
        _require("TO gluevenir_app" in ddl, "tenant policy role is invalid")
        tenant_expression = (
            "USING (tenant_id = current_setting('app.current_tenant':::STRING)::UUID) "
            "WITH CHECK "
            "(tenant_id = current_setting('app.current_tenant':::STRING)::UUID)"
        )
        _require(tenant_expression in ddl, "tenant policy expression is invalid")

    memory_ddl = connection.exec_driver_sql("SHOW CREATE TABLE memory_records").one()[
        -1
    ]
    _require("embedding VECTOR(256)" in memory_ddl, "vector column is invalid")
    _require(
        (
            "VECTOR INDEX memory_recall_idx "
            "(tenant_id, program_id, embedding vector_cosine_ops)"
        )
        in memory_ddl,
        "scoped vector index is invalid",
    )

    approvals_ddl = connection.exec_driver_sql(
        "SHOW CREATE TABLE derivative_approvals"
    ).one()[-1]
    for approved_scope in (
        "purpose_scopes STRING[] NOT NULL",
        "audience_scopes STRING[] NOT NULL",
        "expires_at TIMESTAMPTZ NOT NULL",
        "CONSTRAINT derivative_approvals_expiry_check CHECK",
    ):
        _require(approved_scope in approvals_ddl, "approval scope schema is invalid")


def _verify_reads(engine) -> None:
    expected = ((TENANT_A, 8), (TENANT_B, 1))
    for tenant_id, own_count in expected:
        with engine.connect() as connection, connection.begin():
            _set_app_context(connection, tenant_id)
            visible = connection.execute(
                text("SELECT count(*) FROM memory_records")
            ).scalar_one()
            cross_tenant = TENANT_B if tenant_id == TENANT_A else TENANT_A
            cross_count = connection.execute(
                text(
                    "SELECT count(*) FROM memory_records "
                    "WHERE tenant_id = CAST(:tenant_id AS UUID)"
                ),
                {"tenant_id": cross_tenant},
            ).scalar_one()
            _require(visible == own_count, "tenant-visible fixture count is invalid")
            _require(cross_count == 0, "cross-tenant read boundary failed")


def _verify_context_reset(engine) -> None:
    with engine.connect() as connection:
        transaction = connection.begin()
        _set_app_context(connection, TENANT_A)
        _require(
            connection.execute(
                text("SELECT current_setting('app.current_tenant')")
            ).scalar_one()
            == TENANT_A,
            "transaction tenant context was not set",
        )
        transaction.rollback()
        _require(
            connection.execute(
                text("SELECT current_setting('app.current_tenant', true)")
            ).scalar_one()
            != TENANT_A,
            "transaction tenant context did not reset",
        )
        _require(
            connection.execute(text("SELECT current_user")).scalar_one()
            != "gluevenir_app",
            "transaction role did not reset",
        )

    with engine.connect() as connection:
        transaction = connection.begin()
        connection.execute(text("SET LOCAL ROLE gluevenir_app"))
        try:
            connection.execute(text("SELECT count(*) FROM memory_records")).scalar_one()
        except DatabaseError:
            pass
        else:
            raise LiveVerificationError("missing tenant context did not fail closed")
        finally:
            transaction.rollback()


def _verify_cross_tenant_write_denied(engine) -> None:
    insert_probe = text(
        """
        INSERT INTO memory_records (
            id, tenant_id, program_id, room, content, sensitivity,
            purpose_scopes, audience_scopes, state, valid_from,
            content_sha256, policy_version, created_by
        ) VALUES (
            :id, CAST(:tenant_id AS UUID),
            'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
            'research-confidential', 'SYNTHETIC DATA: denied RLS probe',
            ARRAY['IP_CONFIDENTIAL'], ARRAY['research_review'],
            ARRAY['internal-research'], 'active', current_timestamp(),
            '0000000000000000000000000000000000000000000000000000000000000000',
            'bio-demo-v1', 'live-verifier'
        )
        """
    )
    with engine.connect() as connection:
        transaction = connection.begin()
        _set_app_context(connection, TENANT_A)
        try:
            connection.execute(insert_probe, {"id": PROBE_ID, "tenant_id": TENANT_B})
        except DatabaseError as error:
            _require(
                getattr(error.orig, "sqlstate", None) == "42501",
                "cross-tenant write failed for an unexpected reason",
            )
        else:
            raise LiveVerificationError("cross-tenant write unexpectedly passed RLS")
        finally:
            transaction.rollback()

    with engine.connect() as connection:
        remaining = connection.execute(
            text("SELECT count(*) FROM memory_records WHERE id = CAST(:id AS UUID)"),
            {"id": PROBE_ID},
        ).scalar_one()
        _require(remaining == 0, "cross-tenant write probe was not rolled back")


def main() -> None:
    raw_url = os.environ.get("DATABASE_URL")
    if not raw_url:
        raise SystemExit("DATABASE_URL is required")
    engine = create_engine(
        cockroach_url(
            raw_url,
            database_name=os.environ.get("GLUEVENIR_DATABASE"),
        ),
        pool_size=1,
        max_overflow=0,
    )
    try:
        with engine.connect() as connection:
            _verify_catalog(connection)
        _verify_reads(engine)
        _verify_context_reset(engine)
        _verify_cross_tenant_write_denied(engine)
    finally:
        engine.dispose()
    print("live memory core verified: Alembic, vector index, forced RLS, fixtures")


if __name__ == "__main__":
    main()
