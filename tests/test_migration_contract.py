from __future__ import annotations

import ast
import re
from pathlib import Path

REVISION_PATH = (
    Path(__file__).parents[1] / "migrations" / "versions" / "0001_memory_core.py"
)
TENANT_TABLES = (
    "memory_records",
    "derivative_approvals",
    "recall_receipts",
    "receipt_memory_links",
    "policy_events",
    "session_context",
)
TENANT_EXPRESSION = "tenant_id = current_setting('app.current_tenant')::uuid"


def _revision_source() -> str:
    return REVISION_PATH.read_text(encoding="utf-8")


def _revision_string(name: str) -> str:
    tree = ast.parse(_revision_source())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return value
    raise AssertionError(f"missing literal revision value: {name}")


def _normalized_revision_string(name: str) -> str:
    return re.sub(r"\s+", " ", _revision_string(name).lower())


def _sql() -> str:
    return _normalized_revision_string("UPGRADE_SQL")


def _table(sql: str, table: str) -> str:
    match = re.search(rf"create table {table} \((.*?)\);", sql)
    assert match is not None, f"missing CREATE TABLE for {table}"
    return match.group(1)


def _policy(sql: str, table: str) -> str:
    match = re.search(rf"create policy {table}_tenant_isolation on {table} (.*?);", sql)
    assert match is not None, f"missing tenant policy for {table}"
    return match.group(1)


def test_application_role_is_explicitly_non_bypass_and_non_owner() -> None:
    sql = _sql()
    assert "create role gluevenir_app" in sql
    assert "alter role gluevenir_app nobypassrls" in sql
    assert "alter table" in sql
    assert " owner to gluevenir_app" not in sql
    assert re.search(r"(?<!no)bypassrls", sql) is None


def test_revision_has_alembic_metadata_and_executes_each_statement() -> None:
    source = _revision_source()
    assert "from alembic import op" in source
    assert 'revision = "0001_memory_core"' in source
    assert "down_revision = None" in source
    assert "def upgrade() -> None:" in source
    assert "def downgrade() -> None:" in source
    assert source.count("op.execute(statement)") == 2


def test_all_tenant_tables_have_forced_rls_and_symmetric_tenant_policies() -> None:
    sql = _sql()
    for table in TENANT_TABLES:
        assert "tenant_id uuid not null" in _table(sql, table)
        assert f"alter table {table} enable row level security" in sql
        assert f"alter table {table} force row level security" in sql

        policy = _policy(sql, table)
        assert "for all to gluevenir_app" in policy
        assert f"using ({TENANT_EXPRESSION})" in policy
        assert f"with check ({TENANT_EXPRESSION})" in policy
        assert policy.count("current_setting('app.current_tenant')::uuid") == 2


def test_runtime_role_receives_only_table_dml_and_schema_usage() -> None:
    sql = _sql()
    for table in TENANT_TABLES:
        assert (
            f"grant select, insert, update, delete on table {table} to gluevenir_app"
        ) in sql
    assert "grant usage on schema public to gluevenir_app" in sql
    assert "revoke create on schema public from public" in sql
    assert "grant all" not in sql
    assert "grant create" not in sql


def test_vector_contract_is_created_before_any_fixture_can_be_loaded() -> None:
    sql = _sql()
    memory_table = _table(sql, "memory_records")
    assert "embedding vector(256) null" in memory_table
    expected_index = (
        "create vector index memory_recall_idx on memory_records "
        "(tenant_id, program_id, embedding vector_cosine_ops)"
    )
    assert expected_index in sql
    assert sql.index("create table memory_records") < sql.index(expected_index)
    assert " insert into " not in f" {sql} "


def test_schema_encodes_lifecycle_and_exact_decision_boundaries() -> None:
    sql = _sql()
    memories = _table(sql, "memory_records")
    receipts = _table(sql, "recall_receipts")
    approvals = _table(sql, "derivative_approvals")

    allowed_states = (
        "state in ('proposed', 'active', 'quarantined', 'revoked', 'forgotten')"
    )
    assert allowed_states in memories
    assert "state != 'forgotten' or (content is null and embedding is null)" in memories
    assert "state = 'forgotten' and content_sha256 is null" in memories
    assert "state != 'forgotten' and length(content_sha256) = 64" in memories
    assert "source_memory_id is null or room = 'external-approved'" in memories
    assert "decision in ('allow', 'deny', 'modify', 'step_up', 'defer')" in receipts
    assert "source_memory_id != derivative_memory_id" in approvals
    assert "reviewed_by is not null and reviewed_at is not null" in approvals


def test_content_safe_tables_store_hashes_not_raw_request_or_model_bodies() -> None:
    sql = _sql()
    receipts = _table(sql, "recall_receipts")
    events = _table(sql, "policy_events")
    sessions = _table(sql, "session_context")

    for required_hash in (
        "action_arguments_sha256",
        "raw_query_sha256",
        "model_prompt_sha256",
        "answer_sha256",
        "canonical_receipt_sha256",
    ):
        assert required_hash in receipts

    for table in (receipts, events, sessions):
        assert " raw_query string" not in table
        assert " model_prompt string" not in table
        assert " answer string" not in table
        assert " detector_match" not in table
        assert " tool_output" not in table

    assert "original_intent_sha256" in sessions
    assert "raw_original_request" not in sessions


def test_cross_table_links_bind_tenant_and_program() -> None:
    sql = _sql()
    receipts = _table(sql, "recall_receipts")
    links = _table(sql, "receipt_memory_links")
    events = _table(sql, "policy_events")

    assert (
        "foreign key (tenant_id, program_id, session_id) references "
        "session_context (tenant_id, program_id, session_id)"
    ) in receipts
    assert (
        "foreign key (tenant_id, program_id, resolution_of_receipt_id) "
        "references recall_receipts (tenant_id, program_id, id)"
    ) in receipts
    assert (
        "foreign key (tenant_id, program_id, approval_resolution_id) "
        "references derivative_approvals (tenant_id, program_id, id)"
    ) in receipts
    for table in (links, events):
        assert (
            "foreign key (tenant_id, program_id, receipt_id) references "
            "recall_receipts (tenant_id, program_id, id)"
        ) in table


def test_migration_does_not_use_rls_unsafe_conflict_suppression() -> None:
    sql = _sql()
    assert "on conflict do nothing" not in sql


def test_downgrade_removes_objects_in_dependency_safe_order() -> None:
    sql = _normalized_revision_string("DOWNGRADE_SQL")
    expected = (
        "drop table policy_events",
        "drop table receipt_memory_links",
        "drop table recall_receipts",
        "drop table session_context",
        "drop table derivative_approvals",
        "drop table memory_records",
        "revoke usage on schema public from gluevenir_app",
        "grant create on schema public to public",
        "drop role gluevenir_app",
    )
    positions = [sql.index(statement) for statement in expected]
    assert positions == sorted(positions)
