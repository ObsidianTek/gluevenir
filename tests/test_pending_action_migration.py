from __future__ import annotations

import ast
import re
from pathlib import Path

REVISION_PATH = (
    Path(__file__).parents[1]
    / "migrations"
    / "versions"
    / "0003_pending_memory_actions.py"
)


def _literal(name: str) -> str:
    tree = ast.parse(REVISION_PATH.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return re.sub(r"\s+", " ", value.casefold()).strip()
    raise AssertionError(f"missing literal: {name}")


def test_pending_revision_is_single_chained_alembic_head() -> None:
    source = REVISION_PATH.read_text(encoding="utf-8")
    assert 'revision = "0003_pending_memory_actions"' in source
    assert 'down_revision = "0002_approval_scope_binding"' in source
    assert source.count("op.execute(statement)") == 2


def test_pending_table_is_content_safe_tenant_isolated_and_bounded() -> None:
    sql = _literal("UPGRADE_SQL")
    assert "create table pending_memory_actions" in sql
    for required in (
        "action_arguments_sha256 string not null",
        "original_intent_sha256 string not null",
        "prior_action_context_sha256 string not null",
        "pending_decision in ('step_up', 'defer')",
        "state in ('pending', 'consumed', 'denied', 'expired')",
        "foreign key (tenant_id, program_id, session_id)",
        "foreign key (tenant_id, program_id, evaluation_receipt_id)",
        "foreign key (tenant_id, program_id, transition_receipt_id)",
        "enable row level security",
        "force row level security",
        "for all to gluevenir_app",
        "grant select, insert, update on table pending_memory_actions",
    ):
        assert required in sql
    for forbidden in (
        "raw_query",
        "model_prompt",
        "answer string",
        "memory_content",
        "tool_output",
        "on conflict",
        "grant delete",
    ):
        assert forbidden not in sql


def test_pending_lifecycle_requires_one_way_receipted_transition() -> None:
    sql = _literal("UPGRADE_SQL")
    assert "expires_at > evaluated_at" in sql
    assert "state = 'pending' and transition_receipt_id is null" in sql
    assert "state != 'pending' and transition_receipt_id is not null" in sql
    assert "pending_decision = 'step_up' and cardinality(missing_context) = 0" in sql
    assert "pending_decision = 'defer'" in sql


def test_pending_downgrade_removes_only_its_table() -> None:
    assert _literal("DOWNGRADE_SQL") == "drop table pending_memory_actions;"
