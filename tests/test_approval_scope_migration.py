from __future__ import annotations

import ast
import re
from pathlib import Path

REVISION_PATH = (
    Path(__file__).parents[1]
    / "migrations"
    / "versions"
    / "0002_approval_scope_binding.py"
)


def _source() -> str:
    return REVISION_PATH.read_text(encoding="utf-8")


def _literal(name: str) -> str:
    tree = ast.parse(_source())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return re.sub(r"\s+", " ", value.casefold()).strip()
    raise AssertionError(f"missing literal: {name}")


def test_forward_revision_is_chained_and_uses_alembic() -> None:
    source = _source()
    assert 'revision = "0002_approval_scope_binding"' in source
    assert 'down_revision = "0001_memory_core"' in source
    assert "from alembic import op" in source
    assert source.count("op.execute(statement)") == 2


def test_upgrade_persists_and_backfills_exact_approved_scope() -> None:
    sql = _literal("UPGRADE_SQL")
    for column in ("purpose_scopes", "audience_scopes"):
        assert (
            f"alter table derivative_approvals add column {column} string[] null" in sql
        )
        assert (
            f"alter table derivative_approvals alter column {column} set not null"
            in sql
        )
    assert (
        "alter table derivative_approvals add column expires_at timestamptz null" in sql
    )
    assert (
        "alter table derivative_approvals alter column expires_at set not null" in sql
    )
    assert "set purpose_scopes = derivative.purpose_scopes" in sql
    assert "audience_scopes = derivative.audience_scopes" in sql
    assert "expires_at = derivative.expires_at" in sql
    for exact_join in (
        "derivative.tenant_id = approval.tenant_id",
        "derivative.program_id = approval.program_id",
        "derivative.id = approval.derivative_memory_id",
    ):
        assert exact_join in sql
    assert "expires_at > coalesce(reviewed_at, created_at)" in sql
    assert "on conflict do nothing" not in sql


def test_downgrade_removes_constraint_before_bound_columns() -> None:
    sql = _literal("DOWNGRADE_SQL")
    statements = (
        "drop constraint derivative_approvals_expiry_check",
        "drop column expires_at",
        "drop column audience_scopes",
        "drop column purpose_scopes",
    )
    positions = [sql.index(statement) for statement in statements]
    assert positions == sorted(positions)
