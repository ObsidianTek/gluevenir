"""Bind approved derivative scope and expiry.

Revision ID: 0002_approval_scope_binding
Revises: 0001_memory_core
"""

from collections.abc import Iterator

from alembic import op

revision = "0002_approval_scope_binding"
down_revision = "0001_memory_core"
branch_labels = None
depends_on = None


UPGRADE_SQL = r"""
ALTER TABLE derivative_approvals ADD COLUMN purpose_scopes STRING[] NULL;
ALTER TABLE derivative_approvals ADD COLUMN audience_scopes STRING[] NULL;
ALTER TABLE derivative_approvals ADD COLUMN expires_at TIMESTAMPTZ NULL;

UPDATE derivative_approvals AS approval
SET purpose_scopes = derivative.purpose_scopes,
    audience_scopes = derivative.audience_scopes,
    expires_at = derivative.expires_at
FROM memory_records AS derivative
WHERE derivative.tenant_id = approval.tenant_id
  AND derivative.program_id = approval.program_id
  AND derivative.id = approval.derivative_memory_id;

ALTER TABLE derivative_approvals ALTER COLUMN purpose_scopes SET NOT NULL;
ALTER TABLE derivative_approvals ALTER COLUMN audience_scopes SET NOT NULL;
ALTER TABLE derivative_approvals ALTER COLUMN expires_at SET NOT NULL;

ALTER TABLE derivative_approvals
    ADD CONSTRAINT derivative_approvals_expiry_check
    CHECK (expires_at > COALESCE(reviewed_at, created_at));
"""


DOWNGRADE_SQL = r"""
ALTER TABLE derivative_approvals
    DROP CONSTRAINT derivative_approvals_expiry_check;
ALTER TABLE derivative_approvals DROP COLUMN expires_at;
ALTER TABLE derivative_approvals DROP COLUMN audience_scopes;
ALTER TABLE derivative_approvals DROP COLUMN purpose_scopes;
"""


def _statements(script: str) -> Iterator[str]:
    for statement in script.split(";"):
        if normalized := statement.strip():
            yield normalized


def upgrade() -> None:
    """Persist exact approved scopes and approval expiry."""
    for statement in _statements(UPGRADE_SQL):
        op.execute(statement)


def downgrade() -> None:
    """Remove approval-bound scope and expiry columns."""
    for statement in _statements(DOWNGRADE_SQL):
        op.execute(statement)
