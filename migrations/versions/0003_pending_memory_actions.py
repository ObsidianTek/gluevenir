"""Persist bounded pending memory actions for restart-safe resolution.

Revision ID: 0003_pending_memory_actions
Revises: 0002_approval_scope_binding
"""

from collections.abc import Iterator

from alembic import op

revision = "0003_pending_memory_actions"
down_revision = "0002_approval_scope_binding"
branch_labels = None
depends_on = None


UPGRADE_SQL = r"""
CREATE TABLE pending_memory_actions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    program_id UUID NOT NULL,
    session_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    evaluation_receipt_id UUID NOT NULL,
    agent_id STRING NOT NULL,
    actor_id STRING NOT NULL,
    actor_role STRING NOT NULL,
    operation STRING NOT NULL,
    purpose STRING NOT NULL,
    audience STRING NOT NULL,
    destination STRING NOT NULL,
    policy_version STRING NOT NULL,
    requested_memory_ids UUID[] NOT NULL,
    data_classes STRING[] NOT NULL,
    missing_context STRING[] NOT NULL,
    action_arguments_sha256 STRING NOT NULL,
    original_intent_sha256 STRING NOT NULL,
    prior_action_context_sha256 STRING NOT NULL,
    pending_decision STRING NOT NULL,
    state STRING NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    transition_receipt_id UUID NULL,
    transitioned_at TIMESTAMPTZ NULL,
    CONSTRAINT pending_memory_actions_tenant_program_id_key
        UNIQUE (tenant_id, program_id, id),
    CONSTRAINT pending_memory_actions_session_fk
        FOREIGN KEY (tenant_id, program_id, session_id)
        REFERENCES session_context (tenant_id, program_id, session_id),
    CONSTRAINT pending_memory_actions_evaluation_receipt_fk
        FOREIGN KEY (tenant_id, program_id, evaluation_receipt_id)
        REFERENCES recall_receipts (tenant_id, program_id, id),
    CONSTRAINT pending_memory_actions_transition_receipt_fk
        FOREIGN KEY (tenant_id, program_id, transition_receipt_id)
        REFERENCES recall_receipts (tenant_id, program_id, id),
    CONSTRAINT pending_memory_actions_operation_check CHECK (
        operation IN ('REMEMBER', 'RECALL', 'USE', 'SHARE', 'REVOKE', 'FORGET')
    ),
    CONSTRAINT pending_memory_actions_decision_check CHECK (
        pending_decision IN ('STEP_UP', 'DEFER')
    ),
    CONSTRAINT pending_memory_actions_state_check CHECK (
        state IN ('pending', 'consumed', 'denied', 'expired')
    ),
    CONSTRAINT pending_memory_actions_destination_check CHECK (
        destination IN ('internal', 'external')
    ),
    CONSTRAINT pending_memory_actions_bounds_check CHECK (
        cardinality(requested_memory_ids) <= 5
        AND cardinality(data_classes) <= 8
        AND cardinality(missing_context) <= 2
    ),
    CONSTRAINT pending_memory_actions_context_check CHECK (
        (pending_decision = 'STEP_UP' AND cardinality(missing_context) = 0)
        OR
        (pending_decision = 'DEFER' AND cardinality(missing_context) BETWEEN 1 AND 2)
    ),
    CONSTRAINT pending_memory_actions_hashes_check CHECK (
        length(action_arguments_sha256) = 64
        AND length(original_intent_sha256) = 64
        AND length(prior_action_context_sha256) = 64
    ),
    CONSTRAINT pending_memory_actions_lifecycle_check CHECK (
        expires_at > evaluated_at
        AND (
            (
                state = 'pending'
                AND transition_receipt_id IS NULL
                AND transitioned_at IS NULL
            )
            OR
            (
                state != 'pending'
                AND transition_receipt_id IS NOT NULL
                AND transitioned_at IS NOT NULL
            )
        )
    )
);

ALTER TABLE pending_memory_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pending_memory_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY pending_memory_actions_tenant_isolation ON pending_memory_actions
    FOR ALL TO gluevenir_app
    USING (tenant_id = current_setting('app.current_tenant')::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::UUID);

GRANT SELECT, INSERT, UPDATE ON TABLE pending_memory_actions TO gluevenir_app;
"""


DOWNGRADE_SQL = r"""
DROP TABLE pending_memory_actions;
"""


def _statements(script: str) -> Iterator[str]:
    for statement in script.split(";"):
        if normalized := statement.strip():
            yield normalized


def upgrade() -> None:
    """Create the content-safe durable pending-action state machine."""
    for statement in _statements(UPGRADE_SQL):
        op.execute(statement)


def downgrade() -> None:
    """Remove only the durable pending-action table."""
    for statement in _statements(DOWNGRADE_SQL):
        op.execute(statement)
