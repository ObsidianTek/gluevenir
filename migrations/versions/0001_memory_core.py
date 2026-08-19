"""Create the tenant-isolated governed-memory core.

Revision ID: 0001_memory_core
Revises:
"""

from collections.abc import Iterator

from alembic import op

revision = "0001_memory_core"
down_revision = None
branch_labels = None
depends_on = None


UPGRADE_SQL = r"""
CREATE ROLE gluevenir_app;
ALTER ROLE gluevenir_app NOBYPASSRLS;

CREATE TABLE memory_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    program_id UUID NOT NULL,
    room STRING NOT NULL,
    content STRING NULL,
    embedding VECTOR(256) NULL,
    sensitivity STRING[] NOT NULL,
    purpose_scopes STRING[] NOT NULL,
    audience_scopes STRING[] NOT NULL,
    source_memory_id UUID NULL,
    state STRING NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    content_sha256 STRING NULL,
    policy_version STRING NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp(),
    created_by STRING NOT NULL,
    CONSTRAINT memory_records_tenant_program_id_key
        UNIQUE (tenant_id, program_id, id),
    CONSTRAINT memory_records_source_fk
        FOREIGN KEY (tenant_id, program_id, source_memory_id)
        REFERENCES memory_records (tenant_id, program_id, id),
    CONSTRAINT memory_records_room_check CHECK (
        room IN ('clinical-restricted', 'research-confidential', 'external-approved')
    ),
    CONSTRAINT memory_records_state_check CHECK (
        state IN ('proposed', 'active', 'quarantined', 'revoked', 'forgotten')
    ),
    CONSTRAINT memory_records_hash_check CHECK (
        (state = 'forgotten' AND content_sha256 IS NULL)
        OR (state != 'forgotten' AND length(content_sha256) = 64)
    ),
    CONSTRAINT memory_records_validity_check CHECK (
        expires_at IS NULL OR expires_at > valid_from
    ),
    CONSTRAINT memory_records_revocation_check CHECK (
        revoked_at IS NULL OR state IN ('revoked', 'forgotten')
    ),
    CONSTRAINT memory_records_forgotten_check CHECK (
        state != 'forgotten' OR (content IS NULL AND embedding IS NULL)
    ),
    CONSTRAINT memory_records_derivative_room_check CHECK (
        source_memory_id IS NULL OR room = 'external-approved'
    )
);

CREATE VECTOR INDEX memory_recall_idx
    ON memory_records (tenant_id, program_id, embedding vector_cosine_ops);

CREATE TABLE derivative_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    program_id UUID NOT NULL,
    source_memory_id UUID NOT NULL,
    derivative_memory_id UUID NOT NULL,
    decision STRING NOT NULL,
    reviewed_by STRING NULL,
    reviewed_at TIMESTAMPTZ NULL,
    reason_code STRING NOT NULL,
    source_sha256 STRING NOT NULL,
    derivative_sha256 STRING NOT NULL,
    policy_version STRING NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp(),
    CONSTRAINT derivative_approvals_tenant_program_id_key
        UNIQUE (tenant_id, program_id, id),
    CONSTRAINT derivative_approvals_source_fk
        FOREIGN KEY (tenant_id, program_id, source_memory_id)
        REFERENCES memory_records (tenant_id, program_id, id),
    CONSTRAINT derivative_approvals_derivative_fk
        FOREIGN KEY (tenant_id, program_id, derivative_memory_id)
        REFERENCES memory_records (tenant_id, program_id, id),
    CONSTRAINT derivative_approvals_distinct_memory_check CHECK (
        source_memory_id != derivative_memory_id
    ),
    CONSTRAINT derivative_approvals_decision_check CHECK (
        decision IN ('proposed', 'approved', 'rejected', 'revoked')
    ),
    CONSTRAINT derivative_approvals_hashes_check CHECK (
        length(source_sha256) = 64 AND length(derivative_sha256) = 64
    ),
    CONSTRAINT derivative_approvals_reviewer_check CHECK (
        decision = 'proposed'
        OR (reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)
    )
);

CREATE TABLE session_context (
    session_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    program_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    intent_label STRING NOT NULL,
    original_intent_sha256 STRING NOT NULL,
    agent_id STRING NOT NULL,
    actor_id STRING NOT NULL,
    actor_role STRING NOT NULL,
    declared_purpose STRING NOT NULL,
    declared_audience STRING NOT NULL,
    classification_summary JSONB NOT NULL,
    prior_receipt_ids UUID[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT session_context_tenant_program_session_key
        UNIQUE (tenant_id, program_id, session_id),
    CONSTRAINT session_context_intent_hash_check CHECK (
        length(original_intent_sha256) = 64
    ),
    CONSTRAINT session_context_lifecycle_check CHECK (
        expires_at > created_at AND updated_at >= created_at
    )
);

CREATE TABLE recall_receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    program_id UUID NOT NULL,
    request_id UUID NOT NULL,
    session_id UUID NOT NULL,
    intent_id UUID NOT NULL,
    actor_id STRING NOT NULL,
    agent_id STRING NOT NULL,
    agent_signing_key_id STRING NOT NULL,
    operation STRING NOT NULL,
    action_envelope JSONB NOT NULL,
    action_arguments_sha256 STRING NOT NULL,
    raw_query_sha256 STRING NULL,
    model_prompt_sha256 STRING NULL,
    answer_sha256 STRING NULL,
    decision STRING NOT NULL,
    decision_code STRING NOT NULL,
    reason_code STRING NOT NULL,
    purpose STRING NOT NULL,
    audience STRING NOT NULL,
    policy_version STRING NOT NULL,
    policy_sha256 STRING NOT NULL,
    app_version STRING NOT NULL,
    app_sha256 STRING NOT NULL,
    embedding_model_version STRING NULL,
    embedding_model_sha256 STRING NULL,
    prior_action_context_sha256 STRING NOT NULL,
    candidate_count INT NOT NULL,
    included_count INT NOT NULL,
    exclusion_counts JSONB NOT NULL,
    included_memory_ids UUID[] NOT NULL,
    included_content_sha256 STRING[] NOT NULL,
    resolution_of_receipt_id UUID NULL,
    approval_resolution_id UUID NULL,
    defer_resolution_id UUID NULL,
    retrieval_method STRING NOT NULL,
    response_status STRING NOT NULL,
    canonical_receipt_sha256 STRING NOT NULL,
    signature BYTES NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp(),
    completed_at TIMESTAMPTZ NULL,
    gateway_latency_bucket STRING NOT NULL,
    retrieval_latency_bucket STRING NULL,
    end_to_end_latency_bucket STRING NULL,
    CONSTRAINT recall_receipts_tenant_program_id_key
        UNIQUE (tenant_id, program_id, id),
    CONSTRAINT recall_receipts_session_fk
        FOREIGN KEY (tenant_id, program_id, session_id)
        REFERENCES session_context (tenant_id, program_id, session_id),
    CONSTRAINT recall_receipts_resolution_fk
        FOREIGN KEY (tenant_id, program_id, resolution_of_receipt_id)
        REFERENCES recall_receipts (tenant_id, program_id, id),
    CONSTRAINT recall_receipts_approval_fk
        FOREIGN KEY (tenant_id, program_id, approval_resolution_id)
        REFERENCES derivative_approvals (tenant_id, program_id, id),
    CONSTRAINT recall_receipts_operation_check CHECK (
        operation IN ('REMEMBER', 'RECALL', 'USE', 'SHARE', 'REVOKE', 'FORGET')
    ),
    CONSTRAINT recall_receipts_decision_check CHECK (
        decision IN ('ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER')
    ),
    CONSTRAINT recall_receipts_response_check CHECK (
        response_status IN ('pending', 'completed', 'denied', 'failed')
    ),
    CONSTRAINT recall_receipts_counts_check CHECK (
        candidate_count >= 0
        AND included_count >= 0
        AND included_count <= candidate_count
    ),
    CONSTRAINT recall_receipts_hashes_check CHECK (
        length(action_arguments_sha256) = 64
        AND (raw_query_sha256 IS NULL OR length(raw_query_sha256) = 64)
        AND (model_prompt_sha256 IS NULL OR length(model_prompt_sha256) = 64)
        AND (answer_sha256 IS NULL OR length(answer_sha256) = 64)
        AND length(policy_sha256) = 64
        AND length(app_sha256) = 64
        AND (
            embedding_model_sha256 IS NULL
            OR length(embedding_model_sha256) = 64
        )
        AND length(prior_action_context_sha256) = 64
        AND length(canonical_receipt_sha256) = 64
    ),
    CONSTRAINT recall_receipts_completion_check CHECK (
        completed_at IS NULL OR completed_at >= created_at
    )
);

CREATE TABLE receipt_memory_links (
    tenant_id UUID NOT NULL,
    program_id UUID NOT NULL,
    receipt_id UUID NOT NULL,
    memory_id UUID NOT NULL,
    disposition STRING NOT NULL,
    reason_code STRING NOT NULL,
    content_sha256 STRING NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp(),
    PRIMARY KEY (tenant_id, receipt_id, memory_id, disposition),
    CONSTRAINT receipt_memory_links_receipt_fk
        FOREIGN KEY (tenant_id, program_id, receipt_id)
        REFERENCES recall_receipts (tenant_id, program_id, id),
    CONSTRAINT receipt_memory_links_memory_fk
        FOREIGN KEY (tenant_id, program_id, memory_id)
        REFERENCES memory_records (tenant_id, program_id, id),
    CONSTRAINT receipt_memory_links_disposition_check CHECK (
        disposition IN ('included', 'excluded')
    ),
    CONSTRAINT receipt_memory_links_hash_check CHECK (
        content_sha256 IS NULL OR length(content_sha256) = 64
    )
);

CREATE TABLE policy_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    program_id UUID NOT NULL,
    operation STRING NOT NULL,
    outcome STRING NOT NULL,
    reason_code STRING NOT NULL,
    object_type STRING NOT NULL,
    object_id UUID NULL,
    actor_id STRING NOT NULL,
    actor_role STRING NOT NULL,
    purpose STRING NOT NULL,
    audience STRING NOT NULL,
    receipt_id UUID NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp(),
    CONSTRAINT policy_events_receipt_fk
        FOREIGN KEY (tenant_id, program_id, receipt_id)
        REFERENCES recall_receipts (tenant_id, program_id, id),
    CONSTRAINT policy_events_operation_check CHECK (
        operation IN ('REMEMBER', 'RECALL', 'USE', 'SHARE', 'REVOKE', 'FORGET')
    ),
    CONSTRAINT policy_events_outcome_check CHECK (
        outcome IN ('ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER')
    )
);

ALTER TABLE memory_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory_records FORCE ROW LEVEL SECURITY;
CREATE POLICY memory_records_tenant_isolation ON memory_records
    FOR ALL TO gluevenir_app
    USING (tenant_id = current_setting('app.current_tenant')::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE derivative_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE derivative_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY derivative_approvals_tenant_isolation ON derivative_approvals
    FOR ALL TO gluevenir_app
    USING (tenant_id = current_setting('app.current_tenant')::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE recall_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE recall_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY recall_receipts_tenant_isolation ON recall_receipts
    FOR ALL TO gluevenir_app
    USING (tenant_id = current_setting('app.current_tenant')::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE receipt_memory_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE receipt_memory_links FORCE ROW LEVEL SECURITY;
CREATE POLICY receipt_memory_links_tenant_isolation ON receipt_memory_links
    FOR ALL TO gluevenir_app
    USING (tenant_id = current_setting('app.current_tenant')::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE policy_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_events FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_events_tenant_isolation ON policy_events
    FOR ALL TO gluevenir_app
    USING (tenant_id = current_setting('app.current_tenant')::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE session_context ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_context FORCE ROW LEVEL SECURITY;
CREATE POLICY session_context_tenant_isolation ON session_context
    FOR ALL TO gluevenir_app
    USING (tenant_id = current_setting('app.current_tenant')::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::UUID);

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO gluevenir_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE memory_records TO gluevenir_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE derivative_approvals TO gluevenir_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE recall_receipts TO gluevenir_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE receipt_memory_links TO gluevenir_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE policy_events TO gluevenir_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE session_context TO gluevenir_app;
"""


DOWNGRADE_SQL = r"""
DROP TABLE policy_events;
DROP TABLE receipt_memory_links;
DROP TABLE recall_receipts;
DROP TABLE session_context;
DROP TABLE derivative_approvals;
DROP TABLE memory_records;
REVOKE USAGE ON SCHEMA public FROM gluevenir_app;
GRANT CREATE ON SCHEMA public TO PUBLIC;
DROP ROLE gluevenir_app;
"""


def _statements(script: str) -> Iterator[str]:
    for statement in script.split(";"):
        if normalized := statement.strip():
            yield normalized


def upgrade() -> None:
    """Apply the one-shot schema under Alembic's revision ledger."""
    for statement in _statements(UPGRADE_SQL):
        op.execute(statement)


def downgrade() -> None:
    """Remove all revision-owned objects in dependency-safe order."""
    for statement in _statements(DOWNGRADE_SQL):
        op.execute(statement)
