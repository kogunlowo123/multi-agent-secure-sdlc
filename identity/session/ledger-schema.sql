-- Session ledger schema for agent identity tracking
-- Enables audit trail of all agent sessions and decisions

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Agent session table
CREATE TABLE IF NOT EXISTS agent_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id VARCHAR(255) NOT NULL UNIQUE,
    agent_type VARCHAR(100) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    metadata JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Release gate decisions audit table
CREATE TABLE IF NOT EXISTS release_gate_decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    release_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) REFERENCES agent_sessions(session_id),
    decision VARCHAR(10) NOT NULL CHECK (decision IN ('GO', 'NO-GO')),
    status VARCHAR(50) NOT NULL,
    blockers JSONB DEFAULT '[]'::JSONB,
    warnings JSONB DEFAULT '[]'::JSONB,
    evidence JSONB DEFAULT '{}'::JSONB,
    evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    tenant_id VARCHAR(255) NOT NULL
);

-- Security findings audit table
CREATE TABLE IF NOT EXISTS security_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) REFERENCES agent_sessions(session_id),
    finding_type VARCHAR(50) NOT NULL CHECK (finding_type IN ('code-review', 'sast')),
    severity VARCHAR(20) NOT NULL,
    title TEXT NOT NULL,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    file_path TEXT,
    line_number INTEGER,
    repository VARCHAR(500),
    commit_sha VARCHAR(40),
    tenant_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Security embeddings for RAG
CREATE TABLE IF NOT EXISTS security_embeddings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source VARCHAR(500) NOT NULL UNIQUE,
    content TEXT NOT NULL,
    embedding vector(384),
    metadata JSONB DEFAULT '{}'::JSONB,
    ingested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON agent_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON agent_sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_decisions_release ON release_gate_decisions(release_id);
CREATE INDEX IF NOT EXISTS idx_decisions_tenant ON release_gate_decisions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON security_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_embeddings_vector ON security_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
