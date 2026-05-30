# Data Model Suggestion 1: Normalized Relational (PostgreSQL)

> Project: Security Orchestration & Automation (SOAR) -- Candidate #413
> Approach: Traditional normalized relational database with strict referential integrity

---

## Summary

This approach uses a fully normalized PostgreSQL schema where every entity -- incidents, cases, playbooks, observables, threat intel, users, tenants -- is represented as a dedicated table with foreign key relationships. The design prioritises data integrity, ACID compliance, and straightforward SQL querying, which aligns well with the audit trail and regulatory compliance requirements of a SOAR platform.

---

## Key Entities and Relationships

### Entity-Relationship Overview

```
tenants ──┬── users ──── user_roles
          ├── incidents ──┬── incident_observables ── observables
          │               ├── incident_timeline_events
          │               ├── incident_tasks ── task_assignments
          │               ├── incident_evidence
          │               ├── incident_comments
          │               ├── incident_mitre_mappings ── mitre_techniques
          │               └── incident_playbook_executions ── playbook_execution_steps
          ├── cases ──┬── case_incidents
          │           ├── case_tasks
          │           └── case_sla_tracking
          ├── playbooks ──┬── playbook_versions
          │               ├── playbook_steps ── step_connections
          │               └── playbook_integrations
          ├── integrations ──┬── integration_credentials
          │                  └── integration_actions
          ├── threat_intel_feeds ── threat_indicators
          └── audit_logs
```

### Core Schema Snippets

#### Tenant and User Management

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    tier            VARCHAR(50) NOT NULL DEFAULT 'standard',
    settings        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    email           VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(100) NOT NULL,
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (tenant_id, name)
);

CREATE TABLE user_roles (
    user_id         UUID NOT NULL REFERENCES users(id),
    role_id         UUID NOT NULL REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);
```

#### Incident and Case Management

```sql
CREATE TYPE incident_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE incident_status AS ENUM (
    'new', 'triaging', 'investigating', 'containment',
    'eradication', 'recovery', 'closed', 'reopened'
);
CREATE TYPE incident_phase AS ENUM (
    'detection_analysis', 'containment_eradication_recovery', 'post_incident'
);

CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        incident_severity NOT NULL DEFAULT 'medium',
    status          incident_status NOT NULL DEFAULT 'new',
    phase           incident_phase NOT NULL DEFAULT 'detection_analysis',
    source          VARCHAR(100),          -- e.g. 'siem', 'edr', 'manual'
    source_ref      VARCHAR(500),          -- external reference ID
    assignee_id     UUID REFERENCES users(id),
    created_by      UUID NOT NULL REFERENCES users(id),
    sla_deadline    TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX idx_incidents_severity ON incidents(tenant_id, severity);
CREATE INDEX idx_incidents_created ON incidents(tenant_id, created_at DESC);

CREATE TABLE cases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    status          VARCHAR(50) NOT NULL DEFAULT 'open',
    priority        INTEGER NOT NULL DEFAULT 3,
    lead_analyst_id UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at       TIMESTAMPTZ
);

CREATE TABLE case_incidents (
    case_id         UUID NOT NULL REFERENCES cases(id),
    incident_id     UUID NOT NULL REFERENCES incidents(id),
    PRIMARY KEY (case_id, incident_id)
);

CREATE TABLE incident_tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    assignee_id     UUID REFERENCES users(id),
    due_at          TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### Observables and Threat Intelligence

```sql
CREATE TYPE observable_type AS ENUM (
    'ip_v4', 'ip_v6', 'domain', 'url', 'email', 'email_subject',
    'file_hash_md5', 'file_hash_sha1', 'file_hash_sha256',
    'file_name', 'file_path', 'registry_key', 'process_name',
    'user_account', 'mac_address', 'certificate_hash', 'cve', 'other'
);

CREATE TABLE observables (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    type            observable_type NOT NULL,
    value           TEXT NOT NULL,
    tlp             VARCHAR(20) DEFAULT 'TLP:AMBER',
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    tags            TEXT[],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, type, value)
);

CREATE TABLE incident_observables (
    incident_id     UUID NOT NULL REFERENCES incidents(id),
    observable_id   UUID NOT NULL REFERENCES observables(id),
    is_ioc          BOOLEAN DEFAULT false,
    sighted_at      TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (incident_id, observable_id)
);

CREATE TABLE threat_intel_feeds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    feed_type       VARCHAR(50) NOT NULL,  -- 'stix_taxii', 'misp', 'csv', 'custom'
    url             TEXT,
    polling_interval_seconds INTEGER DEFAULT 3600,
    enabled         BOOLEAN DEFAULT true,
    last_polled_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE threat_indicators (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id         UUID NOT NULL REFERENCES threat_intel_feeds(id),
    stix_id         VARCHAR(255),
    indicator_type  observable_type NOT NULL,
    value           TEXT NOT NULL,
    confidence      INTEGER CHECK (confidence BETWEEN 0 AND 100),
    valid_from      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ,
    kill_chain_phase VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mitre_techniques (
    id              VARCHAR(20) PRIMARY KEY,  -- e.g. 'T1566.001'
    name            VARCHAR(255) NOT NULL,
    tactic          VARCHAR(100) NOT NULL,
    description     TEXT,
    url             TEXT
);

CREATE TABLE incident_mitre_mappings (
    incident_id     UUID NOT NULL REFERENCES incidents(id),
    technique_id    VARCHAR(20) NOT NULL REFERENCES mitre_techniques(id),
    confidence      INTEGER DEFAULT 50,
    mapped_by       VARCHAR(50) DEFAULT 'manual', -- 'manual', 'ai', 'playbook'
    PRIMARY KEY (incident_id, technique_id)
);
```

#### Playbook and Workflow Engine

```sql
CREATE TABLE playbooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    trigger_type    VARCHAR(50) NOT NULL,    -- 'manual', 'alert', 'schedule', 'webhook'
    status          VARCHAR(50) DEFAULT 'draft',
    git_repo_url    TEXT,
    git_branch      VARCHAR(255),
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE playbook_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id     UUID NOT NULL REFERENCES playbooks(id),
    version_number  INTEGER NOT NULL,
    commit_sha      VARCHAR(40),
    definition      TEXT NOT NULL,           -- CACAO JSON or internal DSL
    is_active       BOOLEAN DEFAULT false,
    published_by    UUID REFERENCES users(id),
    published_at    TIMESTAMPTZ,
    UNIQUE (playbook_id, version_number)
);

CREATE TABLE playbook_steps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_version_id UUID NOT NULL REFERENCES playbook_versions(id),
    step_type       VARCHAR(50) NOT NULL,   -- 'action', 'decision', 'parallel', 'loop', 'sub_workflow', 'human_gate'
    name            VARCHAR(255) NOT NULL,
    integration_id  UUID REFERENCES integrations(id),
    action_name     VARCHAR(255),
    parameters      TEXT,                    -- serialised params
    timeout_seconds INTEGER DEFAULT 300,
    sort_order      INTEGER NOT NULL
);

CREATE TABLE step_connections (
    from_step_id    UUID NOT NULL REFERENCES playbook_steps(id),
    to_step_id      UUID NOT NULL REFERENCES playbook_steps(id),
    condition_expr  TEXT,                    -- branching condition
    label           VARCHAR(100),
    PRIMARY KEY (from_step_id, to_step_id)
);

CREATE TABLE playbook_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_version_id UUID NOT NULL REFERENCES playbook_versions(id),
    incident_id     UUID REFERENCES incidents(id),
    status          VARCHAR(50) NOT NULL DEFAULT 'running',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    triggered_by    UUID REFERENCES users(id),
    trigger_source  VARCHAR(100)
);

CREATE TABLE playbook_execution_steps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id    UUID NOT NULL REFERENCES playbook_executions(id),
    step_id         UUID NOT NULL REFERENCES playbook_steps(id),
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    input_data      TEXT,
    output_data     TEXT,
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);
```

#### Integration and Connector Management

```sql
CREATE TABLE integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    vendor          VARCHAR(255),
    category        VARCHAR(100),           -- 'siem', 'edr', 'identity', 'ticketing', 'cloud'
    openapi_spec_url TEXT,
    status          VARCHAR(50) DEFAULT 'active',
    health_status   VARCHAR(50) DEFAULT 'unknown',
    last_health_check TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE integration_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id  UUID NOT NULL REFERENCES integrations(id),
    auth_type       VARCHAR(50) NOT NULL,   -- 'api_key', 'oauth2', 'basic', 'mtls'
    credentials_enc BYTEA NOT NULL,         -- encrypted at rest
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ
);

CREATE TABLE integration_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id  UUID NOT NULL REFERENCES integrations(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    http_method     VARCHAR(10),
    endpoint_path   TEXT,
    request_schema  TEXT,
    response_schema TEXT,
    UNIQUE (integration_id, name)
);
```

#### Audit Log

```sql
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID REFERENCES users(id),
    action          VARCHAR(100) NOT NULL,
    entity_type     VARCHAR(100) NOT NULL,
    entity_id       UUID,
    details         TEXT,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_entity ON audit_logs(entity_type, entity_id);
```

#### Timeline Events

```sql
CREATE TABLE incident_timeline_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id),
    event_type      VARCHAR(100) NOT NULL,  -- 'alert_received', 'enrichment', 'action_taken', 'comment', 'status_change', 'ai_analysis'
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    actor_type      VARCHAR(50),            -- 'user', 'system', 'playbook', 'ai_agent'
    actor_id        UUID,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_timeline_incident ON incident_timeline_events(incident_id, occurred_at);
```

---

## Pros

- **Referential integrity**: Foreign keys guarantee data consistency across all entities -- critical for audit trails and regulatory compliance (SOC 2, ISO 27001, GDPR Art. 33).
- **Mature tooling**: PostgreSQL has decades of tooling, client libraries, ORMs, migration frameworks (Flyway, Alembic), and operational knowledge.
- **Strong query capabilities**: Complex joins across incidents, observables, threat intel, and playbook executions are straightforward in SQL. Aggregate dashboards (MTTD, MTTR, analyst workload) are natural.
- **ACID transactions**: Multi-table updates (e.g. "close incident + update SLA + log audit event") are atomic, preventing partial state corruption.
- **Multi-tenancy via tenant_id**: Row-level security (RLS) in PostgreSQL can enforce tenant isolation at the database level, meeting MSSP requirements.
- **Standards alignment**: Tables map cleanly to NIST 800-61 phases, MITRE ATT&CK, STIX indicator types, and OCSF event categories.

## Cons

- **Schema rigidity**: Every new observable type, enrichment source, or playbook step variant requires a schema migration. In a domain where integrations and alert formats change frequently, this creates maintenance overhead.
- **Impedance mismatch with STIX/CACAO**: STIX 2.1 and CACAO 2.0 are graph-like JSON structures. Flattening them into normalised tables loses the natural graph semantics and requires reconstruction on read.
- **Performance at scale**: Incident timelines, audit logs, and playbook execution logs can grow to billions of rows. Partitioning and archival strategies are essential but add complexity.
- **Playbook definition storage**: Storing workflow graphs (DAGs) in relational tables (playbook_steps + step_connections) is awkward; a graph or document representation is more natural.
- **Limited flexibility for AI reasoning chains**: Agentic AI produces variable-structure reasoning chains. Storing these in fixed relational columns forces either a TEXT blob column or an ever-expanding schema.

---

## Technology Recommendations

| Component | Recommendation |
|-----------|----------------|
| **Primary database** | PostgreSQL 16+ with pg_partman for time-series tables |
| **ORM / query builder** | SQLAlchemy (Python) or Prisma (TypeScript) |
| **Migrations** | Alembic (Python) or Flyway (Java/polyglot) |
| **Multi-tenancy** | Row-Level Security (RLS) policies on tenant_id |
| **Encryption at rest** | pgcrypto for credential columns; TDE for full-disk |
| **Connection pooling** | PgBouncer or Supavisor |
| **Search** | pg_trgm + GIN indexes for observable/indicator search |
| **Time-series partitioning** | Monthly partitions on audit_logs, timeline_events |

---

## Migration and Scaling Considerations

- **Partitioning strategy**: Partition audit_logs, incident_timeline_events, and playbook_execution_steps by month to keep query performance predictable as data grows.
- **Read replicas**: Use streaming replication to offload dashboard and reporting queries to read replicas, keeping the primary database responsive for operational writes.
- **Archival**: Move closed incidents older than a configurable retention period to cold storage (S3 + Parquet) while keeping references in the primary database for compliance.
- **Tenant isolation upgrade path**: Start with shared schema + RLS, then move to schema-per-tenant or database-per-tenant for large MSSP customers if isolation requirements increase.
- **Migration to other models**: The normalised schema provides clean source-of-truth data that can be projected into event stores, graph databases, or search indexes as the system evolves.
