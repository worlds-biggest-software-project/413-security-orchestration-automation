# Data Model Suggestion 3: Hybrid Relational + JSONB/Document Approach

> Project: Security Orchestration & Automation (SOAR) -- Candidate #413
> Approach: PostgreSQL with strategic JSONB columns for semi-structured data, combining relational integrity with document flexibility

---

## Summary

This approach uses PostgreSQL as the single primary database but strategically places JSONB columns where the data is inherently semi-structured, variable, or standards-defined (STIX, CACAO, OCSF). Core operational data -- incidents, cases, users, tenants, integrations -- uses traditional normalised columns with foreign keys and indexes. Domain-specific data that varies by incident type, integration, or AI model -- alert payloads, enrichment results, playbook definitions, AI reasoning chains, OCSF-normalised events -- is stored in JSONB columns with GIN indexes for efficient querying.

This is arguably the most pragmatic approach for a SOAR platform because it acknowledges that a significant portion of SOAR data is inherently schema-on-read (alert payloads from 50+ different tools, threat intel in STIX JSON, playbooks in CACAO JSON) while still providing relational guarantees for the operational core.

---

## Key Entities and Relationships

### Architecture Overview

```
PostgreSQL (single database, multi-tenant)
│
├── Relational Core (normalised columns, FK constraints)
│   ├── tenants, users, roles, user_roles
│   ├── incidents (core fields: id, severity, status, phase, assignee)
│   ├── cases, case_incidents
│   ├── integrations, integration_credentials
│   └── audit_logs
│
├── Hybrid Tables (relational columns + JSONB)
│   ├── incidents.alert_payload          JSONB  -- raw OCSF-normalised alert
│   ├── incidents.enrichments            JSONB  -- accumulated enrichment results
│   ├── incidents.ai_analysis            JSONB  -- latest AI verdict + reasoning chain
│   ├── incidents.custom_fields          JSONB  -- tenant-specific fields
│   ├── observables.enrichment_data      JSONB  -- VirusTotal, Shodan, etc.
│   ├── observables.stix_object          JSONB  -- full STIX 2.1 representation
│   ├── playbook_definitions.workflow    JSONB  -- CACAO 2.0 playbook JSON
│   ├── playbook_executions.step_results JSONB  -- per-step I/O and timings
│   ├── timeline_events.details          JSONB  -- event-type-specific payload
│   └── threat_indicators.stix_data     JSONB  -- full STIX indicator object
│
└── Document-Heavy Tables (primarily JSONB, minimal relational)
    ├── alert_inbox                      JSONB  -- raw inbound alerts before triage
    ├── connector_schemas                JSONB  -- OpenAPI specs for integrations
    └── ai_investigation_sessions        JSONB  -- full reasoning session logs
```

### Schema Snippets

#### Core Entities (relational with JSONB extensions)

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    tier            VARCHAR(50) NOT NULL DEFAULT 'standard',
    settings        JSONB NOT NULL DEFAULT '{}',
    feature_flags   JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    email           VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    preferences     JSONB NOT NULL DEFAULT '{}',   -- UI preferences, notification settings
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);
```

#### Incidents (hybrid: relational core + JSONB extensions)

```sql
CREATE TABLE incidents (
    -- Relational core: frequently queried, indexed, constrained
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    title           VARCHAR(500) NOT NULL,
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium'
                    CHECK (severity IN ('critical','high','medium','low','info')),
    status          VARCHAR(50) NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new','triaging','investigating','containment',
                                      'eradication','recovery','closed','reopened')),
    phase           VARCHAR(50) NOT NULL DEFAULT 'detection_analysis',
    source          VARCHAR(100),
    source_ref      VARCHAR(500),
    assignee_id     UUID REFERENCES users(id),
    created_by      UUID NOT NULL REFERENCES users(id),
    sla_deadline    TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- JSONB extensions: semi-structured, variable per incident type
    alert_payload   JSONB,                  -- OCSF-normalised original alert
    enrichments     JSONB DEFAULT '{}',     -- keyed by enrichment source
    ai_analysis     JSONB,                  -- latest AI verdict and reasoning chain
    custom_fields   JSONB DEFAULT '{}',     -- tenant-defined custom fields
    mitre_mappings  JSONB DEFAULT '[]',     -- [{technique_id, tactic, confidence, mapped_by}]
    tags            JSONB DEFAULT '[]',     -- freeform tags
    related_refs    JSONB DEFAULT '[]'      -- external references (Jira tickets, etc.)
);

-- Standard indexes on relational columns
CREATE INDEX idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX idx_incidents_severity ON incidents(tenant_id, severity);
CREATE INDEX idx_incidents_assignee ON incidents(assignee_id) WHERE status != 'closed';
CREATE INDEX idx_incidents_created ON incidents(tenant_id, created_at DESC);

-- GIN indexes on JSONB for semi-structured queries
CREATE INDEX idx_incidents_mitre ON incidents USING GIN (mitre_mappings jsonb_path_ops);
CREATE INDEX idx_incidents_tags ON incidents USING GIN (tags jsonb_path_ops);
CREATE INDEX idx_incidents_custom ON incidents USING GIN (custom_fields jsonb_path_ops);
CREATE INDEX idx_incidents_alert_payload ON incidents USING GIN (alert_payload jsonb_path_ops);
```

#### Observables (hybrid: relational identity + JSONB enrichment)

```sql
CREATE TABLE observables (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    type            VARCHAR(50) NOT NULL,
    value           TEXT NOT NULL,
    tlp             VARCHAR(20) DEFAULT 'TLP:AMBER',
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,

    -- JSONB: enrichment results from multiple sources
    enrichment_data JSONB DEFAULT '{}',
    -- Example: {
    --   "virustotal": {"score": 12, "detected": true, "last_scan": "..."},
    --   "shodan":     {"ports": [22,80,443], "org": "..."},
    --   "geoip":      {"country": "RU", "city": "Moscow", "asn": 12345},
    --   "whois":      {"registrar": "...", "created": "..."}
    -- }

    -- JSONB: full STIX 2.1 representation if from threat intel
    stix_object     JSONB,

    tags            JSONB DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, type, value)
);

CREATE INDEX idx_obs_tenant_type ON observables(tenant_id, type);
CREATE INDEX idx_obs_value ON observables(tenant_id, value);
CREATE INDEX idx_obs_enrichment ON observables USING GIN (enrichment_data jsonb_path_ops);

CREATE TABLE incident_observables (
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    observable_id   UUID NOT NULL REFERENCES observables(id),
    is_ioc          BOOLEAN DEFAULT false,
    context         JSONB DEFAULT '{}',     -- incident-specific context for this observable
    sighted_at      TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (incident_id, observable_id)
);
```

#### Playbooks (JSONB workflow definitions with relational metadata)

```sql
CREATE TABLE playbook_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    trigger_type    VARCHAR(50) NOT NULL,
    status          VARCHAR(50) DEFAULT 'draft',
    current_version INTEGER NOT NULL DEFAULT 1,

    -- JSONB: full CACAO 2.0 playbook or internal workflow definition
    workflow        JSONB NOT NULL,
    -- The workflow column stores the complete playbook graph:
    -- {
    --   "type": "playbook",
    --   "spec_version": "cacao-2.0",
    --   "playbook_types": ["investigation"],
    --   "workflow": {
    --     "step-1": {"type": "action", "name": "Enrich IP", ...},
    --     "step-2": {"type": "decision", "condition": "...", ...},
    --     ...
    --   },
    --   "workflow_start": "step-1"
    -- }

    git_repo_url    TEXT,
    git_branch      VARCHAR(255),
    git_commit_sha  VARCHAR(40),
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE playbook_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id     UUID NOT NULL REFERENCES playbook_definitions(id),
    version_number  INTEGER NOT NULL,
    workflow        JSONB NOT NULL,             -- snapshot of workflow at this version
    commit_sha      VARCHAR(40),
    changelog       TEXT,
    published_by    UUID REFERENCES users(id),
    published_at    TIMESTAMPTZ,
    UNIQUE (playbook_id, version_number)
);
```

#### Playbook Executions (relational tracking + JSONB step results)

```sql
CREATE TABLE playbook_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    playbook_id     UUID NOT NULL REFERENCES playbook_definitions(id),
    version_number  INTEGER NOT NULL,
    incident_id     UUID REFERENCES incidents(id),
    status          VARCHAR(50) NOT NULL DEFAULT 'running',
    triggered_by    UUID REFERENCES users(id),
    trigger_source  VARCHAR(100),

    -- JSONB: per-step results accumulated during execution
    step_results    JSONB DEFAULT '{}',
    -- Example: {
    --   "step-1": {"status": "completed", "output": {...}, "duration_ms": 450, "started_at": "...", "completed_at": "..."},
    --   "step-2": {"status": "completed", "output": {...}, "duration_ms": 1200},
    --   "step-3": {"status": "failed", "error": "Timeout connecting to CrowdStrike", "duration_ms": 30000}
    -- }

    execution_context JSONB DEFAULT '{}',   -- runtime variables and state
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_exec_tenant ON playbook_executions(tenant_id, status);
CREATE INDEX idx_exec_incident ON playbook_executions(incident_id);
```

#### AI Investigation Sessions

```sql
CREATE TABLE ai_investigation_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    incident_id     UUID NOT NULL REFERENCES incidents(id),
    agent_model     VARCHAR(100) NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'running',

    -- JSONB: full reasoning session with chain-of-thought
    reasoning_chain JSONB NOT NULL DEFAULT '[]',
    -- Example: [
    --   {"step": 1, "action": "query_siem", "query": "...", "finding": "...", "timestamp": "..."},
    --   {"step": 2, "action": "enrich_ip", "target": "198.51.100.23", "finding": "...", "timestamp": "..."},
    --   {"step": 3, "action": "correlate_incidents", "finding": "...", "timestamp": "..."},
    --   {"step": 4, "action": "form_hypothesis", "hypothesis": "...", "confidence": 0.82}
    -- ]

    verdict         VARCHAR(50),            -- 'true_positive', 'false_positive', 'needs_review'
    confidence      FLOAT,
    recommendations JSONB DEFAULT '[]',     -- suggested next actions
    token_usage     JSONB DEFAULT '{}',     -- LLM token tracking

    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_ai_session_incident ON ai_investigation_sessions(incident_id);
```

#### Alert Inbox (document-centric: raw alerts before triage)

```sql
CREATE TABLE alert_inbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    source          VARCHAR(100) NOT NULL,      -- 'splunk', 'sentinel', 'crowdstrike'
    source_ref      VARCHAR(500),

    -- JSONB: raw alert in OCSF-normalised format
    ocsf_event      JSONB NOT NULL,
    -- The alert arrives in whatever format the source uses, gets normalised
    -- to OCSF on ingestion, and stored as a complete OCSF event object.

    -- JSONB: original raw payload for debugging
    raw_payload     JSONB,

    severity_hint   VARCHAR(20),
    triage_status   VARCHAR(50) DEFAULT 'pending',  -- 'pending', 'auto_dismissed', 'promoted', 'merged'
    promoted_to_incident_id UUID REFERENCES incidents(id),
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    triaged_at      TIMESTAMPTZ
);

CREATE INDEX idx_alert_tenant_status ON alert_inbox(tenant_id, triage_status, received_at DESC);
CREATE INDEX idx_alert_ocsf ON alert_inbox USING GIN (ocsf_event jsonb_path_ops);
```

#### Timeline Events (relational envelope + JSONB details)

```sql
CREATE TABLE timeline_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_type      VARCHAR(100) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    actor_type      VARCHAR(50),
    actor_id        UUID,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- JSONB: event-type-specific details
    details         JSONB DEFAULT '{}',
    -- For event_type='enrichment': {"source": "virustotal", "result": {...}}
    -- For event_type='playbook_step': {"step_name": "...", "output": {...}}
    -- For event_type='ai_analysis': {"verdict": "...", "confidence": 0.85}
    -- For event_type='status_change': {"from": "new", "to": "investigating"}

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_timeline_incident ON timeline_events(incident_id, occurred_at);
CREATE INDEX idx_timeline_type ON timeline_events(incident_id, event_type);
```

#### Threat Intelligence (JSONB for STIX objects)

```sql
CREATE TABLE threat_intel_feeds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    feed_type       VARCHAR(50) NOT NULL,
    url             TEXT,
    polling_interval_seconds INTEGER DEFAULT 3600,
    enabled         BOOLEAN DEFAULT true,
    config          JSONB DEFAULT '{}',     -- feed-specific configuration
    last_polled_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE threat_indicators (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    feed_id         UUID NOT NULL REFERENCES threat_intel_feeds(id),
    indicator_type  VARCHAR(50) NOT NULL,
    value           TEXT NOT NULL,
    confidence      INTEGER CHECK (confidence BETWEEN 0 AND 100),
    valid_from      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ,

    -- JSONB: full STIX 2.1 indicator object
    stix_data       JSONB,
    -- Preserves the complete STIX object including:
    -- kill_chain_phases, external_references, labels, pattern, etc.

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ti_tenant_type ON threat_indicators(tenant_id, indicator_type);
CREATE INDEX idx_ti_value ON threat_indicators(tenant_id, value);
CREATE INDEX idx_ti_stix ON threat_indicators USING GIN (stix_data jsonb_path_ops);
```

#### Audit Log

```sql
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    user_id         UUID,
    action          VARCHAR(100) NOT NULL,
    entity_type     VARCHAR(100) NOT NULL,
    entity_id       UUID,
    changes         JSONB,                  -- {"field": {"old": X, "new": Y}}
    request_context JSONB DEFAULT '{}',     -- IP, user-agent, session info
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);

-- Create monthly partitions
CREATE TABLE audit_logs_2026_05 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_logs_2026_06 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, created_at DESC);
```

#### Integration and Connector Management

```sql
CREATE TABLE integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    vendor          VARCHAR(255),
    category        VARCHAR(100),
    status          VARCHAR(50) DEFAULT 'active',
    health_status   VARCHAR(50) DEFAULT 'unknown',
    last_health_check TIMESTAMPTZ,

    -- JSONB: OpenAPI spec and connector config
    openapi_spec    JSONB,                  -- cached OpenAPI definition
    config          JSONB DEFAULT '{}',     -- connector-specific settings
    capabilities    JSONB DEFAULT '[]',     -- list of supported actions

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE integration_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id  UUID NOT NULL REFERENCES integrations(id),
    auth_type       VARCHAR(50) NOT NULL,
    credentials_enc BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ
);
```

---

## Pros

- **Best of both worlds**: Relational integrity for operational data (incidents, users, tenants) and document flexibility for semi-structured data (alerts, enrichments, STIX objects, CACAO playbooks, AI reasoning chains).
- **Single database**: No need to operate multiple database engines. PostgreSQL handles both relational and document workloads, reducing operational complexity significantly.
- **Standards-native storage**: STIX 2.1, CACAO 2.0, and OCSF are all JSON-based standards. Storing them as JSONB preserves the original structure without lossy normalisation, while still allowing indexed queries via GIN.
- **Tenant-specific customisation**: The `custom_fields` JSONB column on incidents lets each tenant define their own fields without schema migrations -- critical for an MSSP platform where every customer has different requirements.
- **GIN index performance**: PostgreSQL GIN indexes on JSONB columns support efficient containment queries (`@>`), existence checks (`?`), and path queries, making it practical to search within semi-structured data at scale.
- **Gradual schema evolution**: New enrichment sources, alert formats, or AI model outputs can be added without migrations. Only changes to the relational core require ALTER TABLE.
- **Familiar tooling**: Standard PostgreSQL tooling, ORMs, and migration frameworks work. JSONB is well-supported in SQLAlchemy, Prisma, TypeORM, and similar.
- **Strong query language**: SQL for relational queries combined with PostgreSQL JSON operators and functions (`->`, `->>`, `@>`, `jsonb_path_query`) provides powerful query capabilities across both structured and semi-structured data.

## Cons

- **JSONB query performance limits**: While GIN indexes help, complex nested JSONB queries are slower than equivalent normalised column queries. Deeply nested path queries and aggregations on JSONB data can be expensive.
- **No referential integrity on JSONB**: Foreign key references within JSONB documents (e.g. a user_id inside a reasoning chain step) cannot be enforced by the database. Application-level validation is required.
- **Schema validation burden**: JSONB columns accept any valid JSON. Without application-layer validation (JSON Schema, Zod, Pydantic), data quality depends entirely on the code writing the data.
- **Reporting complexity**: Dashboard queries that need to aggregate across JSONB fields (e.g. "count incidents by MITRE technique") are more complex and slower than equivalent queries on normalised columns.
- **Backup and migration overhead**: Large JSONB values (e.g. complete CACAO playbooks, full AI reasoning sessions) can make individual rows large, affecting backup times and replication lag.
- **Potential for JSONB sprawl**: Without discipline, JSONB columns become catch-all dumping grounds. Clear boundaries for what goes in JSONB vs. relational columns must be established and enforced.

---

## Technology Recommendations

| Component | Recommendation |
|-----------|----------------|
| **Primary database** | PostgreSQL 16+ (JSONB improvements, better GIN performance) |
| **ORM / query builder** | SQLAlchemy 2.x with JSONB column types, or Prisma with Json field type |
| **JSONB validation** | JSON Schema validation at application layer (python-jsonschema, Zod, ajv) |
| **Indexing strategy** | GIN indexes with `jsonb_path_ops` on JSONB columns used in WHERE clauses |
| **Full-text search** | PostgreSQL tsvector for text fields; consider OpenSearch for complex search across JSONB |
| **Migrations** | Alembic for relational schema; application-level migration for JSONB schema evolution |
| **Multi-tenancy** | Row-Level Security (RLS) on tenant_id; shared schema model |
| **Connection pooling** | PgBouncer with transaction-mode pooling |
| **Monitoring** | pg_stat_statements for query performance; track JSONB query costs specifically |

---

## Migration and Scaling Considerations

- **JSONB to relational promotion**: If a JSONB field is queried frequently enough to warrant its own column and index, promote it to a relational column via ALTER TABLE ADD COLUMN + backfill. This is a routine optimisation path.
- **Partitioning strategy**: Partition alert_inbox, timeline_events, and audit_logs by time range. Partition incidents by tenant_id for large MSSP deployments.
- **TOAST management**: Large JSONB values are automatically stored in TOAST tables by PostgreSQL. Monitor TOAST table sizes and consider compressing or archiving large payloads (e.g. raw_payload in alert_inbox).
- **Read replicas for reporting**: Route dashboard and reporting queries to read replicas to avoid contention with operational writes. JSONB aggregation queries are particularly CPU-intensive.
- **Elasticsearch sidecar**: For full-text search across alert payloads, enrichment data, and AI reasoning chains, consider syncing JSONB data to Elasticsearch/OpenSearch via CDC (Debezium). This provides the search UX analysts expect without overloading PostgreSQL.
- **JSONB schema versioning**: Include a `_schema_version` key in JSONB columns. Application code can handle migration by checking the version and upcasting on read, avoiding bulk data migrations.
- **Upgrade path to event sourcing**: The hybrid model can evolve toward event sourcing for specific domains (e.g. incident lifecycle) by adding an event log table and treating JSONB-stored state as a materialised projection.
