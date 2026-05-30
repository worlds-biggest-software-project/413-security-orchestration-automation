# Data Model Suggestion 2: Event-Sourced / CQRS Approach

> Project: Security Orchestration & Automation (SOAR) -- Candidate #413
> Approach: Event sourcing with Command Query Responsibility Segregation (CQRS)

---

## Summary

This approach treats every state change in the SOAR platform as an immutable event stored in an append-only event log. Incidents are never "updated" -- instead, events like `IncidentCreated`, `SeverityEscalated`, `ObservableAttached`, and `PlaybookStepCompleted` are appended to a stream, and materialised read models (projections) are rebuilt from these events to serve queries. CQRS separates the write path (commands that produce events) from the read path (projections optimised for specific query patterns like dashboards, timelines, and search).

This is a strong architectural fit for SOAR because security incident response is inherently event-driven: alerts arrive, analysts take actions, playbooks execute steps, and AI agents produce reasoning chains -- each of these is a discrete event that must be recorded immutably for audit and forensic purposes.

---

## Key Entities and Relationships

### Event Store Structure

```
Event Store (append-only)
├── Incident Streams         (stream per incident)
│   ├── IncidentCreated
│   ├── AlertCorrelated
│   ├── SeverityEscalated
│   ├── ObservableAttached
│   ├── EnrichmentCompleted
│   ├── TaskCreated / TaskCompleted
│   ├── PlaybookTriggered
│   ├── AIAnalysisCompleted
│   ├── ContainmentActionExecuted
│   ├── StatusChanged
│   ├── CommentAdded
│   └── IncidentClosed
├── Playbook Execution Streams  (stream per execution)
│   ├── ExecutionStarted
│   ├── StepStarted / StepCompleted / StepFailed
│   ├── HumanApprovalRequested / HumanApprovalGranted
│   └── ExecutionCompleted
├── Threat Intel Streams     (stream per feed)
│   ├── FeedPolled
│   ├── IndicatorIngested
│   └── IndicatorExpired
└── AI Agent Streams         (stream per investigation)
    ├── InvestigationStarted
    ├── HypothesisFormed
    ├── EvidenceGathered
    ├── ReasoningStepCompleted
    ├── RecommendationGenerated
    └── InvestigationCompleted

Read Models (projections)
├── IncidentListProjection       → optimised for dashboard queries
├── IncidentDetailProjection     → full incident with timeline
├── CaseProjection               → case-to-incident grouping
├── AnalystWorkloadProjection    → per-analyst task counts and SLA
├── MITRECoverageProjection      → ATT&CK heatmap data
├── PlaybookMetricsProjection    → execution stats and failure rates
├── ObservableCorrelationProjection → cross-incident observable search
└── AuditTrailProjection         → compliance-ready audit log
```

### Schema Snippets

#### Event Store Tables (PostgreSQL as event store)

```sql
-- Core event store: one row per event, append-only
CREATE TABLE events (
    global_position   BIGSERIAL PRIMARY KEY,
    stream_name       VARCHAR(500) NOT NULL,    -- e.g. 'incident-{uuid}', 'playbook-exec-{uuid}'
    stream_position   BIGINT NOT NULL,
    event_type        VARCHAR(200) NOT NULL,    -- e.g. 'IncidentCreated', 'SeverityEscalated'
    data              JSONB NOT NULL,           -- event payload
    metadata          JSONB NOT NULL DEFAULT '{}',  -- correlation_id, causation_id, tenant_id, user_id
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (stream_name, stream_position)
);

CREATE INDEX idx_events_stream ON events(stream_name, stream_position);
CREATE INDEX idx_events_type ON events(event_type, created_at);
CREATE INDEX idx_events_tenant ON events((metadata->>'tenant_id'), created_at);

-- Stream metadata for optimistic concurrency control
CREATE TABLE streams (
    stream_name       VARCHAR(500) PRIMARY KEY,
    stream_category   VARCHAR(100) NOT NULL,    -- 'incident', 'playbook_execution', 'ai_investigation'
    current_position  BIGINT NOT NULL DEFAULT 0,
    tenant_id         UUID NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### Event Type Definitions (examples)

```json
// IncidentCreated
{
  "event_type": "IncidentCreated",
  "stream_name": "incident-550e8400-e29b-41d4-a716-446655440000",
  "data": {
    "incident_id": "550e8400-e29b-41d4-a716-446655440000",
    "title": "Suspicious login from anomalous IP",
    "severity": "high",
    "source": "siem",
    "source_ref": "SPLUNK-ALERT-29481",
    "initial_observables": [
      {"type": "ip_v4", "value": "198.51.100.23"},
      {"type": "user_account", "value": "jdoe@corp.com"}
    ]
  },
  "metadata": {
    "tenant_id": "tenant-001",
    "user_id": "analyst-042",
    "correlation_id": "req-abc123",
    "timestamp": "2026-05-25T10:30:00Z"
  }
}

// AIAnalysisCompleted
{
  "event_type": "AIAnalysisCompleted",
  "stream_name": "incident-550e8400-e29b-41d4-a716-446655440000",
  "data": {
    "incident_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent_id": "ai-agent-triage-v2",
    "verdict": "true_positive",
    "confidence": 0.87,
    "reasoning_chain": [
      {"step": 1, "action": "query_siem", "finding": "5 failed logins from IP in 2 minutes"},
      {"step": 2, "action": "check_geo", "finding": "IP geolocates to country not in user travel history"},
      {"step": 3, "action": "check_identity", "finding": "User account has MFA disabled"},
      {"step": 4, "action": "correlate", "finding": "Similar pattern seen in incident INC-2024-1892"}
    ],
    "recommended_actions": ["enable_mfa", "block_ip", "notify_user"],
    "mitre_techniques": ["T1078", "T1110.001"]
  },
  "metadata": {
    "tenant_id": "tenant-001",
    "causation_id": "incident-created-evt-4521",
    "correlation_id": "req-abc123"
  }
}

// PlaybookStepCompleted
{
  "event_type": "PlaybookStepCompleted",
  "stream_name": "playbook-exec-7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "data": {
    "execution_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "step_id": "step-003",
    "step_name": "Block IP at Firewall",
    "integration": "palo_alto_ngfw",
    "action": "block_ip",
    "input": {"ip": "198.51.100.23", "direction": "inbound"},
    "output": {"rule_id": "FW-RULE-9921", "status": "applied"},
    "duration_ms": 1240
  },
  "metadata": {
    "tenant_id": "tenant-001",
    "causation_id": "playbook-step-started-evt-8832"
  }
}
```

#### Read Model Projections (materialised views)

```sql
-- Incident list projection: rebuilt from events, optimised for dashboard
CREATE TABLE projection_incident_list (
    incident_id     UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    title           VARCHAR(500) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    status          VARCHAR(50) NOT NULL,
    phase           VARCHAR(50) NOT NULL,
    source          VARCHAR(100),
    assignee_id     UUID,
    assignee_name   VARCHAR(255),
    observable_count INTEGER DEFAULT 0,
    task_count      INTEGER DEFAULT 0,
    tasks_completed INTEGER DEFAULT 0,
    ai_verdict      VARCHAR(50),
    ai_confidence   FLOAT,
    mitre_techniques TEXT[],
    sla_deadline    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    last_event_position BIGINT NOT NULL       -- checkpoint for rebuilding
);

CREATE INDEX idx_proj_inc_tenant ON projection_incident_list(tenant_id, status, severity);

-- Incident timeline projection: full event history per incident
CREATE TABLE projection_incident_timeline (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL,
    event_type      VARCHAR(200) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    details         JSONB,
    actor_type      VARCHAR(50),
    actor_id        VARCHAR(255),
    occurred_at     TIMESTAMPTZ NOT NULL,
    event_position  BIGINT NOT NULL
);

CREATE INDEX idx_proj_timeline ON projection_incident_timeline(incident_id, occurred_at);

-- Analyst workload projection
CREATE TABLE projection_analyst_workload (
    analyst_id      UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    display_name    VARCHAR(255),
    open_incidents  INTEGER DEFAULT 0,
    open_tasks      INTEGER DEFAULT 0,
    overdue_tasks   INTEGER DEFAULT 0,
    incidents_closed_24h INTEGER DEFAULT 0,
    avg_resolution_hours FLOAT,
    updated_at      TIMESTAMPTZ NOT NULL
);

-- MITRE coverage projection
CREATE TABLE projection_mitre_coverage (
    tenant_id       UUID NOT NULL,
    technique_id    VARCHAR(20) NOT NULL,
    technique_name  VARCHAR(255),
    tactic          VARCHAR(100),
    incident_count  INTEGER DEFAULT 0,
    playbook_count  INTEGER DEFAULT 0,
    last_seen       TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, technique_id)
);

-- Observable correlation projection for cross-incident search
CREATE TABLE projection_observable_index (
    observable_type VARCHAR(50) NOT NULL,
    observable_value TEXT NOT NULL,
    tenant_id       UUID NOT NULL,
    incident_ids    UUID[] NOT NULL,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    sighting_count  INTEGER DEFAULT 1,
    PRIMARY KEY (tenant_id, observable_type, observable_value)
);
```

#### Command Handlers (conceptual)

```python
# Command handler pattern (pseudocode)
class EscalateIncidentCommand:
    incident_id: UUID
    new_severity: str
    reason: str
    user_id: UUID

class IncidentAggregate:
    def handle_escalate(self, cmd: EscalateIncidentCommand) -> list[Event]:
        # Business rules validation
        if self.status == 'closed':
            raise InvalidOperationError("Cannot escalate a closed incident")
        if cmd.new_severity == self.severity:
            raise InvalidOperationError("Severity unchanged")

        return [
            SeverityEscalatedEvent(
                incident_id=cmd.incident_id,
                old_severity=self.severity,
                new_severity=cmd.new_severity,
                reason=cmd.reason,
                escalated_by=cmd.user_id,
            )
        ]

    def apply(self, event: SeverityEscalatedEvent):
        self.severity = event.new_severity
        self.updated_at = event.timestamp
```

---

## Pros

- **Complete audit trail by default**: Every state change is an immutable event. Regulatory compliance (SOC 2, ISO 27001, GDPR) is built into the architecture rather than bolted on. No separate audit log table needed -- the event store IS the audit log.
- **Natural fit for incident timelines**: Incident timelines are a first-class construct -- just replay the events for that incident stream. No complex join queries needed.
- **AI reasoning chains preserved natively**: Agentic AI investigation steps naturally fit as events in an investigation stream, producing exportable, auditable reasoning chains without any schema gymnastics.
- **Temporal queries**: "What was the state of this incident at 3am?" is answerable by replaying events up to that timestamp. This is invaluable for post-incident review and forensic analysis.
- **Independent read model scaling**: Dashboard projections, search indexes, and report generators can each have their own optimised data store, scaled independently of the write path.
- **Replay and rebuild**: If a projection is corrupted or a new query pattern is needed, projections can be rebuilt from the event log without data loss.
- **Decoupled processing**: New event consumers (e.g. a new analytics dashboard, a threat-hunting module, a compliance reporter) can be added without modifying the write path.

## Cons

- **Increased complexity**: Event sourcing and CQRS require a larger conceptual surface area. Teams must understand aggregates, commands, events, projections, and eventual consistency.
- **Eventual consistency**: Read models are updated asynchronously. An analyst may create an incident and not see it in the dashboard for a few hundred milliseconds. For a SOC tool, this latency must be managed carefully (e.g. synchronous projection updates for critical paths).
- **Event schema evolution**: As the domain evolves, event schemas change. Upcasting old events to new versions adds maintenance burden. Versioning strategies (e.g. event version field, upcaster pipelines) are essential.
- **Storage growth**: Storing every event rather than just current state consumes more storage. For high-volume SOAR deployments processing thousands of alerts per day, the event store can grow rapidly.
- **Query complexity for ad-hoc analysis**: Ad-hoc queries that span multiple aggregates (e.g. "all incidents involving IP X across all tenants in the last 30 days") require pre-built projections or expensive event replays. You cannot simply JOIN tables.
- **Tooling maturity**: While PostgreSQL can serve as an event store, purpose-built tools like EventStoreDB or Marten add dependencies. The ecosystem is less mature than traditional RDBMS tooling.
- **Development velocity impact**: Initial feature development is slower because each feature requires defining commands, events, aggregate logic, and projections rather than simple CRUD operations.

---

## Technology Recommendations

| Component | Recommendation |
|-----------|----------------|
| **Event store** | PostgreSQL with message_store schema (Eventide pattern) or EventStoreDB for dedicated event store |
| **Command/event bus** | In-process: Eventide (Ruby), Marten (C#/.NET), or custom Python handlers. Cross-service: Apache Kafka or NATS JetStream |
| **Projection engine** | Custom subscription workers reading from event store; or Kafka Streams / Flink for complex projections |
| **Read model databases** | PostgreSQL for relational projections; Elasticsearch/OpenSearch for full-text search; Redis for real-time counters |
| **Event schema registry** | Apache Avro with Confluent Schema Registry, or JSON Schema validation in the event store |
| **Workflow orchestration** | Temporal.io for durable playbook execution (each playbook execution is a Temporal workflow with automatic event history) |
| **Real-time push** | WebSocket subscriptions on event streams for live case timeline updates and War Room chat |
| **Serialisation** | JSON for event payloads (human-readable, debuggable); Avro or Protobuf for high-throughput internal streams |

---

## Migration and Scaling Considerations

- **Start simple, project early**: Begin with PostgreSQL as both event store and read model database. Add dedicated projection databases (Elasticsearch for search, Redis for dashboards) as query patterns stabilise.
- **Snapshotting**: For long-lived incident aggregates with hundreds of events, create periodic snapshots so replay does not need to process the full event history. Snapshot every N events (e.g. every 100).
- **Event store partitioning**: Partition the events table by tenant_id or by time range (monthly) to keep individual partition sizes manageable.
- **Kafka as event backbone**: When the platform grows beyond a single service, publish events to Kafka topics. Downstream services (search indexer, analytics engine, compliance reporter) consume from Kafka rather than polling the database.
- **Migration from event-sourced to relational**: If the team later decides event sourcing is too complex for certain bounded contexts, projections already serve as relational read models. Those projections can be promoted to "source of truth" for simpler domains while retaining event sourcing for the incident and playbook domains where audit trails matter most.
- **Multi-region deployment**: Event streams can be replicated across regions using Kafka MirrorMaker or EventStoreDB clustering, enabling geo-distributed SOC operations with eventual consistency.
- **Retention and compaction**: Define retention policies per stream category. Closed incident streams can be archived to cold storage (S3/GCS) after the regulatory retention period while keeping the projections live for historical search.
