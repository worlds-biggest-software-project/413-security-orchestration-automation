# Data Model Suggestion 4: Knowledge Graph + Relational Hybrid (Graph-Native Threat Intelligence)

> Project: Security Orchestration & Automation (SOAR) -- Candidate #413
> Approach: Property graph database for threat intelligence, incident correlation, and STIX relationships, combined with PostgreSQL for operational data and workflow management

---

## Summary

This approach recognises that the core intellectual challenge of a SOAR platform -- connecting alerts to observables, observables to threat actors, threat actors to campaigns, campaigns to MITRE ATT&CK techniques, and all of these to historical incidents -- is fundamentally a graph problem. STIX 2.1 itself is defined as a graph of nodes (Domain Objects, Cyber-observable Objects) and edges (Relationships). MITRE ATT&CK is a knowledge graph. Incident correlation ("has this IP appeared in other incidents?", "what is the kill chain path for this campaign?") is graph traversal.

This design uses a property graph database (Neo4j or Apache AGE on PostgreSQL) as the primary store for threat intelligence, observable correlation, and incident relationship mapping, while retaining PostgreSQL for operational data (users, tenants, playbook execution state, audit logs, SLA tracking) where relational integrity and transactional guarantees are essential.

The key insight is that SOAR platforms need to answer two fundamentally different types of questions:
1. **Operational queries** ("What are my open incidents sorted by SLA deadline?") -- relational
2. **Investigative queries** ("What is the shortest path from this alert to a known threat actor?", "What other incidents share observables with this one?") -- graph

---

## Key Entities and Relationships

### Architecture Overview

```
┌─────────────────────────────────────────────┐
│             Graph Database (Neo4j)           │
│                                              │
│  (:Incident)──[:HAS_OBSERVABLE]──(:Observable)
│       │                              │
│  [:MAPPED_TO]                  [:ENRICHED_BY]
│       │                              │
│  (:MITRETechnique)           (:EnrichmentResult)
│       │                              │
│  [:PART_OF_TACTIC]           [:INDICATES]
│       │                              │
│  (:MITRETactic)              (:ThreatIndicator)
│                                      │
│  (:ThreatActor)──[:USES]──(:Malware) │
│       │              │          [:ATTRIBUTED_TO]
│  [:TARGETS]    [:EXPLOITS]           │
│       │              │         (:Campaign)
│  (:Identity)   (:Vulnerability)      │
│                              [:PART_OF]
│  (:Case)──[:CONTAINS_INCIDENT]──(:Incident)
│                                              │
│  (:AIInvestigation)──[:INVESTIGATED]──(:Incident)
│       │                                      │
│  [:PRODUCED_FINDING]──(:Finding)             │
│       │                                      │
│  [:SUGGESTED_ACTION]──(:ResponseAction)      │
└──────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│        PostgreSQL (Operational Store)         │
│                                              │
│  tenants, users, roles, user_roles           │
│  playbook_definitions, playbook_versions     │
│  playbook_executions, execution_steps        │
│  alert_inbox (raw OCSF events)               │
│  integration_configs, credentials            │
│  audit_logs (partitioned by month)           │
│  sla_tracking, shift_handovers               │
│  notification_queue                          │
└──────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│    Synchronisation Layer (CDC / Dual-Write)   │
│                                              │
│  PostgreSQL ←→ Neo4j sync for:               │
│  - Incident metadata (id, status, severity)  │
│  - User references (assignee, created_by)    │
│  - Playbook execution references             │
└──────────────────────────────────────────────┘
```

### Graph Schema (Neo4j / Cypher)

#### Node Types and Properties

```cypher
// ── Incident Node ──
CREATE CONSTRAINT incident_id IF NOT EXISTS
FOR (i:Incident) REQUIRE i.id IS UNIQUE;

// Example node:
// (:Incident {
//   id: "550e8400-...",
//   tenant_id: "tenant-001",
//   title: "Suspicious login from anomalous IP",
//   severity: "high",
//   status: "investigating",
//   phase: "detection_analysis",
//   source: "splunk",
//   source_ref: "SPLUNK-ALERT-29481",
//   created_at: datetime("2026-05-25T10:30:00Z"),
//   updated_at: datetime("2026-05-25T11:15:00Z")
// })

// ── Observable Node ──
CREATE CONSTRAINT observable_unique IF NOT EXISTS
FOR (o:Observable) REQUIRE (o.tenant_id, o.type, o.value) IS UNIQUE;

// Example:
// (:Observable {
//   id: "obs-001",
//   tenant_id: "tenant-001",
//   type: "ip_v4",
//   value: "198.51.100.23",
//   tlp: "TLP:AMBER",
//   first_seen: datetime("2026-05-20T08:00:00Z"),
//   last_seen: datetime("2026-05-25T10:30:00Z")
// })

// ── STIX Domain Objects ──
CREATE CONSTRAINT stix_id IF NOT EXISTS
FOR (s:STIXObject) REQUIRE s.stix_id IS UNIQUE;

// Subtypes via labels:
// (:STIXObject:ThreatActor {stix_id: "threat-actor--...", name: "APT29", ...})
// (:STIXObject:Malware {stix_id: "malware--...", name: "CozyDuke", ...})
// (:STIXObject:Campaign {stix_id: "campaign--...", name: "...", ...})
// (:STIXObject:Vulnerability {stix_id: "vulnerability--...", cve_id: "CVE-2026-1234", ...})
// (:STIXObject:AttackPattern {stix_id: "attack-pattern--...", mitre_id: "T1566.001", ...})

// ── MITRE ATT&CK ──
CREATE CONSTRAINT mitre_technique IF NOT EXISTS
FOR (t:MITRETechnique) REQUIRE t.technique_id IS UNIQUE;

// (:MITRETechnique {
//   technique_id: "T1566.001",
//   name: "Spearphishing Attachment",
//   url: "https://attack.mitre.org/techniques/T1566/001/"
// })

// (:MITRETactic {
//   tactic_id: "TA0001",
//   name: "Initial Access"
// })

// ── AI Investigation ──
// (:AIInvestigation {
//   id: "inv-001",
//   tenant_id: "tenant-001",
//   agent_model: "claude-soar-v2",
//   status: "completed",
//   verdict: "true_positive",
//   confidence: 0.87,
//   started_at: datetime("..."),
//   completed_at: datetime("...")
// })

// (:Finding {
//   id: "finding-001",
//   step_number: 2,
//   action: "enrich_ip",
//   finding: "IP geolocates to country not in user travel history",
//   timestamp: datetime("...")
// })

// ── Enrichment Result ──
// (:EnrichmentResult {
//   id: "enrich-001",
//   source: "virustotal",
//   score: 12,
//   detected: true,
//   raw_result: '{"scan_date": "...", ...}',
//   retrieved_at: datetime("...")
// })

// ── Case ──
// (:Case {
//   id: "case-001",
//   tenant_id: "tenant-001",
//   title: "APT29 Campaign Investigation Q2 2026",
//   status: "open",
//   priority: 1,
//   created_at: datetime("...")
// })
```

#### Relationship Types

```cypher
// ── Core Incident Relationships ──
// (:Incident)-[:HAS_OBSERVABLE {is_ioc: true, sighted_at: datetime()}]->(:Observable)
// (:Incident)-[:MAPPED_TO {confidence: 85, mapped_by: "ai"}]->(:MITRETechnique)
// (:Incident)-[:ASSIGNED_TO]->(:User)
// (:Incident)-[:CREATED_BY]->(:User)
// (:Incident)-[:TRIGGERED_PLAYBOOK {execution_id: "..."}]->(:Playbook)
// (:Case)-[:CONTAINS_INCIDENT {added_at: datetime()}]->(:Incident)

// ── Observable Relationships ──
// (:Observable)-[:ENRICHED_BY {retrieved_at: datetime()}]->(:EnrichmentResult)
// (:Observable)-[:MATCHES_INDICATOR {confidence: 90}]->(:STIXObject:Indicator)
// (:Observable)-[:ALSO_SEEN_IN]->(:Incident)  -- cross-incident correlation

// ── STIX Relationships (directly from STIX 2.1) ──
// (:STIXObject:Indicator)-[:INDICATES]->(:STIXObject:Malware)
// (:STIXObject:ThreatActor)-[:USES]->(:STIXObject:Malware)
// (:STIXObject:ThreatActor)-[:USES]->(:STIXObject:AttackPattern)
// (:STIXObject:ThreatActor)-[:TARGETS]->(:STIXObject:Identity)
// (:STIXObject:Campaign)-[:ATTRIBUTED_TO]->(:STIXObject:ThreatActor)
// (:STIXObject:Malware)-[:EXPLOITS]->(:STIXObject:Vulnerability)
// (:STIXObject:AttackPattern)-[:SUBTECHNIQUE_OF]->(:STIXObject:AttackPattern)

// ── MITRE ATT&CK ──
// (:MITRETechnique)-[:PART_OF_TACTIC]->(:MITRETactic)
// (:STIXObject:AttackPattern)-[:MAPS_TO]->(:MITRETechnique)

// ── AI Investigation ──
// (:AIInvestigation)-[:INVESTIGATED]->(:Incident)
// (:AIInvestigation)-[:PRODUCED_FINDING {step: 1}]->(:Finding)
// (:AIInvestigation)-[:SUGGESTED_ACTION]->(:ResponseAction)
// (:Finding)-[:REFERENCES_OBSERVABLE]->(:Observable)
// (:Finding)-[:REFERENCES_INCIDENT]->(:Incident)  -- historical correlation
```

#### Example Investigative Queries (Cypher)

```cypher
// 1. Find all incidents sharing observables with a given incident
MATCH (i1:Incident {id: $incident_id})-[:HAS_OBSERVABLE]->(o:Observable)
      <-[:HAS_OBSERVABLE]-(i2:Incident)
WHERE i1 <> i2
RETURN i2.id, i2.title, i2.severity, collect(DISTINCT o.value) AS shared_observables
ORDER BY size(shared_observables) DESC;

// 2. Trace from an observable to known threat actors
MATCH path = (o:Observable {value: $ip_address})
      -[:MATCHES_INDICATOR]->(ind:STIXObject:Indicator)
      -[:INDICATES]->(m:STIXObject:Malware)
      <-[:USES]-(ta:STIXObject:ThreatActor)
RETURN o.value, ind.stix_id, m.name, ta.name, length(path);

// 3. MITRE ATT&CK coverage gap analysis
MATCH (t:MITRETechnique)-[:PART_OF_TACTIC]->(tac:MITRETactic)
OPTIONAL MATCH (i:Incident {tenant_id: $tenant})-[:MAPPED_TO]->(t)
WITH tac.name AS tactic, t.technique_id AS technique, t.name AS name,
     count(i) AS incident_count
RETURN tactic, technique, name, incident_count
ORDER BY incident_count ASC;

// 4. Kill chain reconstruction for an incident
MATCH (i:Incident {id: $incident_id})-[:MAPPED_TO]->(t:MITRETechnique)
      -[:PART_OF_TACTIC]->(tac:MITRETactic)
RETURN tac.name AS tactic, collect({technique: t.technique_id, name: t.name}) AS techniques
ORDER BY CASE tac.name
  WHEN 'Reconnaissance' THEN 1
  WHEN 'Resource Development' THEN 2
  WHEN 'Initial Access' THEN 3
  WHEN 'Execution' THEN 4
  WHEN 'Persistence' THEN 5
  WHEN 'Privilege Escalation' THEN 6
  WHEN 'Defense Evasion' THEN 7
  WHEN 'Credential Access' THEN 8
  WHEN 'Discovery' THEN 9
  WHEN 'Lateral Movement' THEN 10
  WHEN 'Collection' THEN 11
  WHEN 'Command and Control' THEN 12
  WHEN 'Exfiltration' THEN 13
  WHEN 'Impact' THEN 14
END;

// 5. AI investigation reasoning chain traversal
MATCH (inv:AIInvestigation {id: $investigation_id})-[:PRODUCED_FINDING]->(f:Finding)
OPTIONAL MATCH (f)-[:REFERENCES_OBSERVABLE]->(o:Observable)
OPTIONAL MATCH (f)-[:REFERENCES_INCIDENT]->(ri:Incident)
RETURN f.step_number, f.action, f.finding,
       collect(DISTINCT o.value) AS observables_referenced,
       collect(DISTINCT ri.title) AS incidents_referenced
ORDER BY f.step_number;

// 6. Find similar historical incidents for an alert
MATCH (i:Incident {id: $new_incident_id})-[:HAS_OBSERVABLE]->(o:Observable)
MATCH (o)<-[:HAS_OBSERVABLE]-(hist:Incident)
WHERE hist.status = 'closed' AND hist.id <> $new_incident_id
WITH hist, count(o) AS shared_count,
     collect(o.value) AS shared_values
OPTIONAL MATCH (hist)-[:MAPPED_TO]->(t:MITRETechnique)
RETURN hist.id, hist.title, hist.severity, shared_count,
       shared_values, collect(t.technique_id) AS techniques
ORDER BY shared_count DESC
LIMIT 10;
```

### PostgreSQL Schema (Operational Store)

```sql
-- Operational tables remain in PostgreSQL for transactional guarantees

CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    tier            VARCHAR(50) NOT NULL DEFAULT 'standard',
    settings        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
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

-- Playbook definitions stored in PostgreSQL (workflow is structured data)
CREATE TABLE playbook_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    trigger_type    VARCHAR(50) NOT NULL,
    status          VARCHAR(50) DEFAULT 'draft',
    workflow        JSONB NOT NULL,          -- CACAO 2.0 JSON
    git_commit_sha  VARCHAR(40),
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Playbook executions: transactional state machine
CREATE TABLE playbook_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    playbook_id     UUID NOT NULL REFERENCES playbook_definitions(id),
    incident_id     UUID,                    -- references graph incident node by ID
    status          VARCHAR(50) NOT NULL DEFAULT 'running',
    step_results    JSONB DEFAULT '{}',
    triggered_by    UUID REFERENCES users(id),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

-- Alert inbox: high-throughput ingest before graph promotion
CREATE TABLE alert_inbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    source          VARCHAR(100) NOT NULL,
    ocsf_event      JSONB NOT NULL,
    raw_payload     JSONB,
    triage_status   VARCHAR(50) DEFAULT 'pending',
    promoted_to_incident_id UUID,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (received_at);

-- Integration management
CREATE TABLE integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    vendor          VARCHAR(255),
    category        VARCHAR(100),
    status          VARCHAR(50) DEFAULT 'active',
    config          JSONB DEFAULT '{}',
    openapi_spec    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE integration_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id  UUID NOT NULL REFERENCES integrations(id),
    auth_type       VARCHAR(50) NOT NULL,
    credentials_enc BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit log: append-only, partitioned
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    user_id         UUID,
    action          VARCHAR(100) NOT NULL,
    entity_type     VARCHAR(100) NOT NULL,
    entity_id       UUID,
    changes         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);

-- SLA tracking
CREATE TABLE sla_tracking (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    incident_id     UUID NOT NULL,           -- references graph node
    sla_policy      VARCHAR(100) NOT NULL,
    deadline        TIMESTAMPTZ NOT NULL,
    met             BOOLEAN,
    breached_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Synchronisation Layer

```python
# Dual-write pattern: write to PostgreSQL + Neo4j in a saga
# or CDC-based sync from PostgreSQL to Neo4j

class IncidentSyncService:
    """
    Keeps incident metadata in sync between PostgreSQL (operational)
    and Neo4j (investigative). Neo4j is the primary for incident
    relationships; PostgreSQL alert_inbox feeds into Neo4j on promotion.
    """

    async def promote_alert_to_incident(self, alert_id: UUID) -> UUID:
        # 1. Read alert from PostgreSQL
        alert = await self.pg.get_alert(alert_id)

        # 2. Create Incident node in Neo4j with observables
        incident_id = uuid4()
        async with self.neo4j.session() as session:
            await session.execute_write(
                self._create_incident_with_observables,
                incident_id=incident_id,
                alert=alert
            )

        # 3. Update alert_inbox in PostgreSQL
        await self.pg.mark_alert_promoted(alert_id, incident_id)

        # 4. Publish event for downstream consumers
        await self.event_bus.publish(IncidentCreatedEvent(
            incident_id=incident_id,
            tenant_id=alert['tenant_id']
        ))

        return incident_id

    @staticmethod
    async def _create_incident_with_observables(tx, incident_id, alert):
        # Create incident node
        await tx.run("""
            CREATE (i:Incident {
                id: $id, tenant_id: $tenant_id, title: $title,
                severity: $severity, status: 'new',
                phase: 'detection_analysis', source: $source,
                created_at: datetime()
            })
        """, id=str(incident_id), **alert)

        # Create observable nodes and relationships
        for obs in alert.get('observables', []):
            await tx.run("""
                MERGE (o:Observable {
                    tenant_id: $tenant_id, type: $type, value: $value
                })
                ON CREATE SET o.id = $obs_id, o.first_seen = datetime()
                SET o.last_seen = datetime()
                WITH o
                MATCH (i:Incident {id: $incident_id})
                CREATE (i)-[:HAS_OBSERVABLE {
                    sighted_at: datetime(), is_ioc: false
                }]->(o)
            """, tenant_id=alert['tenant_id'], incident_id=str(incident_id),
                 obs_id=str(uuid4()), **obs)
```

---

## Pros

- **Natural STIX 2.1 representation**: STIX is a graph of nodes and edges. Storing it in a graph database preserves the original semantics without the impedance mismatch of flattening into relational tables. STIX relationships map directly to graph edges.
- **Powerful investigative queries**: Graph traversal queries that would require multiple complex JOINs in SQL (e.g. "trace from this IP through indicators to threat actors") become simple, readable Cypher queries with predictable performance.
- **Cross-incident correlation**: Finding shared observables, common attack patterns, and related campaigns across thousands of incidents is where graph databases excel. The "also seen in" query pattern is O(1) per edge rather than O(n) table scan.
- **MITRE ATT&CK as native knowledge graph**: ATT&CK is already a graph (techniques -> tactics, techniques -> sub-techniques). Storing it natively enables coverage gap analysis, kill chain reconstruction, and attack path visualisation with simple traversals.
- **AI investigation context**: When an AI agent investigates an incident, it can traverse the graph to find related historical incidents, known threat actors, and enrichment data -- providing richer context than relational queries.
- **Visual analytics**: Graph databases integrate naturally with visualisation libraries (D3.js, vis.js, Neo4j Bloom) for analyst-facing relationship exploration UIs -- a key differentiator for SOC tools.
- **Schema flexibility**: Property graphs handle heterogeneous STIX objects (each with different properties) naturally via node labels and properties, without requiring a fixed relational schema for each object type.

## Cons

- **Operational complexity**: Running and managing two database engines (PostgreSQL + Neo4j) significantly increases operational burden -- backup, monitoring, upgrade, capacity planning, failover, and on-call procedures for two systems.
- **Data consistency**: Keeping data synchronised between PostgreSQL and Neo4j requires either dual-write patterns (with saga/compensation for failures) or CDC pipelines (with eventual consistency). Both add complexity and failure modes.
- **Neo4j licensing**: Neo4j Community Edition is GPLv3 (copyleft); the Enterprise Edition (with clustering, RBAC, advanced monitoring) is commercially licensed. For a self-hosted open-source SOAR, the GPLv3 constraint of Community Edition may conflict with the project's licensing model.
- **Multi-tenancy in Neo4j**: Neo4j does not have built-in row-level security comparable to PostgreSQL RLS. Tenant isolation requires application-level enforcement (tenant_id property on every node and relationship, filtered in every query), or separate databases per tenant (expensive).
- **ACID limitations**: Neo4j supports ACID transactions within a single database, but cross-database transactions (e.g. between the PostgreSQL operational store and Neo4j) require distributed transaction coordination.
- **Write throughput**: Graph databases are optimised for read-heavy, relationship-traversal workloads. High-frequency alert ingestion (thousands per minute) may bottleneck on Neo4j writes compared to PostgreSQL.
- **Team skill requirements**: Graph databases and Cypher query language represent a meaningful learning curve for teams accustomed to SQL. Hiring and onboarding costs increase.

### Alternative: Apache AGE (Graph on PostgreSQL)

If the two-database complexity is a concern, Apache AGE provides graph query capabilities (openCypher) as a PostgreSQL extension, allowing graph queries within the same PostgreSQL instance. This eliminates the sync problem at the cost of less mature graph performance and tooling compared to Neo4j.

```sql
-- Apache AGE: graph queries within PostgreSQL
SELECT * FROM cypher('soar_graph', $$
    MATCH (i:Incident {id: '550e8400-...'})-[:HAS_OBSERVABLE]->(o:Observable)
          <-[:HAS_OBSERVABLE]-(i2:Incident)
    WHERE i <> i2
    RETURN i2.title, collect(o.value) AS shared
$$) as (title agtype, shared agtype);
```

---

## Technology Recommendations

| Component | Recommendation |
|-----------|----------------|
| **Graph database** | Neo4j Community/Enterprise, or Apache AGE extension on PostgreSQL for single-database deployment |
| **Operational database** | PostgreSQL 16+ for users, playbooks, executions, audit logs |
| **Sync layer** | Debezium CDC from PostgreSQL to Neo4j, or application-level dual-write with saga pattern |
| **Graph query language** | Cypher (Neo4j) or openCypher (AGE); GQL (ISO/IEC 39075) when tooling matures |
| **STIX ingestion** | python-stix2 library for parsing; direct graph writes for STIX objects and relationships |
| **Visualisation** | Neo4j Bloom for analyst exploration; D3.js or vis.js for embedded UI components |
| **Search** | Neo4j full-text indexes for graph search; PostgreSQL for operational search |
| **Playbook engine** | Temporal.io backed by PostgreSQL; graph used only for investigation context |

---

## Migration and Scaling Considerations

- **Start with Apache AGE**: Begin with Apache AGE on PostgreSQL to validate graph query patterns without the operational burden of a second database. Migrate to Neo4j only if graph query performance becomes a bottleneck.
- **STIX import pipeline**: Build a STIX 2.1 ingestion pipeline that parses STIX bundles and creates nodes (Domain Objects) and edges (Relationships) in the graph. The python-stix2 library handles parsing; the application maps to graph writes.
- **Neo4j clustering**: For production, Neo4j Aura (managed) or Enterprise Edition clustering provides read replicas for analyst queries while the primary handles writes from alert processing and enrichment.
- **Tenant isolation strategy**: For MSSP deployments, use separate Neo4j databases per tenant (supported in Enterprise Edition) rather than property-based filtering, for stronger isolation guarantees.
- **Graph pruning and archival**: Old incident nodes and their relationships grow the graph. Implement archival policies that detach closed incidents older than the retention period into a cold archive (Neo4j export to JSON or Parquet), keeping the active graph performant.
- **Fallback path**: If the graph approach proves too complex operationally, the PostgreSQL operational store already contains all data needed to run the platform. The graph layer is an accelerator for investigative queries, not a hard dependency. Demoting it to an optional "investigation accelerator" module is a viable simplification.
