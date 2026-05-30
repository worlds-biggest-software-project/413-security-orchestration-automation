# Security Orchestration & Automation (SOAR) — Phased Development Plan

> Project: 413-security-orchestration-automation · Created: 2026-05-30
> Purpose: Provide sufficient detail for Claude Code (Opus) to implement each phase end-to-end.

This plan synthesises `research.md`, `features.md`, `standards.md`, `README.md`, and the four `data-model-suggestion-*.md` files into concrete technology decisions, an architecture, and a sequence of buildable phases. The product is an **open-source, AI-native SOAR** that combines deterministic playbook automation with auditable agentic AI investigation, standards-based integrations (OCSF, STIX/TAXII, CACAO, OpenC2, MITRE ATT&CK), and MSSP-grade multi-tenancy.

---

## Technology Decisions

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Primary language | **Python 3.12** | The product is LLM-/agent-heavy (agentic investigation, NL-to-workflow, summarisation). Python has the strongest ecosystem for STIX (`stix2`), MITRE ATT&CK (`mitreattack-python`), MCP, the Anthropic SDK, and the security-tool SDKs referenced in standards.md (resilient-sdk, thehive4py). It is also the lingua franca of SOAR connector development (Splunk, XSOAR, FortiSOAR all use Python connector SDKs). |
| API framework | **FastAPI** | Async-first (critical for fan-out enrichment and long LLM calls), generates OpenAPI 3.1 automatically (required for the Shuffle-style connector auto-generation), and integrates natively with Pydantic v2 for JSON Schema 2020-12 validation of alert/observable payloads. |
| Data model | **Hybrid relational + JSONB on PostgreSQL 16** (data-model-suggestion-3) | Chosen over pure normalised (too rigid for 50+ alert formats), event-sourced (too much upfront complexity for an MVP), and graph-hybrid (two-engine operational burden). STIX 2.1, CACAO 2.0, and OCSF are all JSON; JSONB stores them losslessly with GIN indexes while the operational core (incidents, users, tenants) keeps FK integrity and RLS for tenant isolation. The plan keeps a clean upgrade path to Apache AGE (graph queries) and an event log if needed. |
| ORM / migrations | **SQLAlchemy 2.x (async) + Alembic** | Mature JSONB support, async engine for FastAPI, deterministic migrations for the relational core. JSONB schema evolution handled with a `_schema_version` key + application-layer JSON Schema validation. |
| Multi-tenancy | **PostgreSQL Row-Level Security on `tenant_id`** | Database-enforced isolation meets MSSP requirements without per-tenant databases at MVP. Upgrade path: schema-per-tenant for large customers. |
| Task queue / async | **Celery + Redis** (broker + result backend) | Enrichment fan-out, threat-feed polling, webhook ingestion, and LLM investigations are async, retryable, and rate-limited. Celery's retry/backoff and beat scheduler cover polling cron. |
| Workflow / playbook engine | **Custom DAG executor on Celery** for MVP; **Temporal.io** noted as the v1.1 upgrade for durable execution | A SOAR playbook is a DAG with branches, loops, human gates, and sub-workflows. The MVP executor walks a CACAO-derived graph step-by-step on Celery with persisted execution state (resumable). Temporal is the documented scaling path for crash-safe, long-running executions. |
| LLM / agent runtime | **Anthropic SDK (Claude) via the Model Context Protocol (MCP)** | standards.md identifies MCP as the strong fit: each integrated tool is exposed as an MCP server, giving the reasoning agent a uniform, discoverable tool interface. Prompt caching reduces cost on repeated system prompts. The agent emits a structured reasoning chain persisted as JSONB (the auditability differentiator). |
| Connector model | **OpenAPI 3.1 → generated connector** (Shuffle pattern) + **MCP server wrapper** per tool | OpenAPI import auto-generates HTTP actions; an MCP adapter exposes those actions to the agent. A Python SDK lets users hand-write connectors when no OpenAPI spec exists. |
| Frontend | **Next.js 15 (App Router) + React + TypeScript + shadcn/ui + Tailwind** | The analyst workflow is the make-or-break UX (research.md "analyst buy-in"). A web dashboard with incident queue, case timeline, visual workflow editor (React Flow), and War Room chat. Real-time via WebSocket. Separate from the Python API (clean API boundary). |
| Visual workflow editor | **React Flow (xyflow)** | Node-based canvas with branching/loops matches the Shuffle/Splunk block-canvas UX pattern; serialises to the internal workflow JSON / CACAO. |
| Real-time | **WebSocket (FastAPI) + Redis pub/sub** | Live case-timeline updates and War Room chat (RFC 6455 cited in standards.md). |
| Threat intel | **`stix2`, `taxii2-client`, `pymisp`** | Native STIX 2.1 parse/serialise, TAXII 2.1 polling, MISP sync — all standards from standards.md. |
| Secrets / credential encryption | **Envelope encryption with `cryptography` (AES-GCM) + KMS-pluggable master key**; pgcrypto fallback | Integration credentials stored as `BYTEA` encrypted at rest (data model requirement). KMS abstraction supports AWS KMS / Vault for self-hosted and managed modes. |
| AuthN / AuthZ | **OIDC + SAML 2.0 SSO (Authlib), SCIM 2.0 provisioning, JWT sessions, RBAC** | Enterprise/regulated SSO is table-stakes (standards.md). RBAC permissions stored as `TEXT[]` on roles; action-approval gates enforced server-side. |
| Containerisation | **Docker + docker-compose** (dev), **Helm chart** (production self-host) | Self-hosted/on-prem/private-cloud + managed deployment modes (README). Compose for local; Helm for k8s. |
| Testing | **pytest + pytest-asyncio + testcontainers** (Postgres/Redis), **Vitest + Playwright** (frontend) | Real Postgres/Redis in integration tests via testcontainers; mocked external tools for connector tests; Playwright for analyst-workflow E2E. |
| Code quality | **Ruff (lint+format), mypy (strict), bandit (security)** for Python; **ESLint + Prettier + tsc** for frontend | bandit aligns with OWASP ASVS hardening of the platform itself. |
| Package mgmt | **uv** (Python), **pnpm** (frontend) | Fast, lockfile-based, reproducible. |
| Output / wire formats | **OpenAPI 3.1, JSON Schema 2020-12, STIX 2.1, CACAO 2.0, OCSF, OpenC2 v1.0, CloudEvents 1.0** | Direct from standards.md; these are the interoperability layer the product differentiates on. |
| Audit log emission | **Internal `audit_logs` table + optional RFC 5424 syslog export to SIEM** | SOC 2 / ISO 27001 audit trail; syslog forwarding so the SOAR's own actions are observable in the customer SIEM. |

### Project Structure

```
soar/
├── pyproject.toml                  # uv-managed; deps, ruff, mypy, pytest config
├── docker-compose.yml              # postgres, redis, api, worker, beat, frontend
├── Dockerfile.api
├── Dockerfile.worker
├── alembic.ini
├── deploy/
│   └── helm/                       # production k8s chart
├── migrations/                     # Alembic versions
├── src/soar/
│   ├── main.py                     # FastAPI app factory, router mounting
│   ├── config.py                   # Pydantic Settings (env-driven)
│   ├── db/
│   │   ├── engine.py               # async engine, session, RLS context
│   │   ├── base.py                 # declarative base, mixins (tenant, timestamps)
│   │   └── models/                 # SQLAlchemy models (incidents, observables, ...)
│   ├── schemas/                    # Pydantic request/response + JSON Schema defs
│   ├── api/
│   │   ├── deps.py                 # auth, tenant, RBAC dependencies
│   │   └── routes/                 # incidents, cases, observables, playbooks,
│   │                               #   integrations, intel, alerts, auth, ws, ai
│   ├── domain/                     # business logic (services, no framework deps)
│   │   ├── incidents/
│   │   ├── cases/
│   │   ├── observables/
│   │   ├── intel/                  # STIX/TAXII/MISP ingestion + enrichment
│   │   ├── mitre/                  # ATT&CK loader, mapping, coverage
│   │   ├── playbooks/              # parser, validator, DAG executor
│   │   ├── integrations/          # OpenAPI loader, connector runtime, health
│   │   └── ai/                     # agent, MCP host, reasoning-chain store, prompts
│   ├── connectors/
│   │   ├── base.py                 # Connector SDK interface
│   │   ├── openapi_loader.py       # OpenAPI 3.1 → action set
│   │   ├── mcp/                    # MCP server wrappers per tool
│   │   └── builtin/                # hand-written connectors (Slack, Jira, VT, ...)
│   ├── tasks/                      # Celery tasks (enrich, poll_feed, run_playbook)
│   ├── workers/                    # Celery app, beat schedule
│   ├── auth/                       # OIDC, SAML, SCIM, JWT, RBAC engine
│   ├── audit/                      # audit writer + syslog exporter
│   └── realtime/                   # WS manager + Redis pub/sub bridge
├── tests/
│   ├── unit/
│   ├── integration/                # testcontainers Postgres/Redis
│   ├── e2e/
│   └── fixtures/                   # sample OCSF alerts, STIX bundles, CACAO playbooks
└── frontend/
    ├── package.json
    ├── app/                        # Next.js App Router pages
    ├── components/                 # shadcn/ui + custom (timeline, queue, war-room)
    ├── features/
    │   ├── incidents/
    │   ├── workflow-editor/        # React Flow canvas
    │   └── war-room/
    ├── lib/api/                    # typed client generated from OpenAPI
    └── tests/                      # Vitest + Playwright
```

---

## Phase 1: Foundation — Project Skeleton, Data Layer, Multi-Tenancy

### Purpose
Establish the runnable backbone: configuration, the PostgreSQL data layer with the hybrid relational+JSONB schema, RLS-based multi-tenancy, the FastAPI app, Celery/Redis wiring, and Docker. After this phase the app boots, migrations apply, and a health endpoint responds — every later phase adds routes and domain logic onto this skeleton without restructuring.

### Tasks

#### 1.1 — Project scaffold, config, and container stack

**What**: Create the repo skeleton, `pyproject.toml`, Pydantic settings, and a docker-compose stack (postgres, redis, api, worker, beat, frontend).

**Design**:
```python
# src/soar/config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    environment: str = "development"           # development | production
    database_url: str                          # postgresql+asyncpg://...
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str
    jwt_ttl_seconds: int = 3600
    master_encryption_key: str                 # base64 32-byte AES-GCM key (or KMS ref)
    anthropic_api_key: str | None = None
    llm_model: str = "claude-opus-4-8"
    deployment_mode: str = "self_hosted"       # self_hosted | managed | hybrid
    audit_syslog_url: str | None = None        # RFC 5424 target, optional
    class Config: env_prefix = "SOAR_"

settings = Settings()
```
- `docker-compose.yml` services: `postgres:16`, `redis:7`, `api` (uvicorn), `worker` (celery), `beat` (celery beat), `frontend` (next dev).
- `Dockerfile.api` / `Dockerfile.worker` multi-stage with `uv` install.
- FastAPI app factory in `main.py` mounts `/api/v1` routers and a `/healthz` endpoint returning `{"status":"ok","db":bool,"redis":bool}`.

**Testing**:
- `Unit: Settings loads from env with SOAR_ prefix → defaults applied for unset optionals`
- `Unit: Settings missing required database_url → ValidationError naming the field`
- `Integration (testcontainers): GET /healthz with live pg+redis → 200, db=true, redis=true`
- `Integration: GET /healthz with redis down → 200, redis=false (degraded, not crash)`

#### 1.2 — Database engine, base models, RLS multi-tenancy

**What**: Async SQLAlchemy engine, declarative base with shared mixins, and a request-scoped tenant context that sets the Postgres RLS `app.current_tenant` GUC.

**Design**:
```python
# src/soar/db/base.py
class TenantMixin:
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(),
                                                 onupdate=func.now())
```
- Every tenant-scoped table gets an RLS policy:
```sql
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON incidents
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
```
- `db/engine.py` exposes `get_session()` dependency that runs `SET LOCAL app.current_tenant = :tid` at transaction start from the authenticated tenant.

**Testing**:
- `Integration (testcontainers): insert incident for tenant A, query as tenant B → 0 rows (RLS enforced)`
- `Integration: session without tenant GUC set → query raises / returns empty (fail-closed)`
- `Unit: TimestampMixin sets created_at on insert, bumps updated_at on update`

#### 1.3 — Core schema migration (operational core)

**What**: Alembic migration creating `tenants`, `users`, `roles`, `user_roles`, `audit_logs` (partitioned), plus enums.

**Design**: DDL from data-model-suggestion-3 §"Core Entities" and §"Audit Log". `audit_logs` is `PARTITION BY RANGE (created_at)` with a helper that auto-creates monthly partitions (Celery beat job, see 1.4). Severity/status modelled as `CHECK` constraints (suggestion-3 style) rather than PG enums, to avoid migration friction when adding values.

**Testing**:
- `Integration: alembic upgrade head on empty db → all tables + RLS policies present`
- `Integration: alembic downgrade base → clean drop, no orphan objects`
- `Integration: insert audit_log for 2026-05 → lands in audit_logs_2026_05 partition`

#### 1.4 — Celery/Redis wiring + beat schedule

**What**: Celery app bound to Redis, a no-op `ping` task, and a beat schedule placeholder (partition maintenance, feed polling registered in later phases).

**Design**:
```python
# src/soar/workers/app.py
celery_app = Celery("soar", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.task_default_retry_delay = 30
celery_app.conf.task_acks_late = True

@celery_app.task(bind=True, max_retries=3)
def ping(self): return "pong"
```
- Beat job `ensure_monthly_partitions` creates next month's `audit_logs` partition.

**Testing**:
- `Integration: enqueue ping via Redis broker, worker consumes → result "pong"`
- `Integration: ensure_monthly_partitions for a month with no partition → partition created; idempotent on re-run`

### Definition of Done
Tables and RLS apply via Alembic; `/healthz` green with live pg+redis; Celery worker consumes a task; Ruff/mypy/bandit clean; `docker compose up` brings the full stack online.

---

## Phase 2: Identity, RBAC, and Audit

### Purpose
No SOAR action is acceptable without an actor and an audit record. This phase delivers authentication (JWT + OIDC/SAML SSO), SCIM provisioning, the RBAC engine with action-approval semantics, and the audit-log writer with optional syslog export. Every later mutating endpoint depends on the `current_user`, `require_permission`, and `audit()` primitives built here.

### Tasks

#### 2.1 — JWT sessions + OIDC/SAML SSO + SCIM

**What**: Login via local credentials (bootstrap admin), OIDC, and SAML 2.0; SCIM 2.0 endpoints for user/role provisioning; JWT issuance and validation.

**Design**:
- `POST /api/v1/auth/login` → `{access_token, expires_in}` (JWT, RFC 7519; claims `sub`, `tenant_id`, `roles`).
- OIDC via Authlib: `/auth/oidc/login` → redirect; `/auth/oidc/callback` → mint JWT.
- SAML 2.0 ACS endpoint `/auth/saml/acs`.
- SCIM: `GET/POST/PATCH/DELETE /scim/v2/Users` and `/scim/v2/Groups` (RFC 7644).
```python
# src/soar/api/deps.py
async def current_user(token: str = Depends(bearer)) -> AuthContext: ...
def require_permission(perm: str) -> Callable: ...  # FastAPI dependency factory
```

**Testing**:
- `Unit: valid JWT → AuthContext with tenant_id and roles`
- `Unit: expired JWT → 401`
- `Integration (mocked OIDC): callback with valid code → JWT minted, user upserted`
- `Integration: SCIM POST /Users → user created in correct tenant; duplicate email → 409`

#### 2.2 — RBAC engine + action-approval gates

**What**: Permission checks from role `permissions[]`, plus a two-person approval primitive for sensitive actions (e.g. `containment.execute`).

**Design**:
- Permission strings: `incident.read`, `incident.write`, `playbook.execute`, `containment.execute`, `integration.manage`, `intel.manage`, `admin.*`.
- `require_permission("incident.write")` raises 403 if absent.
- `approvals` table: action needing approval inserts a pending `approval_request`; a second authorised user approves before the action commits.

**Testing**:
- `Unit: user with [incident.read] hitting incident.write endpoint → 403`
- `Unit: wildcard admin.* grants incident.write`
- `Integration: containment action by single user → 202 pending_approval; second approver → executed`

#### 2.3 — Audit writer + RFC 5424 syslog export

**What**: `audit(action, entity_type, entity_id, changes)` helper writing to `audit_logs`, plus optional syslog forwarding.

**Design**:
```python
async def audit(session, ctx: AuthContext, action: str, entity_type: str,
                entity_id: UUID | None, changes: dict | None = None): ...
```
- `changes` JSONB = `{"field": {"old": X, "new": Y}}`.
- If `settings.audit_syslog_url` set, emit RFC 5424 structured-data line to the SIEM.

**Testing**:
- `Unit: audit() with changes dict → row with JSONB changes, request_context (ip, ua)`
- `Integration: closing an incident writes an audit row action="incident.closed"`
- `Integration (mocked syslog): audit with syslog configured → RFC 5424 message sent`

### Definition of Done
SSO login works against a mocked IdP; RBAC blocks unauthorised calls; approval gate enforces two-person rule; every mutation in this and later phases produces an audit row; tests green; OWASP API Top-10 checks (authz on every route) covered by a route-coverage test.

---

## Phase 3: Incident & Case Management Core

### Purpose
This is the heart of the analyst experience and ships early. It delivers the incident lifecycle (NIST SP 800-61 phases), observables with sightings, the incident timeline, tasks/assignments, evidence, comments, cases grouping incidents, and SLA tracking. After this phase an analyst can run the full triage→containment→post-incident loop manually through the API.

### Tasks

#### 3.1 — Incident schema, lifecycle state machine, and CRUD

**What**: `incidents` table (hybrid columns + JSONB per suggestion-3), a status state machine, and CRUD endpoints.

**Design**:
- Schema: data-model-suggestion-3 §"Incidents" verbatim (relational core + `alert_payload`, `enrichments`, `ai_analysis`, `custom_fields`, `mitre_mappings`, `tags`, `related_refs` JSONB; GIN indexes).
- State machine (statuses → NIST phases):
```
new → triaging → investigating → containment → eradication → recovery → closed
                                                                    ↑        │
                                                              reopened ←──────┘
```
  Phase derived: `detection_analysis` (new/triaging/investigating), `containment_eradication_recovery` (containment/eradication/recovery), `post_incident` (closed).
- Endpoints: `POST/GET/PATCH /api/v1/incidents`, `POST /incidents/{id}/transition {to_status, reason}` (validates legal transitions, writes timeline + audit).

**Testing**:
- `Unit: transition new→investigating legal; new→recovery illegal → 422`
- `Unit: phase auto-derived from status`
- `Integration: PATCH incident severity → audit row + timeline event`
- `Integration: list incidents filtered by status+severity uses relational index`

#### 3.2 — Observables, sightings, cross-incident correlation

**What**: `observables` + `incident_observables` (suggestion-3), dedup on `(tenant,type,value)`, and a "seen in other incidents" query.

**Design**:
- `observables` with `enrichment_data` and `stix_object` JSONB, GIN-indexed.
- `POST /incidents/{id}/observables` upserts the observable and links it (`is_ioc`, `context`).
- `GET /observables/{id}/correlations` → other incidents sharing this observable (relational self-join now; documented as the natural Apache AGE graph-query upgrade).

**Testing**:
- `Unit: same (type,value) added twice → single observable, two links`
- `Integration: observable in 3 incidents → correlations returns the other 2`
- `Unit: observable_type validated against the enum set`

#### 3.3 — Timeline, tasks, evidence, comments

**What**: `timeline_events` (relational envelope + JSONB `details`), `incident_tasks` with assignments, evidence attachments, comments.

**Design**:
- Timeline write helper appends events on every state change/enrichment/AI step (`event_type`, `actor_type` ∈ user|system|playbook|ai_agent).
- Tasks: status `pending|in_progress|completed`, `assignee_id`, `due_at`, `sort_order`.
- Evidence: object-storage reference + ISO/IEC 27037 chain-of-custody fields (`collected_by`, `collected_at`, `hash_sha256`).

**Testing**:
- `Integration: status change appends timeline event with correct actor_type`
- `Unit: evidence requires sha256; missing → 422`
- `Integration: timeline returns events ordered by occurred_at`

#### 3.4 — Cases, case-incident grouping, SLA tracking

**What**: `cases`, `case_incidents`, `sla_tracking`; SLA breach detection job.

**Design**:
- SLA policy per severity (e.g. critical=1h response). On incident create, compute `sla_deadline`; a Celery beat job flags breaches and writes timeline/audit.
- `POST /cases`, `POST /cases/{id}/incidents`, `GET /cases/{id}` (incidents + rollup status).

**Testing**:
- `Integration: critical incident → sla_deadline = created_at + 1h`
- `Integration: beat job past deadline, unresolved → breach recorded`
- `Unit: case rollup status = highest open incident severity`

### Definition of Done
Full manual incident lifecycle works via API; observables correlate; timeline reflects all actions; cases group incidents; SLA breaches fire; all mutations audited; tests green.

---

## Phase 4: Threat Intelligence & MITRE ATT&CK

### Purpose
Transforms raw observables into contextualised intelligence. Delivers STIX 2.1 / TAXII 2.1 ingestion, MISP sync, observable enrichment from external sources (VirusTotal, Shodan, GeoIP, NVD), the MITRE ATT&CK knowledge base, and incident→technique mapping with coverage analysis. This is what makes an alert actionable.

### Tasks

#### 4.1 — MITRE ATT&CK loader, tagging, coverage

**What**: Load ATT&CK (STIX bundle) into `mitre_techniques`/tactics; map techniques to incidents; coverage view.

**Design**:
- `mitreattack-python` loads the enterprise ATT&CK STIX bundle on first boot / refresh; populates techniques (`T1566.001`), tactics, sub-technique links.
- Mappings live in `incidents.mitre_mappings` JSONB `[{technique_id, tactic, confidence, mapped_by}]` (suggestion-3), GIN-indexed.
- `GET /mitre/coverage?tenant` → per-technique incident counts (ATT&CK navigator-compatible JSON layer export).

**Testing**:
- `Integration: load bundle → techniques+tactics populated, sub-techniques linked`
- `Unit: map technique to incident with confidence/mapped_by → JSONB updated, GIN-queryable`
- `Integration: coverage export is valid ATT&CK Navigator layer JSON`

#### 4.2 — STIX 2.1 / TAXII 2.1 ingestion + MISP sync

**What**: `threat_intel_feeds` + `threat_indicators` (suggestion-3, `stix_data` JSONB); polling tasks for TAXII and MISP.

**Design**:
- Feed types: `stix_taxii`, `misp`, `csv`, `custom`. Celery beat polls each feed at its `polling_interval_seconds`.
- TAXII via `taxii2-client`, parse with `stix2`; MISP via `pymisp`. Store full STIX object in `stix_data`; project `value`,`indicator_type`,`confidence`,`valid_from/until` to columns.
- Indicator→observable match marks `incident_observables.is_ioc=true` and appends a timeline event.

**Testing**:
- `Integration (mocked TAXII): poll returns 3 indicators → 3 threat_indicators rows with full stix_data`
- `Integration: ingested indicator matches existing observable → incident flagged IOC + timeline event`
- `Unit: malformed STIX object → skipped, error logged, poll continues`

#### 4.3 — Observable enrichment framework

**What**: Pluggable enrichers (VirusTotal, Shodan, GeoIP, NVD/CVE) writing into `observables.enrichment_data` JSONB.

**Design**:
```python
class Enricher(Protocol):
    name: str
    supported_types: set[str]
    async def enrich(self, observable: Observable) -> dict: ...
```
- `enrich_observable` Celery task fans out to all enrichers supporting the type; results merged under `enrichment_data[source]`; rate-limited per provider.
- Triggered on observable attach and on demand (`POST /observables/{id}/enrich`).

**Testing**:
- `Integration (mocked VT): IP observable → enrichment_data.virustotal populated`
- `Unit: enricher whose supported_types excludes the type is skipped`
- `Integration: provider 429 → task retried with backoff, partial results preserved`

### Definition of Done
ATT&CK loaded and mappable; TAXII/MISP feeds poll and ingest; indicators auto-match observables; enrichment populates JSONB and timeline; coverage export valid; tests green.

---

## Phase 5: Integration & Connector Framework

### Purpose
A SOAR is only as useful as its connectors. This phase builds the connector runtime: OpenAPI 3.1 auto-generation (Shuffle pattern), a Python connector SDK, encrypted credential storage, the action-execution engine, and connector health checks. It seeds 5-10 priority connectors (Slack, Jira, VirusTotal, Splunk, Sentinel, CrowdStrike, Okta, AWS) toward the 30-50 MVP target.

### Tasks

#### 5.1 — Integrations, encrypted credentials, capability registry

**What**: `integrations`, `integration_credentials` (envelope-encrypted), capability list.

**Design**:
- Credential write: AES-GCM envelope encryption; master key from `settings.master_encryption_key` or KMS; ciphertext in `credentials_enc BYTEA`; supports rotation (`rotated_at`).
- Auth types: `api_key`, `oauth2`, `basic`, `mtls` (RFC 8705).
- `integrations.capabilities` JSONB lists actions (name, input/output JSON Schema).

**Testing**:
- `Unit: store+retrieve credential → round-trips; ciphertext never equals plaintext`
- `Unit: rotate credential → new ciphertext, rotated_at set, old undecryptable with new key only if key unchanged`
- `Integration: list integrations scoped by tenant (RLS)`

#### 5.2 — OpenAPI 3.1 connector auto-generation + SDK

**What**: Import an OpenAPI 3.1 spec → derive an action set; a Python SDK base class for hand-written connectors.

**Design**:
```python
class Connector(ABC):
    name: str
    @abstractmethod
    async def execute(self, action: str, params: dict, creds: Creds) -> ActionResult: ...
```
- `openapi_loader.py` parses spec, generates `integration_actions` (method, path, request/response JSON Schema). Generic HTTP action executes by binding params to the path/query/body per spec.
- `POST /integrations/import-openapi {spec_url|spec}` → integration + actions created.

**Testing**:
- `Integration: import a sample OpenAPI 3.1 spec → actions generated with correct method/path/schemas`
- `Unit: param missing required field → 422 against generated request schema`
- `Integration (mocked HTTP): execute generated GET action → response validated against response schema`

#### 5.3 — Action execution engine + connector health

**What**: Uniform `execute_action(integration, action, params)` with retry/timeout, plus periodic health checks.

**Design**:
- Execution wraps connector call with timeout, retry/backoff, structured `ActionResult{status, output, error, duration_ms}`; every execution audited.
- Health check task pings each integration; updates `health_status` (`healthy|degraded|down`) and `last_health_check`. (Foundation for v1.1 self-healing.)

**Testing**:
- `Integration (mocked): successful action → ActionResult.status=ok, audited`
- `Integration: action timeout → status=error, retried per policy`
- `Integration: health check on unreachable integration → health_status=down`

#### 5.4 — Seed builtin connectors

**What**: Hand-written connectors: Slack, Jira, VirusTotal, Splunk, Microsoft Sentinel, CrowdStrike, Okta, AWS — each with read (query) and at least one write (containment/ticket) action.

**Design**: Each subclasses `Connector`; actions map to vendor REST APIs (auth per standards.md table). Containment actions require `containment.execute` permission + approval gate (Phase 2).

**Testing**:
- `Integration (mocked vendor API): Jira create-ticket → ticket id returned, linked to incident.related_refs`
- `Integration (mocked): CrowdStrike isolate-host requires approval → pending until approved`
- `Unit: each builtin connector declares capabilities with valid JSON Schemas`

### Definition of Done
Credentials encrypted/rotated; OpenAPI import generates working actions; SDK connector executes; health checks run; 8 seed connectors pass mocked-API tests; containment actions gated; tests green.

---

## Phase 6: Playbook & Workflow Engine

### Purpose
Delivers deterministic automation: a CACAO 2.0-compatible playbook model, a DAG executor supporting branching, loops, parallel steps, sub-workflows, and human gates, plus triggers (manual, alert, schedule, webhook). This is the "Orchestration & Automation" pillar and the canvas the frontend editor will drive.

### Tasks

#### 6.1 — Playbook model, CACAO 2.0 parser/validator

**What**: `playbook_definitions` + `playbook_versions` (suggestion-3, `workflow` JSONB = CACAO 2.0); parse/validate workflows.

**Design**:
- `workflow` JSONB stores CACAO 2.0 (`type:playbook`, `workflow:{step-id:{type,...}}`, `workflow_start`). Step types: `action`, `decision`, `parallel`, `loop`, `sub_workflow`, `human_gate` (mapped to CACAO action/if-condition/parallel/while-condition/playbook-action/manual steps).
- Validator: JSON Schema (CACAO) + graph checks (reachability, no orphan, decision branches resolve, sub-workflow refs exist).

**Testing**:
- `Unit: valid CACAO playbook → parsed graph, workflow_start resolved`
- `Unit: decision step with dangling branch → validation error naming the step`
- `Unit: cyclic non-loop graph → validation error`

#### 6.2 — DAG execution engine (Celery)

**What**: Resumable executor walking the graph; `playbook_executions` with `step_results` JSONB + `execution_context` (suggestion-3).

**Design**:
- Each step runs as a Celery task; output merged into `execution_context` (available to later steps via templating, e.g. `{{ steps.step-1.output.ip }}`).
- Decision evaluates `condition_expr` against context; loop iterates over a context list with max-iteration guard; parallel fans out and joins; human_gate creates an approval and pauses (resumes on approval).
- Status: `running|paused|completed|failed|cancelled`; per-step `pending|running|completed|failed|skipped`.

**Testing**:
- `Integration: linear 3-step playbook (mocked actions) → all completed, ordered step_results`
- `Integration: decision routes to branch B when condition true`
- `Integration: human_gate pauses; approval resumes to completion`
- `Integration: step failure → execution failed, downstream skipped, timeline event`
- `Integration: loop over 3 items → action runs 3×; exceeds max-iter → fails safe`

#### 6.3 — Triggers (manual, alert, schedule, webhook)

**What**: Bind playbooks to triggers; alert/webhook ingestion into `alert_inbox`; auto-run on match.

**Design**:
- `alert_inbox` (suggestion-3): inbound alerts normalised to OCSF, `triage_status` lifecycle. Webhook endpoint validates CloudEvents 1.0 envelope + HMAC signature.
- Trigger matcher: alert attributes → matching playbooks → enqueue execution bound to a promoted incident.
- Schedule triggers via Celery beat.

**Testing**:
- `Integration (mocked): signed webhook → alert_inbox row, matching playbook enqueued, 200`
- `Integration: webhook bad signature → 401, no enqueue`
- `Unit: OCSF normalisation maps vendor alert fields to OCSF event`

### Definition of Done
CACAO playbooks parse/validate; executor handles all step types incl. human gates; triggers fire executions; webhook ingestion secure and OCSF-normalised; execution state resumable; tests green.

---

## Phase 7: Agentic AI Investigation (the AI-Native Differentiator)

### Purpose
Delivers the core differentiator: an LLM reasoning agent that investigates alerts using MCP-wrapped tools, assembles evidence, forms hypotheses, maps to ATT&CK, and recommends actions — emitting an exportable, auditable reasoning chain. This is what regulated-industry buyers cannot get from opaque incumbents (Prophet, Radiant).

### Tasks

#### 7.1 — MCP host + tool wrappers over connectors

**What**: Expose each connector action and read API (incidents, observables, intel, ATT&CK) as MCP tools the agent can call.

**Design**:
- `connectors/mcp/` wraps the action engine (Phase 5) and read services as MCP tools with discoverable schemas. Write/containment tools require human approval (surfaced as a tool that returns "approval pending").
- MCP host manages tool registry per tenant + RBAC (agent inherits a constrained service role).

**Testing**:
- `Integration: agent lists MCP tools → only tenant-permitted tools exposed`
- `Integration (mocked connector): agent invokes query_siem tool → result returned`
- `Integration: agent invokes containment tool → returns approval-pending, no execution`

#### 7.2 — Investigation agent + reasoning-chain persistence

**What**: `ai_investigation_sessions` (suggestion-3); agent loop that triages an incident and persists every step.

**Design**:
- Agent loop (Anthropic SDK, prompt caching on the system prompt): given incident + observables, iteratively calls MCP tools, recording each as a reasoning step `{step, action, input, finding, timestamp}` in `reasoning_chain` JSONB; concludes with `verdict ∈ {true_positive,false_positive,needs_review}`, `confidence`, `recommendations[]`, mapped `mitre_techniques`. `token_usage` tracked.
- System prompt template (stored, versioned): role = SOC analyst; constraints = cite evidence for every claim, never execute containment without approval, output structured verdict. Each reasoning step also appended to the incident timeline (`actor_type=ai_agent`).

**Testing**:
- `Integration (mocked LLM + tools): investigation → reasoning_chain has ≥1 step per tool call, verdict+confidence set`
- `Unit: reasoning chain export → JSON conforms to documented schema (auditable)`
- `Integration: agent attempting containment without approval → step records blocked action`
- `Integration: timeline shows ai_agent-authored events for each step`

#### 7.3 — AI assists: NL-to-workflow, summarisation, suggested-next-steps, auto-ATT&CK

**What**: Natural-language→CACAO playbook draft; incident/handover/exec summaries; suggested next steps from similar historical incidents; auto-map alerts to ATT&CK.

**Design**:
- `POST /ai/nl-to-workflow {prompt}` → draft CACAO `workflow` JSON (validated by 6.1 before save).
- `POST /incidents/{id}/summarize {audience: handover|exec}` → markdown summary.
- Suggested next steps: retrieve similar closed incidents by shared observables/techniques, prompt LLM for ranked actions.
- Auto-ATT&CK: classify alert text → technique IDs with confidence, written via 4.1.

**Testing**:
- `Integration (mocked LLM): NL prompt → valid CACAO workflow passing the 6.1 validator`
- `Integration: summarize handover → non-empty markdown referencing incident facts`
- `Integration: auto-ATT&CK on phishing alert → suggests T1566.* with confidence`

### Definition of Done
Agent investigates with MCP tools and produces an exportable, auditable reasoning chain persisted as JSONB + timeline; containment always gated; NL-to-workflow yields valid playbooks; summaries and ATT&CK mapping work; token usage tracked; tests green.

---

## Phase 8: Frontend — Analyst Console

### Purpose
Analyst buy-in is the documented adoption risk. This phase delivers the web console: incident queue, incident detail with timeline, observable/enrichment views, the visual workflow editor, and AI verdict review — the surfaces that make the platform usable day-to-day.

### Tasks

#### 8.1 — App shell, auth, typed API client

**What**: Next.js App Router shell, SSO login, RBAC-aware navigation, OpenAPI-generated typed client.

**Design**: shadcn/ui layout; client generated from the FastAPI OpenAPI 3.1 spec (`lib/api`); route guards by permission; session via httpOnly cookie wrapping the JWT.

**Testing**:
- `E2E (Playwright): login via mocked OIDC → dashboard renders, nav reflects roles`
- `Unit (Vitest): permission-guarded nav item hidden without permission`

#### 8.2 — Incident queue + detail + timeline

**What**: Filterable/sortable incident queue; detail view with timeline, observables+enrichment, tasks, evidence, comments, MITRE chips; transition controls.

**Design**: Server components for list (SLA/severity/status filters mapping to relational indexes); detail streams timeline; WebSocket subscription updates timeline live.

**Testing**:
- `E2E: open incident, change status → timeline updates without reload (WS)`
- `E2E: add observable → appears with enrichment once task completes`
- `Unit: queue filter by severity calls API with correct params`

#### 8.3 — Visual workflow editor (React Flow)

**What**: Node-based canvas to build/edit playbooks; serialises to CACAO `workflow` JSON; inline action config + JSON-path picker.

**Design**: React Flow nodes per step type (action/decision/parallel/loop/sub_workflow/human_gate); save posts workflow validated by 6.1; live run trace highlights executing steps via WS.

**Testing**:
- `E2E: drag two action nodes + connect → save → backend stores valid CACAO`
- `E2E: run playbook from editor → nodes highlight as steps complete`
- `Unit: invalid graph (dangling branch) → save blocked with inline error`

#### 8.4 — AI verdict review + reasoning-chain viewer

**What**: Surface AI verdict, confidence, recommendations; expandable reasoning chain; human-in-the-loop confirm/deny for recommended containment.

**Design**: Reasoning chain rendered step-by-step with evidence links to observables/incidents; "Apply recommendation" triggers gated action (approval flow).

**Testing**:
- `E2E: incident with AI session → verdict + reasoning chain render; export downloads JSON`
- `E2E: apply containment recommendation → approval prompt shown`

### Definition of Done
Analyst can authenticate, triage incidents, view live timelines, build/run playbooks visually, and review AI reasoning end-to-end; Playwright E2E green; tsc/ESLint clean.

---

## Phase 9: ChatOps War Room & Real-Time Collaboration

### Purpose
Adds collaborative response surfaces: in-app War Room chat per incident with live timeline, plus bidirectional Slack and Microsoft Teams integration so analysts act without leaving chat. Includes shift-handover support.

### Tasks

#### 9.1 — In-app War Room (WebSocket)

**What**: Per-incident chat channel with presence, message history, and embedded timeline events.

**Design**: WS rooms keyed by incident id; Redis pub/sub fan-out across API replicas; messages persisted (`war_room_messages` table, JSONB attachments). Activity Streams 2.0 vocabulary for event modelling (standards.md).

**Testing**:
- `Integration: two WS clients in a room → message broadcast to both`
- `Integration: timeline event auto-posts into the room`

#### 9.2 — Slack & Teams bidirectional integration

**What**: Mirror War Room to Slack/Teams; interactive buttons execute gated actions back in the platform.

**Design**: Slack Events API + interactive components; Teams bot. Outbound: incident created/escalated → channel post. Inbound: button click → action (approval-gated) → result posted back.

**Testing**:
- `Integration (mocked Slack): incident escalation → channel message posted`
- `Integration (mocked Slack): "Block IP" button → approval flow → result echoed to channel`

#### 9.3 — Shift handover

**What**: AI-generated handover summary (Phase 7.3) packaged with open incidents/tasks for the next shift.

**Design**: `POST /handovers {shift}` → summary + open-item snapshot; delivered in-app and to chat.

**Testing**:
- `Integration: handover for tenant → summary references current open incidents`

### Definition of Done
In-app War Room real-time; Slack/Teams two-way with gated actions; handover summaries generated and delivered; tests green.

---

## Phase 10: Git-Versioned Playbooks, OpenC2, Reporting & Hardening

### Purpose
Closes the v1.1 scope and production-readiness: Git-backed playbook versioning with diff/PR review, OpenC2 v1.0 command-and-control output, MTTD/MTTR/workload dashboards, and a security/compliance hardening pass (OWASP API Top-10, ASVS, syslog audit export verified).

### Tasks

#### 10.1 — Git-versioned playbooks (branch/diff/PR)

**What**: Store playbook definitions in a Git repo; expose branch, diff, and PR-review workflow; CI hook to validate playbooks.

**Design**: On publish, serialise CACAO JSON to the configured Git repo (`git_repo_url`, `git_branch`, `git_commit_sha` already on the model); diff endpoint compares versions; PR review maps to `playbook_versions` + approval (Phase 2). CI: validate (6.1) on PR.

**Testing**:
- `Integration: publish playbook → commit created; diff two versions → structural diff returned`
- `Integration: PR with invalid playbook → CI validation fails`

#### 10.2 — OpenC2 v1.0 command-and-control

**What**: Emit standardised OpenC2 commands for containment actions where the target supports OpenC2.

**Design**: Map internal containment actions (block_ip, isolate_host) to OpenC2 command JSON (`action`,`target`,`args`); send to OpenC2-capable actuators; record response.

**Testing**:
- `Unit: block_ip → valid OpenC2 command JSON`
- `Integration (mocked actuator): OpenC2 command → response recorded on incident`

#### 10.3 — Reporting dashboards (MTTD/MTTR/workload/coverage)

**What**: Metrics endpoints + dashboard: MTTD, MTTR, analyst workload, ATT&CK coverage heatmap.

**Design**: Aggregate queries over incidents/timeline (read-replica-friendly); coverage from 4.1; workload from task/assignment data. Cached via Redis with short TTL.

**Testing**:
- `Integration: MTTR over closed incidents computed correctly against fixtures`
- `Unit: workload rollup counts open vs overdue tasks per analyst`

#### 10.4 — Security hardening + compliance pass

**What**: OWASP API Top-10 and ASVS review; rate limiting; route-level authz coverage test; verified RFC 5424 syslog export; secrets handling audit.

**Design**: Enforce authz on every route (automated test enumerating routes); per-tenant + per-IP rate limits; bandit clean; dependency scan in CI; confirm credential encryption + RLS under adversarial tests.

**Testing**:
- `Integration: every mutating route without auth → 401/403 (route-coverage test)`
- `Integration: cross-tenant access attempts → denied (RLS + authz)`
- `Integration: rate-limit exceeded → 429`
- `Security: bandit + dependency audit clean in CI`

### Definition of Done
Playbooks Git-versioned with diff/PR + CI validation; OpenC2 commands emitted/validated; dashboards report MTTD/MTTR/workload/coverage; OWASP/ASVS hardening verified; tests green; Helm chart deploys the full stack.

---

## Phase Summary & Dependencies

```
Phase 1: Foundation (data layer, RLS, Celery, Docker)   ─── required by everything
    │
Phase 2: Identity, RBAC, Audit                          ─── requires 1
    │
Phase 3: Incident & Case Management Core                ─── requires 2
    │
    ├── Phase 4: Threat Intel & MITRE ATT&CK             ─── requires 3
    │
    └── Phase 5: Integration & Connector Framework       ─── requires 2 (3 for linking)
             │
        ┌────┴───────────────────────────────────────┐
        │                                             │
   Phase 6: Playbook & Workflow Engine          (uses 4,5)
        │                                             │
   Phase 7: Agentic AI Investigation            ─── requires 4, 5 (MCP over connectors)
        │
   Phase 8: Frontend — Analyst Console          ─── requires 3 (4–7 enrich it)
        │
   Phase 9: ChatOps War Room & Real-Time         ─── requires 3, 5, 8
        │
   Phase 10: Git Playbooks, OpenC2, Reporting,   ─── requires 6, 7, 9
             Hardening
```

**Parallelism opportunities**
- **Phase 4** (Threat Intel/MITRE) and **Phase 5** (Connectors) can be built concurrently once Phase 3 lands — they share no code, only the data layer.
- **Phase 8** (Frontend) can begin against Phase 3 APIs and incrementally absorb Phases 4-7 as they ship; a frontend developer can work in parallel with backend integration/AI work.
- Within Phase 5, **builtin connectors (5.4)** can be parallelised across developers once the SDK/runtime (5.1-5.3) exist.

---

## Definition of Done (per phase)

Every phase must satisfy all of the following before it is considered complete:

1. All tasks implemented.
2. All unit and integration tests pass (`pytest`; frontend `vitest`/`playwright` where applicable).
3. Linting and formatting pass (Ruff for Python, ESLint/Prettier for frontend).
4. Type checking passes (mypy strict; `tsc` for frontend).
5. Security checks pass (bandit; dependency audit) — no new high/critical findings.
6. Docker build succeeds for `api` and `worker`; `docker compose up` runs the stack.
7. Feature works end-to-end (demonstrated by an integration or E2E test).
8. New config options documented in `.env.example` and README.
9. New/changed API endpoints appear in the auto-generated OpenAPI 3.1 spec, and the frontend typed client regenerates cleanly.
10. Alembic migration(s) created, reversible, and applied in CI; RLS policies present on any new tenant-scoped table.
11. Every new mutating action writes an audit-log row.
12. Standards adherence verified where the phase touches them (STIX 2.1 / TAXII 2.1 / CACAO 2.0 / OCSF / OpenC2 / MITRE ATT&CK / OpenAPI 3.1 / JSON Schema 2020-12).
```
