# Security Orchestration & Automation (SOAR) — Feature & Functionality Survey

> Candidate #413 · Researched: 2026-05-06

## Solutions Analysed

| Tool | Type | Licence / Model | URL |
|------|------|-----------------|-----|
| Splunk SOAR (formerly Phantom) | Commercial enterprise SOAR | Proprietary; subscription | https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html |
| Palo Alto Cortex XSOAR | Commercial enterprise SOAR | Proprietary; subscription. Community Edition free for limited use | https://www.paloaltonetworks.com/cortex/cortex-xsoar |
| Palo Alto Cortex XSIAM | Commercial AI-driven SecOps platform (SIEM+SOAR+XDR) | Proprietary; subscription | https://www.paloaltonetworks.com/cortex/cortex-xsiam |
| IBM QRadar SOAR (Resilient) | Commercial enterprise SOAR | Proprietary; subscription | https://www.ibm.com/products/qradar-soar |
| Fortinet FortiSOAR | Commercial mid-market SOAR | Proprietary; subscription | https://www.fortinet.com/products/fortisoar |
| Microsoft Sentinel (Logic Apps Playbooks) | Commercial cloud-native SIEM/SOAR | Proprietary; consumption-based | https://azure.microsoft.com/en-us/products/microsoft-sentinel |
| Tines | Commercial no-code automation (SOAR-adjacent) | Proprietary; subscription. Community Edition available | https://www.tines.com |
| Torq | Commercial hyperautomation for security | Proprietary; subscription | https://torq.io |
| Swimlane Turbine | Commercial low-code SOAR | Proprietary; subscription | https://swimlane.com |
| Shuffle | Open-source SOAR | AGPL-3.0 / commercial cloud | https://shuffler.io |
| TheHive + Cortex (StrangeBee) | Open-source / commercial case management + responder | AGPL-3.0 (TheHive 4) / proprietary (TheHive 5) | https://thehive-project.org |
| Prophet Security | Commercial agentic SOC | Proprietary; subscription | https://www.prophetsecurity.ai |

## Feature Analysis by Solution

### Splunk SOAR

**Core features**
- Visual playbook editor with Python code blocks
- 300+ integrations and 2,800+ automated actions
- Case management with collaboration and evidence tracking
- Built-in event ingestion from Splunk ES and external SIEMs
- Role-based access control with action approvals
- Reporting and SLA dashboards
- Indicator management and threat intel ingestion

**Differentiating features**
- Tight integration with Splunk Enterprise Security and the broader Splunk data platform
- Mission Control unified SOC workspace (post-Cisco acquisition)
- Mature community-shared apps repository

**UX patterns**
- Block-based visual playbook canvas with branching
- Workbook templates for SOPs (NIST IR phases)
- Investigation timelines with pinned artefacts

**Integration points**
- REST API, Python app SDK, Splunkbase ecosystem
- Webhooks, custom scripts, on-poll connectors

**Known gaps**
- Heavy infrastructure footprint vs. SaaS-native rivals
- Steep learning curve for playbook authoring
- Pricing perceived as high for mid-market

**Licence / IP notes**
- Proprietary; commercial subscription. Splunk apps may carry their own licences.

### Palo Alto Cortex XSOAR

**Core features**
- War Room collaboration with chatops and audit log
- 1,000+ content packs with playbooks and integrations
- Threat intel management module (TIM) with indicator scoring
- Incident classification, layouts, and dynamic forms
- Playbook debugger and test framework
- Multi-tenant architecture for MSSPs

**Differentiating features**
- Marketplace ecosystem with versioned content packs
- Integrated threat intel management with feed aggregation
- Native Slack/Teams chatops War Room

**UX patterns**
- Custom incident layouts per type
- Indicator relationship graph visualisation
- Inline playbook task instructions for analysts

**Integration points**
- REST API, Python integration SDK, demisto-sdk
- Marketplace content packs, custom widgets

**Known gaps**
- Complex licensing tiers
- Migration path being pushed toward XSIAM

**Licence / IP notes**
- Proprietary; Community Edition available for non-commercial use.

### Palo Alto Cortex XSIAM

**Core features**
- Unified data lake combining endpoint, network, identity, cloud
- AI-assisted playbook generation from incident patterns
- Automated alert grouping into incidents
- Built-in identity threat detection
- Behavioural analytics across telemetry

**Differentiating features**
- Single platform combining SIEM, SOAR, XDR, ITDR, ASM
- Generative AI playbook recommendations
- Auto-remediation rules without analyst-authored playbooks

**UX patterns**
- Incident-centric "story" view with prebuilt timelines
- Natural language query interface for investigation

**Integration points**
- REST API, XSOAR-compatible content packs
- Cortex Data Lake ingestion APIs

**Known gaps**
- High data ingestion cost
- Lock-in to Palo Alto data lake

**Licence / IP notes**
- Proprietary; subscription only.

### IBM QRadar SOAR

**Core features**
- Dynamic playbook designer (Q1 2025 release)
- Privacy breach module mapped to GDPR, HIPAA, CCPA
- Integration with QRadar SIEM and IBM Cloud Pak for Security
- Customisable case fields, layouts, and tasks
- Strong audit trail for regulated industries

**Differentiating features**
- Privacy/regulatory module with breach notification timelines
- Reported 85% reduction in incident response time with dynamic playbooks
- Open Cybersecurity Schema Framework (OCSF) alignment

**UX patterns**
- Phase-based incident workflow (NIST 800-61)
- Conditional task generation based on incident facts

**Integration points**
- REST API, Python integrations framework, App Host
- IBM Security Exchange marketplace

**Known gaps**
- UX considered dated relative to newer entrants
- Heavy on-prem deployment patterns

**Licence / IP notes**
- Proprietary; some integrations open-sourced under Apache 2.0.

### Fortinet FortiSOAR

**Core features**
- 600+ connectors with FortiGate-tight integration
- Visual playbook designer with subroutines
- Multi-tenant MSSP module
- Built-in threat intel management
- Asset and vulnerability correlation module

**Differentiating features**
- Deep integration across the Fortinet Security Fabric
- Recommendation engine for similar past incidents
- Built-in war rooms and shift handover support

**UX patterns**
- Module-based UI customisable per role
- Visual correlation graphs for assets and indicators

**Integration points**
- REST API, Python connector SDK
- FortiGate, FortiAnalyzer, FortiEDR native integration

**Known gaps**
- Best value when locked into Fortinet stack
- Smaller third-party connector marketplace than XSOAR/Splunk

**Licence / IP notes**
- Proprietary; subscription.

### Microsoft Sentinel (Logic Apps Playbooks)

**Core features**
- Cloud-native SIEM with KQL analytics
- Logic Apps-based playbooks (300+ connectors)
- Automation rules for alert grouping and assignment
- Workbooks for visualisation
- UEBA and Fusion ML correlation

**Differentiating features**
- Pay-per-GB cloud pricing
- Native Azure and Microsoft 365 telemetry
- Logic Apps share connectors with broader Azure ecosystem

**UX patterns**
- Incident-centric view in Microsoft Defender XDR portal
- Side-pane investigation graph

**Integration points**
- Logic Apps connectors, REST API, Microsoft Graph
- Sentinel content hub solutions

**Known gaps**
- Logic Apps less expressive than dedicated playbook engines
- Cost can spiral with high ingest volumes
- Best when Microsoft-centric

**Licence / IP notes**
- Proprietary; consumption pricing.

### Tines

**Core features**
- No-code story builder with drag-and-drop actions
- 500+ pre-built actions
- Cases module with collaboration
- Credential vaulting and tenant isolation
- AI mode for natural language story generation

**Differentiating features**
- No-code-first philosophy attractive to non-developers
- Stories shareable as templates within Tines Library
- Strong audit log and change review workflow

**UX patterns**
- Storyboard canvas with live runtime debugging
- Inline event JSON inspector

**Integration points**
- HTTP request action (universal); native event transforms
- Webhooks and email triggers

**Known gaps**
- Less prescriptive case management than dedicated SOAR
- Not a SIEM substitute

**Licence / IP notes**
- Proprietary; Community Edition free with feature caps.

### Torq

**Core features**
- Hyperautomation engine across security and IT use cases
- 300+ integrations with code-optional steps
- AI agents (HyperSOC) for autonomous triage
- Workflow versioning and approval gates
- Slack/Teams interactive case workflows

**Differentiating features**
- HyperSOC autonomous triage with LLM agents
- Branchless conditional workflows
- Generative workflow authoring from natural language

**UX patterns**
- Modular workflow steps with runtime trace
- Built-in user prompts via chat surfaces

**Integration points**
- REST API, generic HTTP, custom Python steps

**Known gaps**
- Newer entrant; smaller content marketplace
- Limited deep case management features

**Licence / IP notes**
- Proprietary; subscription.

### Swimlane Turbine

**Core features**
- Low-code playbook canvas with Python steps
- Active sensing framework (event-driven triggers)
- Case management with custom dashboards
- Hero AI for assisted authoring and summarisation
- High-throughput automation engine

**Differentiating features**
- Claims highest events-per-second throughput
- Hero AI playbook copilot
- Customisable record types beyond incidents

**UX patterns**
- Application-builder paradigm for case schemas
- Real-time playbook execution graph

**Integration points**
- REST API, Python SDK, generic HTTP

**Known gaps**
- Smaller installed base than top three vendors

**Licence / IP notes**
- Proprietary; subscription.

### Shuffle

**Core features**
- Visual workflow editor inspired by node-based tools
- 1,000+ open app integrations (auto-generated from OpenAPI)
- Multi-tenant cloud and on-prem deployment
- Triggers from email, webhooks, schedules
- Sub-workflows and forms

**Differentiating features**
- Fully open-source SOAR (AGPL-3.0)
- OpenAPI-driven auto app generation
- MSSP-friendly multi-tenant from the start

**UX patterns**
- Node-based workflow canvas
- Inline app testing and JSON path picker

**Integration points**
- OpenAPI imports, generic HTTP, custom Python apps

**Known gaps**
- Smaller community than commercial vendors
- Case management less mature than commercial SOARs
- Documentation thinner than enterprise alternatives

**Licence / IP notes**
- AGPL-3.0; commercial cloud and support tier available. AGPL has redistribution and network-use implications.

### TheHive + Cortex (StrangeBee)

**Core features**
- Case-centric incident management
- Observable-driven enrichment via Cortex analyzers (200+)
- Responders for containment actions
- MISP-native threat intel integration
- Customisable case templates with tasks

**Differentiating features**
- Case-first design rather than playbook-first
- Strong open-source community heritage and MISP alignment
- TheHive 4 remains AGPL-3.0; TheHive 5 is proprietary

**UX patterns**
- Kanban-style case board
- Observable graph with hits across cases

**Integration points**
- REST API, Cortex analyzer/responder Python SDK
- MISP synchronisation

**Known gaps**
- Lacks visual playbook orchestration (relies on external tools)
- TheHive 5 transition split community

**Licence / IP notes**
- TheHive 4: AGPL-3.0. TheHive 5: proprietary. Cortex remains AGPL-3.0. Verify version-specific licences.

### Prophet Security

**Core features**
- Autonomous AI SOC analyst that triages every alert
- LLM reasoning over alert context with evidence assembly
- Auto-generated investigation reports
- Outcome-based pricing model
- Integrations across SIEM, EDR, identity, cloud

**Differentiating features**
- Playbook-less operation; reasoning at runtime
- Per-alert decision audit trail with chain of reasoning
- Positions as SOAR-replacement, not complement

**UX patterns**
- Alert-centric review with AI verdict and rationale
- Human-in-the-loop confirmation for response actions

**Integration points**
- Read APIs into SIEM/EDR/identity tools
- Write APIs for containment actions (with approval)

**Known gaps**
- Limited transparency into model behaviour for regulated industries
- Newer entrant with smaller integration breadth than incumbents

**Licence / IP notes**
- Proprietary; subscription.

## Cross-Cutting Feature Themes

### Table-Stakes Features
- Visual playbook/workflow editor with branching and loops
- 100+ integrations with major SIEMs, EDRs, identity providers, ticketing, chatops
- Case management with timelines, evidence, assignments, SLA tracking
- Threat intel ingestion (STIX/TAXII, MISP) and indicator enrichment
- Role-based access control and action approval workflows
- Audit logs sufficient for SOC 2, ISO 27001, regulator review
- REST API and Python/JS SDK for custom integrations
- MITRE ATT&CK tagging on incidents and playbooks
- Reporting and dashboards (MTTD, MTTR, analyst workload)
- Multi-tenancy for MSSPs

### Differentiating Features
- Agentic AI investigation that operates without pre-authored playbooks
- Auto-generated playbooks from historical incident patterns
- OpenAPI-driven integration auto-generation (Shuffle pattern)
- Self-healing integrations that detect and patch broken connectors
- Natural language workflow authoring
- Outcome-based pricing tied to alerts triaged or incidents resolved
- Privacy/regulatory breach modules with notification deadlines (GDPR Art. 33, HIPAA, CCPA)
- ChatOps-native War Rooms with bidirectional Slack/Teams flows

### Underserved Areas / Opportunities
- High-quality open-source SOAR with modern UX (Shuffle is the main contender)
- Transparent, auditable agentic AI with exportable reasoning chains for regulators
- Lightweight SOAR for SMB/mid-market without enterprise pricing
- First-class playbook testing, version control, and CI/CD
- Cross-team incident response (security + IT + compliance) in one platform
- Native OCSF and OpenC2 support across vendors
- Plain-text playbook formats versioned in Git rather than proprietary blob storage

### AI-Augmentation Candidates
- Alert triage and false-positive suppression with explanation
- Automated incident summarisation for handovers and exec reports
- Natural language to playbook translation
- Anomaly detection on playbook execution metrics (drift, broken connectors)
- Threat hunting query generation from natural language
- Suggested next steps based on similar historical cases
- Auto-mapping of alerts to MITRE ATT&CK techniques
- Generation of post-incident review reports and lessons learned

## Legal & IP Summary

The SOAR space contains a mix of proprietary and open-source software. Commercial platforms (Splunk SOAR, Cortex XSOAR/XSIAM, QRadar SOAR, FortiSOAR, Sentinel, Tines, Torq, Swimlane, Prophet) are closed-source and require commercial licences for use; their connector content packs may carry separate licence terms (typically Apache 2.0 or MIT for community-shared content). On the open-source side, Shuffle is AGPL-3.0, TheHive 4 was AGPL-3.0 before TheHive 5 transitioned to a proprietary licence, and Cortex (StrangeBee) remains AGPL-3.0. AGPL-3.0 has network-use copyleft implications: a SaaS deployment derived from AGPL code must make source available to its users. Patents in the SOAR space typically cover specific UI/algorithmic mechanisms (e.g., Palo Alto's incident classification methods, IBM's case-management workflows) — a clean-room implementation following published behaviour and standards-based protocols (STIX/TAXII, OpenC2, OCSF, MITRE ATT&CK, all openly licensed) avoids most exposure. Reuse of vendor-specific integration content (XSOAR content packs, Splunk apps) requires checking each pack's individual licence header. No specific patent infringement risks were identified for a standards-based, clean-room AI-native SOAR; further IP review is recommended before commercial release.

## Recommended Feature Scope

**Must-have (MVP)**
- Visual workflow editor with branching, loops, and sub-workflows
- 30–50 priority integrations (Splunk, Sentinel, CrowdStrike, SentinelOne, Okta, Microsoft 365, Slack, Jira, MISP, VirusTotal, Shodan, AWS, GCP, Azure)
- Case management with timelines, observables, evidence, and tasks
- Threat intel enrichment via STIX/TAXII and MISP
- REST API, webhooks, and Python integration SDK
- RBAC, action approvals, and complete audit log
- MITRE ATT&CK tagging and coverage view

**Should-have (v1.1)**
- Agentic AI investigation copilot with exportable reasoning chains
- Natural-language to workflow generator
- Git-versioned playbooks with branch/diff/PR review
- ChatOps War Room (Slack and Teams) with two-way actions
- Multi-tenancy for MSSPs
- OCSF-compliant data normalisation across integrations
- OpenC2 command-and-control support

**Nice-to-have (backlog)**
- Self-healing integration framework that auto-detects schema drift
- Outcome-based pricing telemetry (alerts triaged, MTTR delta)
- Privacy/regulatory breach module with jurisdictional templates
- Marketplace for community-contributed workflows under permissive licences
- Auto-generated post-incident review reports
- Embedded threat-hunting query authoring with natural language
