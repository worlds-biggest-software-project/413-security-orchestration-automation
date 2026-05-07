# Standards & API Reference

> Project: Security Orchestration & Automation (SOAR) · Generated: 2026-05-06

## Industry Standards & Specifications

### ISO Standards

- **ISO/IEC 27001:2022 — Information security management systems**
  https://www.iso.org/standard/27001
  Foundational ISMS standard. SOAR platforms support Annex A controls covering incident management (A.5.24–A.5.28) and logging (A.8.15–A.8.17).

- **ISO/IEC 27002:2022 — Code of practice for information security controls**
  https://www.iso.org/standard/75652.html
  Implementation guidance for ISO 27001 controls; defines what "incident response" capabilities a SOAR is expected to deliver.

- **ISO/IEC 27035-1:2023 — Information security incident management: Principles and process**
  https://www.iso.org/standard/78973.html
  Process model for incident detection, reporting, response, and lessons learned. Maps directly onto SOAR case lifecycle stages.

- **ISO/IEC 27035-2:2023 — Guidelines to plan and prepare for incident response**
  https://www.iso.org/standard/78974.html
  Guidance on building IR teams, playbooks, and tooling — relevant to SOAR adoption planning.

- **ISO/IEC 27037:2012 — Guidelines for identification, collection, acquisition and preservation of digital evidence**
  https://www.iso.org/standard/44381.html
  Drives evidence handling and chain-of-custody requirements that case management modules must support.

- **ISO/IEC 27043:2015 — Incident investigation principles and processes**
  https://www.iso.org/standard/44407.html
  Standardises the incident investigation lifecycle relevant to SOAR investigation tasks.

### W3C & IETF Standards

- **RFC 9110 — HTTP Semantics**
  https://www.rfc-editor.org/rfc/rfc9110
  Underpins SOAR REST APIs.

- **RFC 6749 — OAuth 2.0 Authorization Framework**
  https://www.rfc-editor.org/rfc/rfc6749
  Standard authentication for outbound integrations.

- **RFC 7519 — JSON Web Token (JWT)**
  https://www.rfc-editor.org/rfc/rfc7519
  Common token format for API authentication and service identity.

- **RFC 5424 — The Syslog Protocol**
  https://www.rfc-editor.org/rfc/rfc5424
  Audit log emission to SIEMs.

- **RFC 7230–7235 (legacy HTTP/1.1)**
  https://www.rfc-editor.org/rfc/rfc7230
  Still relevant for legacy connector behaviour.

- **RFC 8259 — JSON**
  https://www.rfc-editor.org/rfc/rfc8259
  Default payload format.

- **RFC 6455 — WebSocket Protocol**
  https://www.rfc-editor.org/rfc/rfc6455
  Real-time updates for case timelines and War Room chat.

- **W3C Activity Streams 2.0**
  https://www.w3.org/TR/activitystreams-core/
  Vocabulary basis for case timeline event modelling.

### Data Model & API Specifications

- **OpenAPI Specification 3.1**
  https://spec.openapis.org/oas/v3.1.0
  Standard for documenting SOAR REST APIs and auto-generating connectors (Shuffle pattern).

- **AsyncAPI 3.0**
  https://www.asyncapi.com/docs/reference/specification/v3.0.0
  Specification for event-driven integrations (webhooks, message queues).

- **JSON Schema 2020-12**
  https://json-schema.org/specification
  Validation of incident, alert, and observable payloads.

- **CloudEvents 1.0 (CNCF)**
  https://cloudevents.io/
  Standard envelope for cross-system event delivery.

- **STIX 2.1 (OASIS)**
  https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
  Structured Threat Information Expression — canonical data model for threat intelligence (indicators, TTPs, campaigns, intrusion sets).

- **TAXII 2.1 (OASIS)**
  https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
  Trusted Automated Exchange of Intelligence Information — transport for STIX content between systems.

- **OpenC2 v1.0 (OASIS)**
  https://docs.oasis-open.org/openc2/oc2ls/v1.0/oc2ls-v1.0.html
  Standardised command-and-control language for issuing response actions across heterogeneous tools.

- **OCSF — Open Cybersecurity Schema Framework**
  https://schema.ocsf.io/
  Industry-backed (AWS, Splunk, IBM, etc.) normalised schema for security telemetry; useful for SOAR alert ingestion normalisation.

- **MITRE ATT&CK**
  https://attack.mitre.org/
  Knowledge base of adversary tactics and techniques. STIX-encoded data is freely downloadable.

- **MITRE D3FEND**
  https://d3fend.mitre.org/
  Defensive countermeasure ontology, complementary to ATT&CK.

- **MITRE CACAO 2.0 (OASIS)**
  https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html
  Collaborative Automated Course of Action Operations — open standard playbook format. Directly relevant to portable SOAR playbooks.

- **VERIS — Vocabulary for Event Recording and Incident Sharing**
  https://verisframework.org/
  Common framework for describing security incidents in a structured, repeatable way.

- **MISP Core Format**
  https://www.misp-standard.org/
  De-facto open threat intel exchange schema with broad community adoption.

### Security & Authentication Standards

- **OAuth 2.0 / 2.1 (IETF)**
  https://oauth.net/2/
  Authorisation for outbound integrations and tenant access.

- **OpenID Connect Core 1.0**
  https://openid.net/specs/openid-connect-core-1_0.html
  Identity layer on OAuth for SSO into the SOAR console.

- **SAML 2.0 (OASIS)**
  https://docs.oasis-open.org/security/saml/v2.0/
  Enterprise SSO standard common in regulated industries.

- **SCIM 2.0 (RFC 7643/7644)**
  https://www.rfc-editor.org/rfc/rfc7644
  User and role provisioning into the SOAR platform.

- **mTLS (RFC 8705)**
  https://www.rfc-editor.org/rfc/rfc8705
  Strong authentication for connector-to-target communication.

- **NIST SP 800-61r2 — Computer Security Incident Handling Guide**
  https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
  Canonical IR lifecycle (Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity) — basis for case workflow phases.

- **NIST SP 800-150 — Guide to Cyber Threat Information Sharing**
  https://csrc.nist.gov/publications/detail/sp/800-150/final
  Frames how SOAR platforms should integrate threat intel feeds.

- **NIST SP 800-53 Rev. 5**
  https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
  Federal control catalogue; SOAR platforms commonly map evidence collection to AU/IR control families.

- **NIST Cybersecurity Framework 2.0**
  https://www.nist.gov/cyberframework
  Function-based mapping (Identify, Protect, Detect, Respond, Recover) used in SOAR dashboards.

- **OWASP API Security Top 10 (2023)**
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  Required hardening checklist for SOAR REST APIs.

- **OWASP ASVS 4.0.3**
  https://owasp.org/www-project-application-security-verification-standard/
  Application security verification baseline for the SOAR product itself.

- **GDPR Article 33 — Notification of a personal data breach to the supervisory authority**
  https://gdpr-info.eu/art-33-gdpr/
  72-hour notification clock that privacy modules of SOAR platforms must enforce.

- **HIPAA Breach Notification Rule (45 CFR §§ 164.400–414)**
  https://www.hhs.gov/hipaa/for-professionals/breach-notification/
  US healthcare breach notification timing relevant to regulated industry SOAR deployments.

### MCP Server Specifications

- **Model Context Protocol (MCP)**
  https://modelcontextprotocol.io/specification
  Anthropic-led open protocol for connecting LLM agents to tools and data sources. Highly relevant to agentic SOAR — exposing SIEM, EDR, identity, and ticketing tools as MCP servers lets a reasoning agent invoke them with consistent semantics.

- **MCP Reference Servers**
  https://github.com/modelcontextprotocol/servers
  Reference implementations of MCP servers (filesystem, GitHub, Slack, Postgres) usable as templates for SOAR-specific MCP servers wrapping security tools.

- **MCP Schema (TypeScript)**
  https://github.com/modelcontextprotocol/specification
  Canonical schema for MCP messages, tool definitions, and resource discovery — basis for any MCP-compliant SOAR connector.

## Similar Products — Developer Documentation & APIs

### Splunk SOAR
- **Description:** Enterprise SOAR with 300+ integrations and 2,800+ automated actions; tightly integrated with Splunk ES.
- **API Documentation:** https://docs.splunk.com/Documentation/SOAR/current/PlatformAPI/AboutAPIs
- **SDKs/Libraries:** Python app SDK — https://docs.splunk.com/Documentation/SOAR/current/DevelopApps/Overview
- **Developer Guide:** https://docs.splunk.com/Documentation/SOAR
- **Standards:** REST/JSON; Splunk app manifest format
- **Authentication:** Token (ph-auth-token), session-based, or basic auth

### Palo Alto Cortex XSOAR
- **Description:** Enterprise SOAR with content pack marketplace, threat intel management module, and War Room chatops.
- **API Documentation:** https://xsoar.pan.dev/docs/reference/api/cortex-xsoar-api
- **SDKs/Libraries:** demisto-sdk (Python) — https://github.com/demisto/demisto-sdk
- **Developer Guide:** https://xsoar.pan.dev/docs/welcome
- **Standards:** REST/JSON, OpenAPI-described endpoints, content pack YAML schema
- **Authentication:** API key + API key ID; OAuth for tenant SSO

### IBM QRadar SOAR
- **Description:** Case-management-strong SOAR with regulatory privacy module and dynamic playbook designer.
- **API Documentation:** https://www.ibm.com/docs/en/qradar-soar
- **SDKs/Libraries:** resilient-circuits and resilient-sdk Python packages — https://github.com/ibmresilient
- **Developer Guide:** https://ibm.biz/soar-dev-center
- **Standards:** REST/JSON, OpenAPI; OCSF alignment in newer releases
- **Authentication:** API key, basic auth, or session token

### Fortinet FortiSOAR
- **Description:** Mid-market SOAR with 600+ connectors and Fortinet Security Fabric integration.
- **API Documentation:** https://docs.fortinet.com/product/fortisoar
- **SDKs/Libraries:** Python connector SDK (bundled with platform)
- **Developer Guide:** https://docs.fortinet.com/document/fortisoar/connector-developer-guide
- **Standards:** REST/JSON; connector manifest schema
- **Authentication:** HMAC-signed API keys, OAuth for SSO

### Microsoft Sentinel
- **Description:** Cloud-native SIEM with Logic Apps-based playbooks deeply integrated with Azure and Microsoft 365.
- **API Documentation:** https://learn.microsoft.com/en-us/rest/api/securityinsights/
- **SDKs/Libraries:** Azure SDKs — Python (azure-mgmt-securityinsight), .NET, Go, JS — https://learn.microsoft.com/en-us/azure/sentinel/
- **Developer Guide:** https://learn.microsoft.com/en-us/azure/sentinel/develop-overview
- **Standards:** REST/JSON, OData v4, OpenAPI, KQL for queries
- **Authentication:** Azure AD OAuth 2.0 with managed identities or service principals

### Tines
- **Description:** No-code automation platform popular for security workflows, with story-based authoring and AI mode.
- **API Documentation:** https://www.tines.com/api/
- **SDKs/Libraries:** Generic HTTP; no first-party SDK (HTTP request action is universal)
- **Developer Guide:** https://www.tines.com/docs
- **Standards:** REST/JSON; webhooks
- **Authentication:** API token (Bearer)

### Torq
- **Description:** Hyperautomation platform with HyperSOC autonomous AI agents for security workflows.
- **API Documentation:** https://docs.torq.io/api
- **SDKs/Libraries:** Generic HTTP; CLI for workflow management
- **Developer Guide:** https://docs.torq.io
- **Standards:** REST/JSON; webhooks
- **Authentication:** API key (Bearer)

### Swimlane Turbine
- **Description:** Low-code SOAR with high-throughput automation engine and Hero AI copilot.
- **API Documentation:** https://docs.swimlane.com/turbine/apidocs/
- **SDKs/Libraries:** Python SDK (pyswimlane), generic HTTP
- **Developer Guide:** https://docs.swimlane.com/turbine/
- **Standards:** REST/JSON; OpenAPI for plugins
- **Authentication:** Token-based (PAT), OAuth for SSO

### Shuffle
- **Description:** Open-source SOAR (AGPL-3.0) with OpenAPI-driven app generation and 1,000+ integrations.
- **API Documentation:** https://shuffler.io/docs/API
- **SDKs/Libraries:** shuffle-shared (Go), Python app SDK — https://github.com/Shuffle
- **Developer Guide:** https://shuffler.io/docs
- **Standards:** REST/JSON, OpenAPI 3.0 for app definitions, JSON workflow format
- **Authentication:** API key (Bearer); SSO via OpenID Connect

### TheHive 5 / Cortex
- **Description:** Case-management-centric incident response platform with Cortex analyzer/responder framework.
- **API Documentation:** https://docs.strangebee.com/thehive/api-docs/
- **SDKs/Libraries:** thehive4py (Python), cortex4py (Python) — https://github.com/TheHive-Project
- **Developer Guide:** https://docs.strangebee.com/thehive/
- **Standards:** REST/JSON; MISP-compatible STIX export
- **Authentication:** API key (Bearer), session-based

### Prophet Security
- **Description:** Agentic SOC platform that autonomously investigates every alert using LLM reasoning.
- **API Documentation:** https://www.prophetsecurity.ai/docs (limited public)
- **SDKs/Libraries:** Not publicly documented
- **Developer Guide:** https://www.prophetsecurity.ai
- **Standards:** REST/JSON; MCP-style tool invocation internally
- **Authentication:** API key, OAuth for SSO

## Notes

- **Open standards moving fast:** OCSF (schema normalisation), CACAO (portable playbooks), and OpenC2 (response actions) form an emerging interoperability layer that an AI-native SOAR should adopt early to differentiate against proprietary playbook formats.
- **MCP is a strong fit for agentic SOAR.** Wrapping each integrated tool (SIEM, EDR, identity, ticketing) as an MCP server gives a reasoning agent a uniform interface and built-in capability discovery — a cleaner architecture than vendor-specific connector SDKs.
- **Threat intel space (STIX/TAXII/MISP) is mature and free to adopt.** No licence concerns blocking ingestion or redistribution of intel in these formats.
- **Patent landscape is active but navigable.** Splunk, Palo Alto, IBM, and Fortinet hold patents around specific UI mechanisms and incident clustering algorithms; an implementation grounded in published standards (NIST 800-61, OASIS CACAO, MITRE ATT&CK) and clean-room engineering avoids most exposure but warrants formal IP review prior to release.
- **Regulatory clocks (GDPR Art. 33 72h, HIPAA 60-day, sectoral rules) are concrete product requirements** — a privacy/compliance module is a clear differentiator if implemented with jurisdiction templates.
- **Audit and explainability standards for AI in security are still emerging** (NIST AI RMF, ISO/IEC 42001 for AI management systems). Building exportable reasoning chains and decision logs early positions an agentic SOAR for upcoming regulatory scrutiny.
