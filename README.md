# Security Orchestration & Automation (SOAR)

> Part of the [worlds-biggest-software-project](https://github.com/worlds-biggest-software-project) initiative.
>
> An open-source, AI-native SOAR platform that replaces brittle, vendor-locked playbook engines with transparent agentic investigation, standards-based integrations, and accessible pricing for teams of every size.

Security operations centres face a compounding problem: alert volumes grow faster than headcount, and the commercial SOAR platforms meant to help carry enterprise price tags, proprietary lock-in, and playbooks that go stale the moment an integration changes. This project delivers a modern, open-source SOAR that combines structured playbook automation with agentic AI investigation -- giving SOC analysts a tool that works with them rather than creating more engineering overhead.

---

## Why Security Orchestration & Automation (SOAR)?

- **Enterprise pricing shuts out mid-market teams.** Splunk SOAR, Cortex XSOAR, and QRadar SOAR are subscription-only products aimed at large enterprises. Mid-market and SMB security teams -- who face the same alert-overload problems -- are priced out or forced into lowest-tier plans with capped integrations.
- **Vendor lock-in limits integration breadth.** FortiSOAR is strongest inside the Fortinet Security Fabric; Microsoft Sentinel playbooks are most useful in Azure-centric environments; Cortex XSIAM pushes customers toward the Palo Alto data lake. Teams running heterogeneous stacks pay a tax for every out-of-ecosystem connector.
- **Playbooks rot.** Traditional SOAR requires security engineers to manually author and maintain deterministic workflows. When APIs change, connectors break, and playbooks silently fail. Only Morpheus AI claims self-healing integrations; the rest leave maintenance to the customer.
- **Existing open-source options are immature.** Shuffle (AGPL-3.0) is the primary open-source SOAR, but its case management is less mature than commercial alternatives and documentation is thinner. TheHive 5 moved to a proprietary licence, fragmenting its community. There is no high-quality, modern-UX open-source SOAR with agentic AI capabilities.
- **Agentic AI is emerging but opaque.** Prophet Security and Radiant Security offer autonomous alert triage, but their model reasoning is not transparent enough for regulated industries that require auditable decision chains.

---

## Key Features

### Playbook & Workflow Automation
- Visual workflow editor with branching, loops, and reusable sub-workflows
- Git-versioned playbooks with branch, diff, and pull-request review workflows
- Natural-language to workflow translation powered by AI
- Self-healing integration framework that auto-detects schema drift and broken connectors

### Case Management & Collaboration
- Full incident lifecycle tracking: triage, containment, eradication, post-incident review
- Timeline visualisation with observable tracking, evidence attachment, and task assignment
- ChatOps War Rooms with bidirectional Slack and Microsoft Teams integration
- Shift handover support and SLA tracking dashboards

### Threat Intelligence & Enrichment
- STIX/TAXII and MISP-native threat intelligence ingestion
- Automated indicator enrichment from VirusTotal, Shodan, NVD, identity directories, and CMDB systems
- MITRE ATT&CK tagging on incidents, playbooks, and coverage gap analysis
- OCSF-compliant data normalisation across all integrations

### Agentic AI Investigation
- Autonomous alert triage with exportable, auditable reasoning chains
- AI-generated investigation reports and post-incident reviews
- Suggested next steps drawn from similar historical cases
- Auto-mapping of alerts to MITRE ATT&CK techniques

### Integration & Extensibility
- 30-50 priority connectors at MVP (Splunk, Sentinel, CrowdStrike, SentinelOne, Okta, Microsoft 365, Jira, AWS, GCP, Azure)
- OpenAPI-driven integration auto-generation for rapid connector development
- REST API, webhooks, and Python SDK for custom integrations
- Multi-tenancy for MSSPs with tenant isolation

---

## AI-Native Advantage

Unlike traditional SOAR platforms that depend entirely on pre-authored deterministic playbooks, this project uses large language models as reasoning agents that investigate alerts, assemble evidence, form hypotheses, and recommend response actions at runtime. Critically, every AI decision produces an exportable reasoning chain -- making agentic investigation auditable for regulated industries where incumbent AI-native vendors (Prophet Security, Radiant Security) lack transparency. AI also powers natural-language workflow authoring, automated incident summarisation for handovers and executive reports, anomaly detection on playbook execution metrics, and threat-hunting query generation from plain English.

---

## Tech Stack & Deployment

- **Deployment modes:** Self-hosted (on-prem or private cloud), managed cloud, and hybrid configurations. Multi-tenant architecture supports MSSP use cases from day one.
- **Standards alignment:** OCSF for data normalisation, OpenC2 for command-and-control, STIX/TAXII for threat intelligence exchange, MITRE ATT&CK for TTP mapping. All standards are openly licensed.
- **Integration approach:** OpenAPI-driven auto-generation of connectors (following the Shuffle pattern), a Python SDK for custom integrations, and a REST API for programmatic access.
- **Playbook storage:** Plain-text playbook definitions versioned in Git rather than proprietary blob storage, enabling CI/CD pipelines for playbook testing and promotion.

---

## Market Context

The SOAR market is valued at $666 million-$987 million in 2026, with projections reaching $1.3-1.9 billion by 2034 (Mordor Intelligence). Enterprise incumbents like Splunk SOAR and Cortex XSOAR command premium subscription pricing, while consolidation plays -- Cisco's $28 billion Splunk acquisition, Palo Alto's $500 million QRadar SaaS purchase from IBM -- are concentrating the market among a few large vendors. Primary buyers are SOC teams, MSSPs, and security engineering groups at organisations with 50+ security tools seeking to reduce mean time to respond and analyst burnout.

---

## Project Status

> This project is in the **research and specification phase**.  
> Contributions, feedback, and domain expertise are welcome.

---

## Contributing

We welcome contributions from developers, domain experts, and potential users.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Important:** All contributions must be your own original work or clearly attributed
open-source material with a compatible licence. Copyright infringement and licence
violations will not be tolerated and will result in immediate removal of the offending
contribution. If you are unsure whether a piece of code, text, or other material is
safe to contribute, open an issue and ask before submitting.

---

## Licence

Licence to be determined. See [discussion](#) for context.
