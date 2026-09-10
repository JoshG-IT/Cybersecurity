# MHI | Mad Hat Investigations

### Security Investigation Portfolio

Hands-on security investigations completed through **Mad Hat** using live, multi-user training environments.

MHI is my case-based portfolio for documenting practical security investigations across infrastructure, Microsoft Azure, AWS, and Google Cloud.

Each completed case includes sanitized evidence, investigation methodology, technical analysis, commands or queries used, findings, root-cause analysis, and security recommendations.

> **Training Environment:** These investigations are performed in hands-on training environments and are not presented as production customer incidents.

---

## Investigation Tracks

| Track | Focus | Progress | Status |
|---|---|:---:|:---:|
| [**Infrastructure Security Operations**](Infrastructure%20Security%20Operations/) | Windows, networking, forensics, Active Directory, Linux, scripting | 0 / 8 | ⏳ Pending |
| [**Azure Security Investigations**](Azure%20Security%20Investigations/) | Governance, identity, RBAC, compute, networking, storage, detection and cloud security | 1 / 10 | 🟢 Active |
| [**AWS Security Investigations**](AWS%20Security%20Investigations/) | AWS security investigation scenarios | - | ⏳ Pending |
| [**GCP Security Investigations**](GCP%20Security%20Investigations/) | Google Cloud security investigation scenarios | - | ⏳ Pending |

---

## Completed Investigations

| Case | Investigation | Track | Focus |
|---|---|---|---|
| **MHI-AZ-001** | [**Operation Dead Deploy**](Azure%20Security%20Investigations/MHI-AZ-001-operation-dead-deploy/) | Azure | Governance, ARM deployment tracing, Azure Policy and RBAC |

---

**Skills demonstrated:**

`Azure CLI` · `ARM` · `Azure Policy` · `RBAC` · `JMESPath` · `Azure PowerShell` · `Root Cause Analysis`

---

## Portfolio Progress

**1 documented investigation completed**

```text
Infrastructure Security Operations    0 / 8
Azure Security Investigations         1 / 10
AWS Security Investigations           Pending
GCP Security Investigations           Pending
```

---

## About the Environment

The investigations documented here originate from hands-on training through **Mad Hat**.

The portfolio reorganizes the concluding practical exercises into independent security investigation cases.

## Management and Investigation Interfaces

This repository intentionally uses multiple Microsoft cloud management interfaces.

The goal is not to rely on one tool for everything. Different interfaces are better suited to different parts of Azure, Microsoft Entra ID, and security operations.

My primary interface is **Azure CLI**, with PowerShell, Microsoft Graph, KQL, Azure Resource Graph, and the Azure Portal used when they are better suited to the task.

| Interface | Primary Use |
|---|---|
| [Azure CLI](guides/azure-cli.md) | Azure resource discovery, configuration, RBAC, policy, and command-line investigation |
| [PowerShell](guides/powershell.md) | Automation, scripting, Microsoft administration, and reusable investigation workflows |
| [Microsoft Graph](guides/microsoft-graph.md) | Microsoft Entra ID, identity, sign-ins, audit data, applications, and Microsoft 365 |
| [KQL](guides/kql.md) | Log Analytics, Microsoft Sentinel, Defender, telemetry, and event investigation |
| [Azure Resource Graph](guides/azure-resource-graph.md) | Large-scale Azure resource discovery and inventory |
| [Azure Portal](guides/azure-portal.md) | Visual exploration, validation, and functionality not easily exposed through CLI |
| [Bicep](guides/bicep.md) | Repeatable Infrastructure as Code deployments |

### Interface Selection Philosophy

```text
What am I trying to investigate?

Azure resource or configuration
        |
        v
Azure CLI
        |
        +-- Need large-scale inventory?
        |        |
        |        v
        |   Azure Resource Graph
        |
        +-- Need automation?
        |        |
        |        v
        |    PowerShell
        |
        +-- Identity / Entra / M365 data?
        |        |
        |        v
        |   Microsoft Graph
        |
        +-- Logs / events / telemetry?
        |        |
        |        v
        |       KQL
        |
        +-- Need visual validation or CLI/API cannot expose it?
                 |
                 v
            Azure Portal
```

### Investigation Rule

Whenever possible:

1. Discover the object.
2. Inspect the raw output.
3. Understand the JSON structure.
4. Filter only after understanding the data.
5. Record commands and evidence.
6. Validate important conclusions using another interface when appropriate.

The objective is to understand the underlying Azure and Microsoft cloud systems rather than memorize individual commands.
