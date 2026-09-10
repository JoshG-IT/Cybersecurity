# Azure Security Investigations

Hands-on Microsoft Azure security investigations completed through Mad Hat in a live multi-user Azure training tenant.

Each case represents the concluding hands-on investigation for a major Azure security domain.

> Training environment only. Completed investigations demonstrate hands-on analysis and are not presented as production customer incidents.

## Investigation Index

| Case | Investigation | Security Focus | Status |
|---|---|---|:---:|
| **MHI-AZ-001** | [Operation Dead Deploy](MHI-AZ-001-operation-dead-deploy/) | Azure governance, ARM deployment tracing, Azure Policy | ✅ Complete |
| **MHI-AZ-002** | [The Stolen Identity](MHI-AZ-002-the-stolen-identity/) | Microsoft Entra ID and identity security | ⏳ Pending |
| **MHI-AZ-003** | [Privilege Audit](MHI-AZ-003-privilege-audit/) | RBAC, least privilege, privileged access | ⏳ Pending |
| **MHI-AZ-004** | [The Friday Deploy](MHI-AZ-004-the-friday-deploy/) | Compute and workload security | ⏳ Pending |
| **MHI-AZ-005** | [Network Like an Operative](MHI-AZ-005-network-like-an-operative/) | Network segmentation and access control | ⏳ Pending |
| **MHI-AZ-006** | [Looting Buckets](MHI-AZ-006-looting-buckets/) | Storage security and secrets | ⏳ Pending |
| **MHI-AZ-007** | [Find the Anomaly](MHI-AZ-007-find-the-anomaly/) | Monitoring, Log Analytics, KQL | ⏳ Pending |
| **MHI-AZ-008** | [Threat Hunt](MHI-AZ-008-threat-hunt/) | Microsoft Sentinel and threat hunting | ⏳ Pending |
| **MHI-AZ-009** | [Score the Tenant](MHI-AZ-009-score-the-tenant/) | Defender for Cloud and CSPM | ⏳ Pending |
| **MHI-AZ-010** | [The Breach](MHI-AZ-010-the-breach/) | Capstone cloud security investigation | ⏳ Pending |

---

## Investigation Interfaces

I use these Azure investigations as an opportunity to become more familiar with the different interfaces available for investigating Microsoft Azure and Microsoft Entra ID.

My primary learning focus is **Azure CLI**, while PowerShell, Microsoft Graph, KQL, Azure Resource Graph, and the Azure Portal are used when they are relevant to the investigation.

The goal is not to force every investigation through every interface. Instead, I use each case to learn which interface is best suited to the resource, identity, configuration, log source, or activity being investigated.

| Interface | Best For | Guide |
|---|---|---|
| Azure CLI | Azure resources, RBAC, Policy, networking, tags, locks, and reconnaissance | [Azure CLI](Guides/azure-cli.md) |
| PowerShell | Scripting, automation, loops, and reusable investigation workflows | [PowerShell](Guides/powershell.md) |
| Microsoft Graph | Microsoft Entra ID, users, groups, applications, service principals, sign-ins, and audit data | [Microsoft Graph](Guides/microsoft-graph.md) |
| KQL | Logs, telemetry, Log Analytics, Microsoft Sentinel, Defender, and event investigation | [KQL](Guides/kql.md) |
| Azure Resource Graph | Large-scale Azure resource discovery, inventory, and filtering | [Azure Resource Graph](Guides/azure-resource-graph.md) |
| Azure Portal | Visual exploration, validation, and tasks better suited to a graphical interface | [Azure Portal](Guides/azure-portal.md) |

See the complete [Azure Interface Training Guide](Guides/).

---

## Interface Selection

```text
What am I investigating?
        |
        +-- Azure resource, RBAC, Policy, lock, tag, or network
        |       |
        |       --> Azure CLI
        |
        +-- Repeated task, scripting, or automation
        |       |
        |       --> PowerShell
        |
        +-- Entra ID, identity, sign-in, or directory data
        |       |
        |       --> Microsoft Graph
        |
        +-- Logs, events, telemetry, or security activity
        |       |
        |       --> KQL
        |
        +-- Large-scale Azure resource inventory
        |       |
        |       --> Azure Resource Graph
        |
        +-- Visual exploration, validation, or a task
                better suited to a graphical interface
                |
                --> Azure Portal
```

---

## Personal Learning Priority

```text
Azure CLI
    ↓
PowerShell
    ↓
Microsoft Graph
    ↓
KQL / Azure Resource Graph
    ↓
Azure Portal
```

This reflects my personal learning approach rather than a requirement of the Mad Hat investigations.

The Azure Portal remains an important administrative and investigative interface. I use these investigations as opportunities to practice command-line, scripting, API, and query-based methods when appropriate.

---

## Investigation Approach

Whenever practical:

1. Understand the investigation objective.
2. Identify the Azure or Microsoft Entra object, service, or data source involved.
3. Determine which interface is appropriate for the task.
4. Inspect the available information before heavily filtering it.
5. Understand the object structure, IDs, scope, and relationships.
6. Filter or query the information needed for the investigation.
7. Correlate findings with additional evidence when appropriate.
8. Document the commands, evidence, findings, and conclusions.

> **Learning Goal:** Understand the underlying Microsoft cloud services and learn when each interface is useful rather than simply memorizing individual commands.
