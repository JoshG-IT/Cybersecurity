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
