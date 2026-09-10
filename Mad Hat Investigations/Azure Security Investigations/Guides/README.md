# Microsoft Cloud Interface Training Guide

Microsoft cloud administration and security investigation can be performed through multiple interfaces.

No single interface exposes every capability.

These guides document how I am learning to select the appropriate interface based on what I am investigating, querying, or analyzing.

## Interface Map

| Interface | Best For | Main Skill Developed |
|---|---|---|
| Azure CLI | Azure resources | Resource investigation |
| PowerShell | Automation and administration | Scripting |
| Microsoft Graph | Identity and Microsoft 365 | API investigation |
| KQL | Logs and telemetry | Security analysis |
| Azure Resource Graph | Resource inventory at scale | Cloud reconnaissance |
| Azure Portal | Visual exploration and validation | Architecture awareness |

---

## The Three Questions

When approaching a task, determine:

### 1. What am I interacting with?

Examples:

- Azure resource
- Microsoft Entra identity
- Azure RBAC assignment
- Microsoft 365 object
- Security event
- Log record
- Network resource

### 2. Which interface is best suited to it?

Examples:

```text
Azure resource
→ Azure CLI

Entra sign-in
→ Microsoft Graph

Sentinel logs
→ KQL

Hundreds of Azure resources
→ Azure Resource Graph

Repeated investigation task
→ PowerShell

Visual exploration or validation
→ Azure Portal
```

### 3. What system/API is underneath the interface?

Examples:

```text
Azure CLI
→ Azure Resource Manager

az ad
→ Microsoft Graph

Graph PowerShell
→ Microsoft Graph

Azure Resource Graph
→ Azure Resource Graph service

Azure Portal
→ ARM / Graph / service APIs
```

Understanding the underlying service is more important than memorizing the interface.

---

## Learning Priority

My current priority:

```text
1. Azure CLI
2. PowerShell
3. Microsoft Graph
4. KQL
5. Azure Resource Graph
6. Azure Portal
```

This is a personal learning priority rather than a requirement of the Mad Hat investigations.

The Azure Portal remains useful throughout the learning process and may be the primary interface used by a lab. I use the investigations as an opportunity to practice command-line, scripting, API, and query-based approaches when appropriate.

The goal is to understand when each interface is useful and how the different interfaces relate to the underlying Microsoft cloud services.
