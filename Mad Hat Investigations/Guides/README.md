# Microsoft Cloud Interface Training Guide

Microsoft cloud administration is performed through multiple interfaces.

No single interface exposes every capability.

These guides document how I am learning to select the correct interface based on what I am investigating or managing.

## Interface Map

| Interface | Best For | Main Skill Developed |
|---|---|---|
| Azure CLI | Azure resources | Resource investigation |
| PowerShell | Automation and administration | Scripting |
| Microsoft Graph | Identity and Microsoft 365 | API investigation |
| KQL | Logs and telemetry | Security analysis |
| Azure Resource Graph | Resource inventory at scale | Cloud reconnaissance |
| Azure Portal | Visual exploration | Architecture awareness |
| Bicep | Infrastructure creation | Infrastructure as Code |

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

Repeatable infrastructure deployment
→ Bicep
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

Azure Portal
→ ARM / Graph / service APIs

Bicep
→ Azure Resource Manager
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
7. Bicep
```

The Azure Portal remains useful throughout the learning process but is primarily used for visual discovery and validation rather than as the default investigation method.
