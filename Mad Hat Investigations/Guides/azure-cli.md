# Azure CLI Training Guide

## Purpose

Azure CLI is my primary interface for Azure investigations.

I use it to discover resources, inspect configuration, investigate Azure RBAC, examine policies, inspect tags, and build a mental map of unfamiliar Azure environments.

## Best Used For

- Subscriptions
- Management groups
- Resource groups
- Azure resources
- RBAC
- Policies
- Locks
- Tags
- Networking
- Storage resource configuration
- Managed identities
- Deployments

## Core Learning Goal

Do not memorize every command.

Learn how to discover commands using the CLI itself.

```powershell
az --help
az account --help
az resource --help
az role --help
```

## Investigation Workflow

```text
Identify object
      |
      v
Find command group
      |
      v
Read --help
      |
      v
Run command with raw JSON
      |
      v
Inspect structure
      |
      v
Use --query
      |
      v
Format output
```

## Output Formats

```powershell
-o json
```

Best for learning the structure of an object.

```powershell
-o table
```

Best for human-readable summaries.

```powershell
-o tsv
```

Best for extracting a raw value.

## JMESPath

Azure CLI uses JMESPath with `--query`.

Example:

```powershell
az resource list `
  --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" `
  -o table
```

### JSON Shape Rule

```text
{
    object
}
```

Usually query directly:

```text
name
properties.status
```

```text
[
    array
]
```

Usually project or filter:

```text
[].name
[?condition]
```

## Learning Exercises

Practice answering:

- What subscription am I using?
- Which tenant does it trust?
- What resource groups exist?
- What resources are inside a specific resource group?
- What identities exist?
- Who has access?
- At what scope?
- Which policies apply?
- Which tags contain useful metadata?

## When Azure CLI Is Not Enough

Pivot when the information belongs primarily to:

```text
Entra / Microsoft 365
→ Microsoft Graph

Logs / telemetry
→ KQL

Large resource inventory
→ Azure Resource Graph

Visual-only or unfamiliar configuration
→ Azure Portal
```

## What I Want to Master

- Azure CLI command discovery
- JMESPath
- JSON
- Azure resource IDs
- Azure RBAC scopes
- Resource hierarchy
- Azure REST concepts
