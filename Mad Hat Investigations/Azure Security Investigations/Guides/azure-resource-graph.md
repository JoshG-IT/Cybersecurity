# Azure Resource Graph Training Guide

## Purpose

Azure Resource Graph is designed for fast resource discovery across large Azure environments.

It becomes valuable when normal Azure CLI enumeration starts requiring too many individual API calls.

## Question It Answers

```text
What Azure resources exist across my environment?
```

## Examples

- Find every public IP
- Find every storage account
- Find every VM
- Find resources without required tags
- Search multiple subscriptions
- Identify resource types
- Find configuration patterns
- Investigate resource changes

## Relationship to Azure CLI

Normal Azure CLI:

```text
az resource list
```

Azure Resource Graph:

```text
query Azure's indexed resource inventory
```

Resource Graph is especially useful when the environment becomes large.

## Query Language

Azure Resource Graph uses a query language based on KQL.

Example concept:

```kusto
Resources
| where type =~ "microsoft.storage/storageaccounts"
| project name, resourceGroup, location
```

## Learning Priority

Learn this after becoming comfortable with:

- Azure resource IDs
- Resource types
- Resource groups
- Azure CLI
- Basic KQL

## Investigation Goal

Eventually be able to walk into an unfamiliar tenant and rapidly answer:

```text
What exists?
Where is it?
What type is it?
How is it configured?
Which resources look unusual?
```
