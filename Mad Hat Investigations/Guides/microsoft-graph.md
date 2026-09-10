# Microsoft Graph Training Guide

## Purpose

Microsoft Graph is the API used to access Microsoft Entra ID and Microsoft 365 data.

I use Graph when Azure CLI does not expose the identity or Microsoft 365 information I need.

## Common Investigation Targets

- Users
- Groups
- Service principals
- Applications
- Sign-ins
- Audit logs
- Conditional Access
- Directory roles
- Administrative Units
- Microsoft 365 objects

## Ways I Can Access Graph

```text
Microsoft Graph
      |
      +-- az rest
      |
      +-- Graph PowerShell
      |
      +-- Graph Explorer
      |
      +-- REST client
      |
      +-- Python / SDK
```

Graph is the API.

The tool used to call Graph is the interface/client.

## Azure CLI Example

```powershell
az rest --method GET `
  --url "https://graph.microsoft.com/v1.0/..."
```

This allows me to remain in Azure CLI while directly querying Microsoft Graph.

## Graph PowerShell Example

```powershell
Get-MgUser
```

## What I Need to Learn

- REST APIs
- GET
- POST
- PATCH
- DELETE
- API endpoints
- JSON
- OAuth
- Delegated permissions
- Application permissions
- Microsoft Graph scopes
- v1.0 vs beta
- OData query parameters

## Investigation Mindset

Do not memorize every Graph endpoint.

Learn how to identify the resource being queried.

Example:

```text
Need sign-ins
      |
      v
Microsoft Entra
      |
      v
Microsoft Graph
      |
      v
auditLogs
      |
      v
signIns
```

## Security Lesson

Graph permissions matter.

Being an Azure Reader does not automatically mean an account can read all Microsoft Graph data.

Azure RBAC and Microsoft Graph permissions are separate authorization systems.
