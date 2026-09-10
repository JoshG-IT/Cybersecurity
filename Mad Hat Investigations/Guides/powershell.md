# PowerShell Training Guide

## Purpose

PowerShell is my automation and orchestration layer.

Azure CLI tells Azure what I want.

PowerShell allows me to combine commands into reusable workflows.

## Important Distinction

PowerShell itself is a shell and scripting language.

There are multiple Microsoft management modules that run inside PowerShell.

```text
PowerShell
   |
   +-- Azure CLI
   |
   +-- Az PowerShell
   |
   +-- Microsoft Graph PowerShell
```

## Az PowerShell

Used primarily for Azure Resource Manager operations.

Examples:

```powershell
Get-AzResource
Get-AzResourceGroup
Get-AzRoleAssignment
```

## Microsoft Graph PowerShell

Used primarily for Microsoft Entra and Microsoft 365.

Examples:

```powershell
Get-MgUser
Get-MgGroup
Get-MgAuditLogSignIn
```

## Best Used For

- Reusable functions
- Variables
- Loops
- Automation
- Processing Azure CLI output
- Administrative scripts
- Investigation tooling
- Bulk operations

## Example

Instead of checking several groups manually:

```text
group 1
group 2
group 3
group 4
```

PowerShell can loop through them automatically.

## Concepts to Learn

```text
Variables
$args
Arrays
Objects
Pipelines
ForEach-Object
foreach
if
Functions
Parameters
Error handling
Tee-Object
Get-Command
Get-Help
```

## Investigation Goal

Turn repeated manual investigation steps into reusable functions.

Example:

```powershell
Get-MySecurityGroups
```

instead of repeatedly entering several Azure CLI commands.

## Do Not Automate Too Early

First:

```text
understand task manually
```

Then:

```text
repeat task several times
```

Then:

```text
automate it
```

Automation should reinforce understanding rather than hide it.
