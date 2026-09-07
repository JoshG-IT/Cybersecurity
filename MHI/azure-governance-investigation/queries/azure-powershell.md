# Azure PowerShell Investigation Commands

Azure PowerShell was used as a secondary validation interface. Azure CLI remained the primary investigation tool.

---

## Policy Definition

```powershell
Get-AzPolicyDefinition -Name <POLICY_DEFINITION_ID>
```

**Purpose:** Retrieve the policy definition and validate its display name, mode, type, parameters, and rule.

---

## Policy State

```powershell
Get-AzPolicyState -ResourceGroupName <RESOURCE_GROUP>
```

**Purpose:** Retrieve policy-compliance state for a resource group.

---

## Filter a Specific Policy Definition

```powershell
Get-AzPolicyState -ResourceGroupName <RESOURCE_GROUP> |
Where-Object {
    $_.PolicyDefinitionName -eq '<POLICY_DEFINITION_ID>'
} |
Format-List *
```

Useful properties include:

```text
PolicyAssignmentName
PolicyAssignmentId
PolicyAssignmentScope
PolicyDefinitionName
PolicyDefinitionAction
ComplianceState
ResourceId
ResourceType
Timestamp
```

---

## Create a Focused Policy-State View

```powershell
Get-AzPolicyState -ResourceGroupName <RESOURCE_GROUP> |
Where-Object {
    $_.PolicyDefinitionName -eq '<POLICY_DEFINITION_ID>'
} |
Select-Object `
    PolicyAssignmentName,
    PolicyAssignmentId,
    PolicyAssignmentScope,
    PolicyDefinitionName,
    ComplianceState,
    PolicyDefinitionAction,
    ResourceId
```

---

## Policy Assignment

```powershell
Get-AzPolicyAssignment `
  -Name <POLICY_ASSIGNMENT_ID> `
  -Scope <POLICY_ASSIGNMENT_SCOPE>
```

**Investigation result:** Direct subscription-level policy-assignment retrieval was restricted by RBAC in the training environment.

---

# CLI vs Azure PowerShell

| Question | Azure CLI | Azure PowerShell |
|---|---|---|
| What policy evaluations exist? | `az policy state list` | `Get-AzPolicyState` |
| What is the rule? | `az policy definition show` | `Get-AzPolicyDefinition` |
| How is it assigned? | `az policy assignment show` | `Get-AzPolicyAssignment` |

The same RBAC model applies regardless of interface.
