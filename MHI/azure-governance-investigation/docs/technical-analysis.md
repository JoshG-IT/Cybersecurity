# Technical Analysis
## Azure Policy, ARM, RBAC, and CLI Investigation Notes

## 1. Why the Portal and CLI Looked Different

The Azure Portal presented policy compliance as one connected workflow. Azure CLI exposed several separate objects that needed to be correlated.

```text
Policy Definition
Defines the rule
        ↓
Policy Assignment
Applies the rule to a scope and supplies configuration
        ↓
Policy State
Records the evaluation result for a resource
```

This distinction became important during Stage 4.

---

## 2. `list` vs `show`

A useful Azure CLI pattern throughout the investigation was:

```text
list
= I do not know the object name yet; discover objects

show
= I know the object identifier; inspect one object
```

Examples:

```powershell
az group list
az deployment group list -g <RESOURCE_GROUP>
az policy state list -g <RESOURCE_GROUP>
```

versus:

```powershell
az group show -n <RESOURCE_GROUP>
az deployment group show -g <RESOURCE_GROUP> -n <DEPLOYMENT>
az policy definition show --name <POLICY_DEFINITION>
```

---

## 3. Resource Discovery

### Resource Groups

```powershell
az group list -o table
```

Purpose: identify naming anomalies at subscription scope.

### Resources Within the Target Group

```powershell
az resource list \
  -g <RESOURCE_GROUP> \
  -o table
```

Purpose: establish workload scope.

---

## 4. ARM Deployment Evidence

### Deployment Inventory

```powershell
az deployment group list \
  -g <RESOURCE_GROUP> \
  -o table
```

### Deployment Parameters

```powershell
az deployment group show \
  -g <RESOURCE_GROUP> \
  -n <DEPLOYMENT_NAME> \
  --query properties.parameters
```

### Optional Deployment Operations

```powershell
az deployment operation group list \
  -g <RESOURCE_GROUP> \
  -n <DEPLOYMENT_NAME> \
  --query "[].{Operation:properties.provisioningOperation,State:properties.provisioningState,Type:properties.targetResource.resourceType}" \
  -o table
```

Purpose: break a deployment into its individual ARM operations.

---

## 5. JMESPath Filtering

Large JSON results were narrowed using `--query`.

Example concept:

```powershell
az policy state list \
  -g <RESOURCE_GROUP> \
  --query "[?complianceState=='NonCompliant']"
```

Custom projections make CLI output easier to read:

```powershell
--query "[].{Compliance:complianceState,Effect:policyDefinitionAction}"
```

General syntax:

```text
[].{FriendlyColumn:actualJsonProperty}
```

JMESPath property names are case-sensitive.

---

## 6. Azure Policy State

Policy state answered:

> What happened when Azure evaluated this resource?

```powershell
az policy state list -g <RESOURCE_GROUP>
```

Relevant fields included:

```text
policyAssignmentName
policyAssignmentId
policyAssignmentScope
policyDefinitionName
policyDefinitionAction
complianceState
resourceId
resourceType
timestamp
```

The relevant evaluation showed:

```text
ComplianceState        = NonCompliant
PolicyDefinitionAction = audit
```

---

## 7. Azure Policy Definition

The policy definition answered:

> What rule is Azure evaluating?

```powershell
az policy definition show \
  --name <POLICY_DEFINITION_ID>
```

The definition showed:

- Display name: Naming Convention
- Policy type: Custom
- Mode: All
- Resource-group naming pattern: `rg-*`
- Configurable effects: Audit, Deny, Disabled

`rg-*` is retained publicly because it documents the technical policy logic and is not a challenge answer.

---

## 8. Policy Assignment Read Failure

The policy assignment answered:

> Where is the rule applied and how is it configured?

The logical command was:

```powershell
az policy assignment show \
  --name <POLICY_ASSIGNMENT_ID>
```

The Reader identity was denied:

```text
AuthorizationFailed
Microsoft.Authorization/policyAssignments/read
```

This was not an Azure CLI syntax issue.

---

## 9. Validation Through Azure PowerShell

Azure PowerShell was used as a secondary validation interface.

### Policy Definition

```powershell
Get-AzPolicyDefinition -Name <POLICY_DEFINITION_ID>
```

### Policy State

```powershell
Get-AzPolicyState -ResourceGroupName <RESOURCE_GROUP>
```

Filtering a definition:

```powershell
Get-AzPolicyState -ResourceGroupName <RESOURCE_GROUP> |
Where-Object {
    $_.PolicyDefinitionName -eq '<POLICY_DEFINITION_ID>'
} |
Format-List *
```

This exposed the same policy-state relationship as Azure CLI.

### Policy Assignment

```powershell
Get-AzPolicyAssignment \
  -Name <POLICY_ASSIGNMENT_ID> \
  -Scope <POLICY_ASSIGNMENT_SCOPE>
```

This was also restricted by RBAC.

---

## 10. Azure Resource Graph Validation

Azure Resource Graph was used to determine whether policy-assignment data could be retrieved through `PolicyResources`.

Policy states remained visible, while the target subscription-level policy assignment object was not directly returned to the Reader identity.

This reinforced the conclusion that the investigation had reached an authorization boundary rather than a CLI limitation.

---

## 11. Direct ARM REST Validation

A direct ARM `GET` was tested through `az rest`.

Conceptually:

```powershell
az rest \
  --method get \
  --url "https://management.azure.com/<POLICY_ASSIGNMENT_RESOURCE_ID>?api-version=<API_VERSION>"
```

The same `policyAssignments/read` authorization failure occurred.

This demonstrated that the authorization failure was enforced by ARM itself, not merely by the Azure CLI command wrapper.

---

## 12. Policy Effect Interpretation

| Effect | High-Level Behavior |
|---|---|
| Audit | Allows request, records violation |
| Deny | Blocks non-compliant request |
| Disabled | Policy rule does not evaluate for enforcement |

The incident behavior was consistent with `Audit`.

---

## 13. Investigation Takeaway

The investigation required correlating:

```text
Resource Inventory
        +
Resource Metadata
        +
ARM Deployment History
        +
Policy State
        +
Policy Definition
        +
Policy Assignment Configuration
        +
RBAC
```

The technical root cause was not a failed policy engine. It was a governance control configured for detection rather than prevention.
