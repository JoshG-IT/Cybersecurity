# Azure CLI Investigation Commands

These are sanitized examples of the Azure CLI commands used during the investigation.

> Replace placeholders with values from your own authorized environment. Challenge answers and environment-specific identifiers are intentionally omitted.

---

## 1. Discover Azure CLI Resource-Group Commands

```powershell
az group --help
```

---

## 2. Enumerate Resource Groups

```powershell
az group list -o table
```

**Purpose:** Identify naming patterns and anomalies at subscription scope.

---

## 3. Inspect a Resource Group

```powershell
az group show \
  --name <RESOURCE_GROUP>
```

**Purpose:** Review location, provisioning state, tags, and other resource-group properties.

---

## 4. Enumerate Resources

```powershell
az resource list \
  --resource-group <RESOURCE_GROUP> \
  -o table
```

**Purpose:** Determine what resources exist within the group.

---

## 5. Review Resource Metadata

```powershell
az resource list \
  --resource-group <RESOURCE_GROUP> \
  --query "[].{Name:name,Type:type,Location:location,Tags:tags}" \
  -o json
```

**Purpose:** Review resource type, location, and tags.

---

## 6. List ARM Deployments

```powershell
az deployment group list \
  --resource-group <RESOURCE_GROUP> \
  -o table
```

**Purpose:** Identify deployment records associated with the resource group.

---

## 7. Inspect Deployment Parameters

```powershell
az deployment group show \
  --resource-group <RESOURCE_GROUP> \
  --name <DEPLOYMENT_NAME> \
  --query properties.parameters
```

**Purpose:** Review the inputs used during deployment.

---

## 8. Inspect Deployment Details

```powershell
az deployment group show \
  --resource-group <RESOURCE_GROUP> \
  --name <DEPLOYMENT_NAME> \
  --query "{State:properties.provisioningState,Mode:properties.mode,Timestamp:properties.timestamp,Parameters:properties.parameters,OutputResources:properties.outputResources}"
```

---

## 9. List Deployment Operations

```powershell
az deployment operation group list \
  --resource-group <RESOURCE_GROUP> \
  --name <DEPLOYMENT_NAME> \
  --query "[].{Operation:properties.provisioningOperation,State:properties.provisioningState,Type:properties.targetResource.resourceType}" \
  -o table
```

**Purpose:** Review the individual ARM operations performed by a deployment.

---

## 10. Query Policy State

```powershell
az policy state list \
  -g <RESOURCE_GROUP>
```

**Purpose:** Review policy evaluation results for resources in the group.

---

## 11. Filter Non-Compliant Policy State

```powershell
az policy state list \
  -g <RESOURCE_GROUP> \
  --query "[?complianceState=='NonCompliant'].{Compliance:complianceState,Effect:policyDefinitionAction,Location:resourceLocation}" \
  -o table
```

**Purpose:** Reduce policy-state output to non-compliant evaluations.

---

## 12. Inspect a Policy Definition

```powershell
az policy definition show \
  --name <POLICY_DEFINITION_ID>
```

**Purpose:** Review the policy rule, supported effect values, mode, and policy type.

---

## 13. List Policy Assignments

```powershell
az policy assignment list
```

For scope investigation:

```powershell
az policy assignment list --help
```

---

## 14. Inspect a Policy Assignment

```powershell
az policy assignment show \
  --name <POLICY_ASSIGNMENT_ID>
```

**Investigation result:** In this training environment, direct assignment retrieval was blocked by RBAC at subscription scope.

---

## 15. Azure Resource Graph - Policy States

```powershell
az graph query -q "
PolicyResources
| where type =~ 'Microsoft.PolicyInsights/PolicyStates'
| project
    assignment=tostring(properties.policyAssignmentName),
    definition=tostring(properties.policyDefinitionId),
    compliance=tostring(properties.complianceState),
    effect=tostring(properties.policyDefinitionAction),
    resource=tostring(properties.resourceId)
" \
--query data \
-o table
```

**Purpose:** Validate policy-state relationships through Azure Resource Graph.

---

## 16. Direct ARM Request

```powershell
az rest \
  --method get \
  --url "https://management.azure.com/<RESOURCE_ID>?api-version=<API_VERSION>"
```

**Purpose:** Determine whether a failure originates from the CLI wrapper or ARM authorization itself.

---

# JMESPath Quick Reference

```text
[0]
First object in an array

[0].property
Property from the first object

[].property
Property from every object

[?property=='value']
Filter objects

[].{FriendlyName:property}
Create a custom projection
```

Example:

```powershell
--query "[].{Name:name,Location:location}"
```

---

# Investigation Pattern

```text
list
↓
discover objects

show
↓
inspect one object

--query
↓
reduce output to the evidence you need
```
