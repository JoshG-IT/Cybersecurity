# Azure Governance Investigation
## Operation Dead Deploy

> Investigated unexpected Azure resource provisioning in a **live multi-user Azure training tenant** and traced why an active naming policy detected a violation without preventing deployment.

![Azure Governance Investigation Architecture](diagrams/azure-governance-investigation.png)

## Executive Summary

A resource governance review was performed after an unexpected Azure resource group was identified in a shared training subscription. Using primarily **Azure CLI**, I enumerated the environment, inspected the deployed resource and its metadata, reconstructed the Azure Resource Manager (ARM) deployment, and reviewed Azure Policy compliance.

The investigation determined that the naming control was functioning as configured: the resource group was evaluated as **NonCompliant**, but the applicable policy effect was **Audit**. Audit records a policy violation but does not block resource creation.

Stages 1 through 3 were completed with Azure CLI. During Stage 4, Azure CLI successfully exposed policy state, the policy definition, compliance state, and effective action, but direct retrieval of the subscription-level policy assignment was blocked by RBAC. The final assignment review was therefore completed in the Azure Portal.

> **Training Environment Note:** This project documents work performed in a live multi-user Azure training tenant. It does not represent production access.

---

## Environment

| Component | Details |
|---|---|
| Platform | Microsoft Azure |
| Environment | Live multi-user Azure training tenant |
| Investigation access | Reader |
| Provisioning role in scenario | Temporary Contributor |
| Primary investigation tool | Azure CLI |
| Secondary tools | Azure PowerShell, Azure Portal |
| Governance | Azure Policy |
| Deployment evidence | Azure Resource Manager deployment history |
| Compliance evidence | Azure Policy / Policy Insights |
| Investigation mode | Read-only / observe mode |

---

## Investigation Objectives

- Identify the resource group that violated the expected naming standard.
- Determine what resource was deployed and review its metadata.
- Trace the provisioning event through ARM deployment history.
- Determine whether Azure Policy evaluated the non-compliant resource.
- Identify why the governance control detected the violation but did not prevent the deployment.
- Document investigation limitations caused by RBAC.

---

# Investigation

## 1. Resource Group Discovery

I began at the subscription level and enumerated resource groups using Azure CLI. Most resource groups followed the expected `rg-` naming pattern. One resource group clearly broke that convention and became the focus of the investigation.

```powershell
az group list -o table
```

**Evidence**

> [SCREENSHOT HERE - `evidence/01-resource-group-discovery.png`]  
> Redact the Stage 1 resource-group answer. Replace it visually with `[REDACTED - NAMING OUTLIER]`.  
> Redact the operative-specific resource-group name or any unique operative identifier.  
> Keep several normal `rg-*` resource-group names visible so the naming pattern is obvious.  
> Keep Location and Status visible.

**Conclusion:** A naming anomaly was identifiable through subscription-level resource inventory and pattern matching.

---

## 2. Resource Inspection and Tags

After isolating the suspicious resource group, I enumerated its contents and confirmed that it contained a single Azure Storage account.

```powershell
az resource list \
  --resource-group <REDACTED_RESOURCE_GROUP> \
  --query "[].{Name:name,Type:type,Location:location,Tags:tags}" \
  -o json
```

The resource metadata showed that tags were present, but some values were not operationally useful. The challenge-specific tag value is intentionally excluded from this repository.

**Evidence**

> [SCREENSHOT HERE - `evidence/02-resource-tags-redacted.png`]  
> Redact the storage-account name if it is challenge-specific or uniquely identifies the lab resource.  
> Redact the `intern-flag` value completely and show `[REDACTED]`.  
> Redact the owner value if it identifies the lab user or environment.  
> Keep safe metadata such as `environment: unknown` and `cost-center: unspecified` visible.

**Conclusion:** Resource tags can provide useful investigation context, but the presence of tags alone does not guarantee meaningful governance metadata.

---

## 3. ARM Deployment Reconstruction

I reviewed the resource group's ARM deployment history to determine how the resource was provisioned.

```powershell
az deployment group list \
  --resource-group <REDACTED_RESOURCE_GROUP> \
  -o table
```

The deployment record showed:

| Property | Observed |
|---|---|
| Provisioning state | Succeeded |
| Deployment mode | Incremental |
| Region | East US |
| Deployment timestamp | Preserved in evidence |
| Workload resource | Azure Storage account |

I then reviewed the deployment parameters and output resources to understand the deployment context.

```powershell
az deployment group show \
  --resource-group <REDACTED_RESOURCE_GROUP> \
  --name <REDACTED_DEPLOYMENT_NAME> \
  --query properties.parameters
```

**Evidence**

> [SCREENSHOT HERE - `evidence/03-deployment-history-redacted.png`]  
> Redact the Stage 3 deployment-name answer.  
> Redact the Stage 1 resource-group answer.  
> Keep State, Timestamp, Mode, and Region visible.

> [SCREENSHOT HERE - `evidence/04-deployment-parameters-redacted.png`]  
> Redact the challenge flag value.  
> Redact GUID values such as group/object identifiers.  
> Redact the resource-group and deployment answers if visible in the command line.  
> Keep parameter names, parameter types, and safe values such as `eastus` visible.

**Conclusion:** ARM deployment history provided the provisioning record needed to reconstruct how the resource appeared in the environment.

---

## 4. Governance Analysis

Azure Policy state was queried from the affected resource-group scope.

```powershell
az policy state list \
  -g <REDACTED_RESOURCE_GROUP> \
  -o table
```

The relevant policy evaluation showed:

- **Compliance:** `NonCompliant`
- **Effective action:** `audit`
- **Location:** East US

I then traced the evaluation to the custom naming policy definition.

```powershell
az policy definition show \
  --name <REDACTED_POLICY_DEFINITION_ID>
```

The policy definition established that:

- It was a custom **Naming Convention** policy.
- It evaluated resource groups.
- Resource-group names were expected to match `rg-*`.
- The effect was parameterized and supported `Audit`, `Deny`, or `Disabled`.

`rg-*` is intentionally left visible because it is the technical naming rule being evaluated, not a challenge answer or sensitive identifier.

**Evidence**

> [SCREENSHOT HERE - `evidence/05-policy-state-cli-redacted.png`]  
> Redact policy-definition GUIDs, assignment GUIDs, subscription IDs, and resource-group answers.  
> Keep `NonCompliant`, `audit`, and `eastus` visible.  
> Prefer a tightly cropped screenshot showing only the relevant policy-state result.

> [SCREENSHOT HERE - `evidence/06-policy-definition-cli-redacted.png`]  
> Redact the subscription ID.  
> Redact the policy-definition GUID.  
> Redact creator IDs, usernames, and tenant-domain email addresses.  
> Keep `Naming Convention`, `Audit`, `Deny`, `Disabled`, `All`, `Custom`, and `rg-*` visible.

---

## 5. Stage 4 RBAC Constraint

Azure CLI successfully exposed the policy evaluation, the definition, the assignment identifier, the assignment scope, and the effective action. However, direct retrieval of the subscription-level policy assignment object failed because the Reader-scoped lab identity did not have:

```text
Microsoft.Authorization/policyAssignments/read
```

I validated this behavior with Azure CLI, Azure PowerShell, Azure Resource Graph, and a direct ARM REST request. The compliance data remained readable while the underlying assignment object could not be retrieved directly.

Because the lab's final evidence was stored on the policy assignment, I completed that portion of the investigation in the Azure Portal.

**Evidence**

> [SCREENSHOT HERE - `evidence/07-policy-assignment-portal-redacted.png`]  
> Redact the policy Description value because it contains the Stage 4 challenge answer.  
> Redact Assignment ID and subscription ID.  
> Keep `Naming Convention`, Scope, Definition type, Policy enforcement, Parameter name `Effect`, and Parameter value `Audit` visible.

> [SCREENSHOT HERE - `evidence/08-rbac-boundary-redacted.png`]  
> Redact username/email, object ID, subscription ID, assignment ID, and any tenant-specific identifier.  
> Keep `AuthorizationFailed` and `Microsoft.Authorization/policyAssignments/read` visible.

**Conclusion:** The investigation exposed an important distinction between visibility into **policy compliance state** and permission to read the underlying **policy assignment object**.

---

# Root Cause

> **Azure Policy detected the naming violation correctly. The governance control did not prevent provisioning because the effective policy action was configured as `Audit` rather than a preventive `Deny` effect.**

| Effect | Behavior |
|---|---|
| `Audit` | Allows the request and records non-compliance |
| `Deny` | Rejects the non-compliant request |

The policy itself was not malfunctioning. The control was configured for **detective monitoring** rather than **preventive enforcement**.

---

# Key Findings

1. A resource group was successfully provisioned outside the expected naming convention.
2. The deployed workload consisted of a single Azure Storage account.
3. ARM deployment history confirmed a successful Incremental deployment.
4. Azure Policy detected the naming violation and marked the resource group `NonCompliant`.
5. The effective policy action was `Audit`, which recorded the violation without blocking creation.
6. Reader-level access exposed policy compliance evidence but did not permit direct reading of the subscription-level policy assignment object.

---

# Recommendations

| Priority | Recommendation | Rationale |
|---|---|---|
| High | Evaluate moving the naming policy from `Audit` to `Deny` after impact testing | Converts the control from detective to preventive |
| High | Review temporary Contributor assignments | Reduces unnecessary provisioning capability |
| Medium | Use time-bound privileged access where available | Limits how long elevated access remains active |
| Medium | Enforce approved tag values, not only tag presence | Improves ownership, lifecycle, environment, and cost metadata |
| Medium | Document intentional Audit-mode exceptions | Prevents temporary monitoring configurations from becoming permanent |
| Medium | Monitor Azure Policy compliance continuously | Helps detect governance drift and non-compliant provisioning |

> A move from `Audit` to `Deny` should be tested before enforcement so legitimate workloads are not unexpectedly blocked.

---

# Investigation Challenge

The most important troubleshooting lesson was that the Azure Portal presented policy compliance as a unified experience, while Azure CLI exposed separate Azure Policy objects:

```text
Policy Definition
"What is the rule?"
        ↓
Policy Assignment
"Where and how is it applied?"
        ↓
Policy State
"What happened when the resource was evaluated?"
```

I initially expected Reader-level access to allow direct retrieval of the assignment because the Portal displayed related compliance information. Instead, the investigation showed that policy state could be queried while direct policy-assignment reads were restricted by RBAC.

---

# What I Learned

- Azure Policy definitions, assignments, and policy states are separate objects.
- `Audit` is a detective policy effect; `Deny` is preventive.
- Azure CLI can quickly expose resource inventory, metadata, ARM deployment history, and policy state.
- ARM deployment history provides valuable evidence when reconstructing provisioning events.
- Tags are only useful when their values are governed and operationally meaningful.
- RBAC can allow visibility into compliance results while restricting direct access to the underlying governance object.
- Portal views can aggregate information from multiple backend objects, so reproducing a Portal view in CLI may require tracing several APIs or resource types.

---

# Technical Drill-Down

For the detailed investigation methodology, commands, troubleshooting, and evidence mapping:

- [Full Investigation Report](docs/investigation-report.md)
- [Technical Analysis](docs/technical-analysis.md)
- [Evidence Register](docs/evidence-register.md)
- [Azure CLI Commands](queries/azure-cli.md)
- [Azure PowerShell Commands](queries/azure-powershell.md)

---

# Tools and Services

- Microsoft Azure
- Azure CLI
- Azure PowerShell
- Azure Portal
- Azure Resource Manager
- Azure Policy
- Azure Policy Insights
- Azure Resource Graph
- Azure RBAC
- JMESPath
- PowerShell

---

# Data Handling and Disclosure

Challenge answers and sensitive training-environment identifiers are intentionally excluded.

Redacted information includes:

- Challenge flags
- Stage-answer resource and deployment names
- Tenant IDs
- Subscription IDs
- Usernames and email addresses
- Operative identifiers
- Object IDs
- Policy-definition GUIDs
- Policy-assignment GUIDs
- Group GUIDs
- Other environment-specific identifiers

This repository documents **investigation methodology, evidence, and reasoning**, not the course answer key.

---

## Resume Summary

> Investigated unexpected Azure resource provisioning in a live multi-user training tenant using Azure CLI, Azure PowerShell, ARM deployment history, and Azure Policy; traced a naming-control violation to an Audit-mode governance configuration that detected non-compliance without preventing deployment.
