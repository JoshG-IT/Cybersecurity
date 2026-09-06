# Investigation Report
## Azure Governance Investigation - Operation Dead Deploy

## 1. Report Purpose

This report documents a read-only investigation into unexpected Azure resource provisioning within a live multi-user Azure training tenant.

The investigation sought to answer five questions:

| Question | Investigation Goal |
|---|---|
| Who? | Identify the role associated with provisioning activity |
| What? | Determine what resources were created |
| When? | Establish the deployment timestamp |
| Where? | Identify the affected Azure scope and region |
| Why? | Determine why governance detected but did not prevent the deployment |

No destructive or modifying actions were performed.

---

## 2. Scope

### Included

- Azure subscription resource-group inventory
- A non-compliant resource group
- One Azure Storage account
- Resource metadata and tags
- ARM deployment history
- Azure Policy compliance state
- Azure Policy definition
- Subscription-level policy assignment evidence
- Reader-role investigation limitations

### Excluded

Other Azure resources in the shared training tenant were outside the scope of this investigation and are intentionally omitted from the project architecture.

---

## 3. Access Model

| Role | Access |
|---|---|
| Scenario intern | Temporary Contributor |
| Investigator | Reader |
| Investigation mode | Observe only |

The Reader identity was sufficient for resource inventory, deployment inspection, policy-state queries, and policy-definition reads, but not for direct retrieval of the subscription-level policy assignment object.

---

## 4. Investigation Timeline

> Training-environment note: Scenario timing is narrative. Azure control-plane timestamps are preserved as observed because shared training environments may use persistent or pre-provisioned artifacts.

| Sequence | Event | Evidence |
|---:|---|---|
| 1 | Resource group identified as naming anomaly | E-01 |
| 2 | Single deployed resource identified | E-02 |
| 3 | ARM deployment record reviewed | E-03 / E-04 |
| 4 | Policy state confirmed non-compliance | E-05 |
| 5 | Naming policy definition traced | E-06 |
| 6 | Direct assignment read blocked by RBAC | E-08 |
| 7 | Policy assignment reviewed in Azure Portal | E-07 |

---

## 5. Investigation Detail

### 5.1 Resource Group Discovery

Azure CLI was used to enumerate resource groups at subscription scope.

```powershell
az group list -o table
```

The investigation used naming-pattern analysis rather than a known target. Most resource groups followed an `rg-` naming convention. One resource group did not.

> [SCREENSHOT HERE - E-01]  
> Redact the Stage 1 answer and operative-specific identifiers.

**Assessment:** The naming anomaly justified deeper inspection.

---

### 5.2 Resource Enumeration

The resource group was enumerated using:

```powershell
az resource list \
  --resource-group <REDACTED_RESOURCE_GROUP>
```

The resource group contained one Azure Storage account.

> [SCREENSHOT HERE - E-02]  
> Redact challenge-specific names and values.

**Assessment:** The incident scope was limited to a small workload footprint, allowing the investigation to focus on deployment history and governance controls.

---

### 5.3 Metadata Review

Resource tags were reviewed to identify ownership and contextual metadata.

Observed metadata included values for environment and cost-center that were present but not operationally useful.

Challenge-specific tag values are intentionally omitted.

**Assessment:** Tag presence alone did not provide strong governance assurance. Approved-value enforcement would improve metadata quality.

---

### 5.4 ARM Deployment History

The ARM deployment history was queried:

```powershell
az deployment group list \
  --resource-group <REDACTED_RESOURCE_GROUP> \
  -o table
```

Observed properties included:

- State: `Succeeded`
- Mode: `Incremental`
- Region: East US
- Timestamp: preserved in evidence

The deployment parameters were then reviewed:

```powershell
az deployment group show \
  --resource-group <REDACTED_RESOURCE_GROUP> \
  --name <REDACTED_DEPLOYMENT_NAME> \
  --query properties.parameters
```

> [SCREENSHOT HERE - E-03 / E-04]  
> Redact deployment answer, resource-group answer, challenge flag, and GUID values.

**Assessment:** ARM deployment history provided the creation story for the deployed workload.

---

### 5.5 Policy State Analysis

Azure Policy state was queried from the affected resource-group scope.

```powershell
az policy state list \
  -g <REDACTED_RESOURCE_GROUP>
```

The relevant evaluation showed:

- Compliance state: `NonCompliant`
- Effective action: `audit`
- Resource type: Resource Group
- Location: East US

> [SCREENSHOT HERE - E-05]  
> Redact policy GUIDs and environment identifiers. Keep compliance/action fields visible.

**Assessment:** Azure Policy evaluated the resource and detected the violation successfully.

---

### 5.6 Policy Definition Analysis

The custom policy definition was retrieved using Azure CLI.

```powershell
az policy definition show \
  --name <REDACTED_POLICY_DEFINITION_ID>
```

The definition showed:

- Display name: Naming Convention
- Policy type: Custom
- Mode: All
- Expected naming pattern: `rg-*`
- Parameterized effects: `Audit`, `Deny`, `Disabled`

> [SCREENSHOT HERE - E-06]  
> Redact IDs and creator information. Keep rule logic and effect options visible.

**Assessment:** The policy rule itself was correctly capable of detecting the observed naming violation.

---

### 5.7 Policy Assignment and RBAC Constraint

The policy state exposed an assignment identifier and subscription-level scope. Direct assignment retrieval was attempted through multiple interfaces.

Examples included:

```powershell
az policy assignment show --name <REDACTED_ASSIGNMENT_ID>
```

and:

```powershell
Get-AzPolicyAssignment -Name <REDACTED_ASSIGNMENT_ID>
```

The Reader identity received:

```text
AuthorizationFailed
Microsoft.Authorization/policyAssignments/read
```

A direct ARM REST request produced the same authorization result.

> [SCREENSHOT HERE - E-08]  
> Redact all identity and subscription-specific values. Keep the denied permission visible.

The Azure Portal compliance experience still exposed the assignment configuration required by the lab, so Stage 4 was completed through the Portal.

> [SCREENSHOT HERE - E-07]  
> Redact the assignment Description because it contains a challenge answer. Keep `Effect = Audit` visible.

**Assessment:** The investigation demonstrated a distinction between policy-compliance visibility and direct read permission on the underlying assignment object.

---

## 6. Root Cause Analysis

### Expected Control Behavior

If the naming policy were intended to prevent invalid resource-group names:

```text
Naming violation
      ↓
Deny
      ↓
Deployment blocked
```

### Observed Control Behavior

```text
Naming violation
      ↓
Audit
      ↓
Violation recorded
      ↓
Deployment allowed
```

### Root Cause

The Azure Policy control detected the violation correctly, but the effective policy action was configured as `Audit`.

This made the control **detective** rather than **preventive**.

---

## 7. Findings

### Finding 1 - Naming Standard Violation

A resource group existed outside the expected naming convention.

### Finding 2 - Successful Provisioning

ARM deployment history confirmed that the environment was provisioned successfully.

### Finding 3 - Weak Metadata Quality

Tags existed, but some metadata values were not actionable.

### Finding 4 - Governance Control Operated in Audit Mode

The naming policy evaluated the resource as non-compliant but did not block creation.

### Finding 5 - Reader Investigation Boundary

The Reader identity could query policy compliance data but could not directly retrieve the subscription-level policy assignment.

---

## 8. Recommendations

1. Evaluate transitioning the naming policy from `Audit` to `Deny` after testing for legitimate workload impact.
2. Review temporary Contributor access, its scope, approval, and duration.
3. Use time-bound elevation where supported.
4. Enforce meaningful tag values through policy rather than requiring tag presence alone.
5. Document intentional Audit-mode exceptions and review them periodically.
6. Monitor policy compliance for governance drift and newly introduced non-compliant resources.

---

## 9. Lessons Learned

- Portal experiences can aggregate multiple underlying Azure objects.
- Policy definitions, assignments, and states must be treated as separate investigation artifacts.
- `Audit` and `Deny` have materially different governance outcomes.
- ARM deployment history is a useful control-plane evidence source.
- RBAC can create investigation boundaries even when compliance information remains visible.

---

## 10. Disclosure

This project was completed in a live multi-user Azure training tenant.

Challenge answers, flags, GUIDs, tenant IDs, subscription IDs, usernames, and other identifying training-environment data are intentionally redacted.
