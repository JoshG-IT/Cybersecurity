# Screenshot Redaction Guide

Use this checklist before publishing screenshots from the training environment.

## Always Redact

- Challenge flags such as `MadHat{...}`
- Stage-answer resource-group names
- Stage-answer deployment names
- Tenant IDs
- Subscription IDs
- Usernames and email addresses
- Operative IDs
- Object IDs
- Group IDs
- Policy-definition GUIDs
- Policy-assignment GUIDs
- Assignment IDs
- Any lab-specific answer value

## Usually Safe to Keep

- Azure service names
- Generic role names: Reader, Contributor
- `Audit`
- `Deny`
- `Disabled`
- `NonCompliant`
- `Succeeded`
- `Incremental`
- `East US`
- `Microsoft.Storage/storageAccounts`
- `rg-*`
- Generic field names
- Relevant timestamps

## Screenshot-by-Screenshot Checklist

### E-01 Resource Group Discovery

Redact:
- Outlier resource-group answer
- Operative-specific resource-group name

Keep:
- Several normal `rg-*` names
- Location
- Status

### E-02 Resource Tags

Redact:
- `intern-flag` value
- Owner value
- Unique resource name if challenge-specific

Keep:
- Tag keys
- Safe values such as `unknown` and `unspecified`

### E-03 Deployment History

Redact:
- Deployment answer
- Resource-group answer

Keep:
- State
- Timestamp
- Mode

### E-04 Deployment Parameters

Redact:
- Challenge flag
- GUID values
- Resource-group answer
- Deployment answer

Keep:
- Parameter names
- Parameter types
- Safe region values

### E-05 Policy State

Redact:
- Policy GUIDs
- Assignment GUIDs
- Subscription ID
- Target resource-group answer

Keep:
- Compliance
- Effect
- Location

### E-06 Policy Definition

Redact:
- Subscription ID
- Policy GUID
- Creator GUID
- Creator email or username

Keep:
- Naming Convention
- Audit / Deny / Disabled
- `rg-*`
- Mode and policy type

### E-07 Policy Assignment Portal

Redact:
- Description value / challenge answer
- Assignment ID
- Subscription ID

Keep:
- Naming Convention
- Scope label
- Policy enforcement
- Effect = Audit

### E-08 RBAC Failure

Redact:
- Account/email
- Object ID
- Subscription ID
- Assignment ID

Keep:
- `AuthorizationFailed`
- `Microsoft.Authorization/policyAssignments/read`
