# Evidence Register

This register maps each public screenshot to the investigation question it supports.

| ID | File | Evidence | Purpose | Required Redaction |
|---|---|---|---|---|
| E-01 | `01-resource-group-discovery.png` | Resource-group inventory | Establish naming anomaly | Stage 1 answer, operative-specific RG/ID |
| E-02 | `02-resource-tags-redacted.png` | Resource tags | Establish metadata context | Intern flag, owner identity, unique resource name if needed |
| E-03 | `03-deployment-history-redacted.png` | ARM deployment history | Establish provisioning record | Stage 3 deployment name, Stage 1 RG answer |
| E-04 | `04-deployment-parameters-redacted.png` | Deployment parameters | Establish deployment context | Challenge flag, GUID values, RG/deployment answers |
| E-05 | `05-policy-state-cli-redacted.png` | Azure Policy state | Establish compliance and action | Policy GUIDs, assignment GUIDs, subscription ID, target RG answer |
| E-06 | `06-policy-definition-cli-redacted.png` | Naming policy definition | Establish rule logic | Subscription ID, policy GUID, creator information |
| E-07 | `07-policy-assignment-portal-redacted.png` | Policy assignment configuration | Establish Audit effect | Description/Stage 4 answer, assignment ID, subscription ID |
| E-08 | `08-rbac-boundary-redacted.png` | Authorization failure | Establish investigation limitation | Username, email, object ID, subscription ID, assignment ID |

## Publicly Safe Technical Values

The following values are intentionally retained because they explain the technology rather than reveal challenge answers:

- `Audit`
- `Deny`
- `Disabled`
- `NonCompliant`
- `Incremental`
- `Succeeded`
- `East US`
- `Microsoft.Storage/storageAccounts`
- `rg-*`
- `Reader`
- `Contributor`
- Azure service names
- Relevant timestamps

## Never Publish

- `MadHat{...}` values
- Stage-answer resource-group names
- Stage-answer deployment names
- Operative IDs
- Tenant IDs
- Subscription IDs
- Object IDs
- Policy-definition GUIDs
- Policy-assignment GUIDs
- Group GUIDs
- Usernames or tenant email addresses
- Any challenge-specific value that would allow another learner to bypass the investigation
