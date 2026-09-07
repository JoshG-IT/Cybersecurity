# Evidence Register

This evidence register is based **only on the nine screenshots supplied for this rebuild**.

| ID | Recommended Filename | Screenshot Content | Investigation Purpose |
|---|---|---|---|
| E-01 | `01-resource-group-discovery.png` | `az group --help` + `az group list -o table` | Identify the naming outlier |
| E-02 | `02-resource-inventory-tags.png` | `az resource list -g ... -o json` | Inspect the storage account and current resource tags |
| E-03 | `03-deployment-parameters.png` | `az deployment group show --query properties.parameters` | Inspect deployment-time inputs |
| E-04 | `04-deployment-history.png` | `az deployment group list -o table` | Establish deployment record, status, timestamp, and mode |
| E-05 | `05-policy-state-cli.png` | `az policy state list` with JMESPath projection | Establish compliance state and effective action |
| E-06 | `06-policy-definition-cli.png` | `az policy definition show` | Establish Naming Convention rule and effect choices |
| E-07 | `07-policy-definition-powershell.png` | `Get-AzPolicyDefinition` | Secondary validation of the custom policy definition |
| E-08 | `08-policy-assignment-rbac-failure.png` | `az policy assignment show` → AuthorizationFailed | Document the Reader RBAC boundary |
| E-09 | `09-policy-assignment-portal.png` | Azure Portal Naming Convention assignment | Confirm `Effect = Audit` |

## Important Evidence Relationships

### Stage 1
E-01

### Stage 2
E-02

### Stage 3
E-03 and E-04

### Stage 4
E-05 through E-09

---

## Safe Technical Values to Keep

- `Audit`
- `Deny`
- `Disabled`
- `NonCompliant`
- `Succeeded`
- `Incremental`
- `East US`
- `eastus`
- `StorageV2`
- `Standard_LRS`
- `Microsoft.Storage/storageAccounts`
- `Microsoft.Resources/subscriptions/resourceGroups`
- `rg-*`
- generic role names such as Reader and Contributor
- deployment timestamps

---

## Values to Redact

- all `MadHat{...}` values
- Stage 1 resource-group answer
- Stage 3 deployment-name answer
- Stage 4 Description value
- storage-account name
- owner value
- subscription IDs
- tenant IDs
- usernames and tenant emails
- operative identifiers
- object/group IDs
- policy-definition GUIDs
- policy-assignment GUIDs
- full resource IDs and assignment paths
