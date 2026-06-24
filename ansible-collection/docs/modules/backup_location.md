# Backup Location Module

The backup location module provides comprehensive management of PX-Backup storage locations, including creation, modification, deletion, validation, inspection, ownership management, and backup sync (federated mode) for S3, Azure, Google, and NFS storage destinations.

## Synopsis

- Create and manage backup locations in PX-Backup
- Support for multiple storage providers (S3, Azure, Google, NFS)
- Validate backup location configurations
- Manage backup location ownership and access control
- Comprehensive inspection and enumeration capabilities
- Trigger on-demand backup sync from object store (federated mode)

## Requirements

- PX-Backup >= 3.0.0
- Stork >= 25.3.0
- Python >= 3.9
- The `requests` Python package

## Operations

The module supports the following operations:

| Operation        | Description                                                                       |
| ---------------- | --------------------------------------------------------------------------------- |
| CREATE           | Create a new backup location                                                      |
| UPDATE           | Modify existing backup location                                                   |
| DELETE           | Remove a backup location                                                          |
| VALIDATE         | Validate backup location configuration (per-cluster validation in federated mode) |
| INSPECT_ONE      | Get details of a specific backup location                                         |
| INSPECT_ALL      | List all backup locations                                                         |
| UPDATE_OWNERSHIP | Update ownership settings                                                         |
| SYNC             | Trigger backup sync from object store (federated mode only)                       |

## Parameters

### Common Parameters

| Parameter      | Type    | Required | Default | Description                                                                  |
| -------------- | ------- | -------- | ------- | ---------------------------------------------------------------------------- |
| api_url        | string  | yes      |         | PX-Backup API URL                                                            |
| token          | string  | yes      |         | Authentication token                                                         |
| name           | string  | varies   |         | Name of the backup location (required for all operations except INSPECT_ALL) |
| org_id         | string  | yes      |         | Organization ID                                                              |
| operation      | string  | yes      |         | Operation to perform                                                         |
| uid            | string  | varies   |         | Backup location unique identifier                                            |
| validate_certs | boolean | no       | true    | Whether to validate SSL certificates                                         |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### Location Configuration Parameters

| Parameter                 | Type       | Required | Default                        | Description                                | Choices                        |
| ------------------------- | ---------- | -------- | ------------------------------ | ------------------------------------------ | ------------------------------ |
| location_type             | string     | varies   |                                | Type of backup location                    | `S3`, `Azure`, `Google`, `NFS` |
| path                      | string     | varies   |                                | Path/bucket name for the backup location   |                                |
| encryption_key            | string     | no       |                                | Encryption key for backup data             |                                |
| validate_cloud_credential | boolean    | no       | true                           | Whether to validate cloud credentials      |                                |
| object_lock_enabled       | boolean    | no       | false                          | Enable object lock for S3 backup locations |                                |
| cloud_credential_ref      | dictionary | no       | Reference to cloud credentials |                                            |                                |

### Sync Parameters (SYNC operation)

| Parameter           | Type    | Required | Default | Description                                                 |
| ------------------- | ------- | -------- | ------- | ----------------------------------------------------------- |
| sync                | boolean | no       | false   | Trigger backup sync (can also be used with CREATE/UPDATE)   |
| wait_for_completion | boolean | no       | false   | Wait for the asynchronous server-side operation to complete |
| sync_timeout        | integer | no       | 600     | Max seconds to wait for sync completion                     |
| sync_poll_interval  | integer | no       | 10      | Seconds between status polls when waiting for completion    |

> **Note:** The SYNC operation is only available when PX-Backup is running in federated deployment mode.
> Backup sync discovers backups in the object store bucket that are not yet tracked in PX-Backup and imports them.
> The sync is on-demand (not automatic or periodic). Parallel sync triggers while another sync is in progress are not allowed.

### Validation Parameters (federated / Workload Identity)

In federated deployment mode, BackupLocations rely on cluster-level identities (Workload Identity)
instead of a global cloud credential. Validation is performed per-cluster, asynchronously by Stork
on each associated cluster. The API triggers validation and returns immediately — poll with
`INSPECT_ONE` to observe progress.

| Parameter    | Type | Required | Default | Description                                                                 |
| ------------ | ---- | -------- | ------- | --------------------------------------------------------------------------- |
| cluster_refs | list | no       |         | Subset of associated clusters to (re)validate; omit to validate all of them |

The `cluster_refs` parameter is required for `CREATE` / `UPDATE` when `federated: true`. For
`VALIDATE`, it is optional — omit to re-validate all associated clusters, or supply a subset to
scope the call.

> **Note:** `CREATE` and `UPDATE` automatically trigger validation on every cluster in
> `cluster_refs`. On `UPDATE`, the entire `cluster_status` map is replaced and **all** associated
> clusters are re-validated — not just newly added ones. Users who remove a cluster from
> `cluster_refs` on `UPDATE` should expect the remaining clusters to also cycle through
> `Pending` / `InProgress` before reaching a terminal state.

> **VALIDATE output:** `BackupLocationValidateResponse` is empty — `backup_location` will be `{}`
> after a VALIDATE call. Use `INSPECT_ONE` to observe per-cluster validation progress.
>
> **CREATE / UPDATE output:** `backup_location.backup_location_info.cluster_status` contains the
> per-cluster validation state at the moment the write completed, and
> `backup_location.backup_location_info.status` contains the overall status. Since validation is
> asynchronous, these may show `Pending` or `InProgress` — use `INSPECT_ONE` to poll for the
> final state.

### cloud_credential_ref Reference

| Parameter                                  | Type   | Required | Description                  |
| ------------------------------------------ | ------ | -------- | ---------------------------- |
| cloud_credential_ref.cloud_credential_name | string | yes      | Name of the cloud credential |
| cloud_credential_ref.cloud_credential_uid  | string | no       | UID of the cloud credential  |

### Storage Provider Configurations

#### S3 Configuration

| Parameter                           | Type    | Required | Description                 | Choices                                  |
| ----------------------------------- | ------- | -------- | --------------------------- | ---------------------------------------- |
| s3_config.endpoint                  | string  | no       | S3 endpoint URL             |                                          |
| s3_config.region                    | string  | no       | S3 region                   |                                          |
| s3_config.disable_ssl               | boolean | no       | Disable SSL verification    |                                          |
| s3_config.disable_path_style        | boolean | no       | Disable path style access   |                                          |
| s3_config.storage_class             | string  | no       | S3 storage class            |                                          |
| s3_config.sse_type                  | string  | no       | Server-side encryption type | 'Invalid', 'SSE_S3', 'SSE_KMS'           |
| s3_config.azure_environment.type    | string  | no       | Azure environment type      | 'Invalid', 'AZURE_GLOBAL', 'AZURE_CHINA' |
| s3_config.azure_resource_group_name | string  | no       | Azure resource group name   |                                          |
| s3_config.azure_account_name        | string  | no       | Azure storage account name (federated Azure) |                               |
| s3_config.azure_subscription_id     | string  | no       | Azure subscription ID (federated Azure)      |                               |
| s3_config.google_project_id         | string  | no       | Google Cloud project ID (required for federated Google) |                    |

> **Workload Identity (federated) notes:**
> - **AWS S3** (`location_type: S3`, `federated: true`): uses AWS IRSA / EKS Pod Identity, no cloud credential. `endpoint` and `disable_ssl` are ignored (TLS always enforced); `region` is optional and falls back to `AWS_REGION` on the Stork pod if omitted.
> - **Azure** (`location_type: Azure`, `federated: true`): provide `azure_account_name` and `azure_subscription_id` in `s3_config`.
> - **Google** (`location_type: Google`, `federated: true`): `google_project_id` is required in `s3_config` since no cloud credential is referenced. It is immutable, so it is only set on `CREATE`.

#### NFS Configuration

| Parameter               | Type   | Required | Description           |
| ----------------------- | ------ | -------- | --------------------- |
| nfs_config.server_addr  | string | yes      | NFS server address    |
| nfs_config.sub_path     | string | yes      | Sub path on NFS share |
| nfs_config.mount_option | string | no       | NFS mount options     |

#### Azure Configuration

| Parameter                      | Type   | Required | Description            |
| ------------------------------ | ------ | -------- | ---------------------- |
| azure_config.account_name      | string | yes      | Azure account name     |
| azure_config.account_key       | string | yes      | Azure account key      |
| azure_config.client_secret     | string | yes      | Azure client secret    |
| azure_config.client_id         | string | yes      | Azure client ID        |
| azure_config.tenant_id         | string | yes      | Azure tenant ID        |
| azure_config.subscription_id   | string | yes      | Azure subscription ID  |
| azure_config.azure_environment | string | no       | Azure environment type |

#### Google Configuration

| Parameter                | Type   | Required | Description                     |
| ------------------------ | ------ | -------- | ------------------------------- |
| google_config.project_id | string | yes      | Google project ID               |
| google_config.json_key   | string | yes      | Google service account JSON key |

### Ownership Configuration

| Parameter               | Type       | Required | Description                                |
| ----------------------- | ---------- | -------- | ------------------------------------------ |
| ownership               | dictionary | varies   | Ownership and access control configuration |
| ownership.owner         | string     | no       | Owner of the backup location               |
| ownership.groups        | list       | no       | List of group access configurations        |
| ownership.collaborators | list       | no       | List of collaborator access configurations |
| ownership.public        | dictionary | no       | Public access configuration                |

#### Access Configuration (for groups and collaborators)

| Parameter | Type   | Required | Choices                             | Description                      |
| --------- | ------ | -------- | ----------------------------------- | -------------------------------- |
| id        | string | yes      |                                     | Group or collaborator identifier |
| access    | string | yes      | 'Invalid', 'Read', 'Write', 'Admin' | Access level                     |

## Error Handling

The module implements comprehensive error handling:

1. Parameter validation
2. API communication errors
3. Authentication failures
4. Resource state validation
5. Permission checks
6. Cloud provider-specific validations

Common error scenarios:

- Invalid credentials
- Location not found
- Permission denied
- Invalid configuration
- Cloud provider errors
- Network connectivity issues

## Notes

1. **Security Considerations**
   - Secure token management
   - Encryption key handling
   - Cloud credential security
   - Access control configuration

2. **Storage Provider Considerations**
   - Provider-specific requirements
   - Regional restrictions
   - Access permissions
   - Storage class options

3. **Best Practices**
   - Regular validation checks
   - Proper access control
   - Encryption configuration
   - Monitoring and maintenance

4. **Limitations**
   - Operation-specific requirements
   - Provider-specific restrictions
   - Storage limitations
