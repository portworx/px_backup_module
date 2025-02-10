# Backup Location Module

The backup location module provides comprehensive management of PX-Backup storage locations, including creation, modification, deletion, validation, inspection, and ownership management for S3, Azure, Google, and NFS storage destinations.

## Synopsis

* Create and manage backup locations in PX-Backup
* Support for multiple storage providers (S3, Azure, Google, NFS)
* Validate backup location configurations
* Manage backup location ownership and access control
* Comprehensive inspection and enumeration capabilities

## Requirements

* PX-Backup >= 2.8.3
* Stork >= 24.3.3
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation        | Description                               |
| ------------------ | ------------------------------------------- |
| CREATE           | Create a new backup location              |
| UPDATE           | Modify existing backup location           |
| DELETE           | Remove a backup location                  |
| VALIDATE         | Validate backup location configuration    |
| INSPECT_ONE      | Get details of a specific backup location |
| INSPECT_ALL      | List all backup locations                 |
| UPDATE_OWNERSHIP | Update ownership settings                 |

## Parameters

### Common Parameters


| Parameter      | Type    | Required | Default | Description                                                                                                  |
| ---------------- | --------- | ---------- | --------- | -------------------------------------------------------------------------------------------------------------- |
| api_url        | string  | yes      |         | PX-Backup API URL                                                                                            |
| token          | string  | yes      |         | Authentication token                                                                                         |
| name           | string  | varies   |         | Name of the backup location (required for all operations except INSPECT_ALL)                                 |
| org_id         | string  | yes      |         | Organization ID                                                                                              |
| operation      | string  | yes      |         | Operation to perform                                                                                         |
| uid            | string  | varies   |         | Backup location unique identifier (required for UPDATE, DELETE, VALIDATE, INSPECT_ONE, and UPDATE_OWNERSHIP) |
| validate_certs | boolean | no       | true    | Whether to validate SSL certificates                                                                         |

### Location Configuration Parameters


| Parameter                 | Type       | Required | Default                        | Description                                | Choices                        |
| --------------------------- | ------------ | ---------- | -------------------------------- | -------------------------------------------- | -------------------------------- |
| location_type             | string     | varies   |                                | Type of backup location                    | `S3`, `Azure`, `Google`, `NFS` |
| path                      | string     | varies   |                                | Path/bucket name for the backup location   |                                |
| encryption_key            | string     | no       |                                | Encryption key for backup data             |                                |
| validate_cloud_credential | boolean    | no       | true                           | Whether to validate cloud credentials      |                                |
| object_lock_enabled       | boolean    | no       | false                          | Enable object lock for S3 backup locations |                                |
| cloud_credential_ref      | dictionary | no       | Reference to cloud credentials |                                            |                                |

### cloud_credential_ref Reference


| Parameter                                  | Type   | Required | Description                  |
| -------------------------------------------- | -------- | ---------- | ------------------------------ |
| cloud_credential_ref.cloud_credential_name | string | yes      | Name of the cloud credential |
| cloud_credential_ref.cloud_credential_uid  | string | yes      | UID of the cloud credential  |

### Storage Provider Configurations

#### S3 Configuration


| Parameter                           | Type    | Required | Description                 | Choices                                  |
| ------------------------------------- | --------- | ---------- | ----------------------------- | ------------------------------------------ |
| s3_config.endpoint                  | string  | no       | S3 endpoint URL             |                                          |
| s3_config.region                    | string  | no       | S3 region                   |                                          |
| s3_config.disable_ssl               | boolean | no       | Disable SSL verification    |                                          |
| s3_config.disable_path_style        | boolean | no       | Disable path style access   |                                          |
| s3_config.storage_class             | string  | no       | S3 storage class            |                                          |
| s3_config.sse_type                  | string  | no       | Server-side encryption type | 'Invalid', 'SSE_S3', 'SSE_KMS'           |
| s3_config.azure_environment.type    | string  | no       | Azure environment type      | 'Invalid', 'AZURE_GLOBAL', 'AZURE_CHINA' |
| s3_config.azure_resource_group_name | string  | no       | Azure resource group name   |                                          |

#### NFS Configuration


| Parameter               | Type   | Required | Description           |
| ------------------------- | -------- | ---------- | ----------------------- |
| nfs_config.server_addr  | string | yes      | NFS server address    |
| nfs_config.sub_path     | string | yes      | Sub path on NFS share |
| nfs_config.mount_option | string | no       | NFS mount options     |

#### Azure Configuration


| Parameter                      | Type   | Required | Description            |
| -------------------------------- | -------- | ---------- | ------------------------ |
| azure_config.account_name      | string | yes      | Azure account name     |
| azure_config.account_key       | string | yes      | Azure account key      |
| azure_config.client_secret     | string | yes      | Azure client secret    |
| azure_config.client_id         | string | yes      | Azure client ID        |
| azure_config.tenant_id         | string | yes      | Azure tenant ID        |
| azure_config.subscription_id   | string | yes      | Azure subscription ID  |
| azure_config.azure_environment | string | no       | Azure environment type |

#### Google Configuration


| Parameter                | Type   | Required | Description                     |
| -------------------------- | -------- | ---------- | --------------------------------- |
| google_config.project_id | string | yes      | Google project ID               |
| google_config.json_key   | string | yes      | Google service account JSON key |

### Ownership Configuration


| Parameter               | Type       | Required | Description                                |
| ------------------------- | ------------ | ---------- | -------------------------------------------- |
| ownership               | dictionary | varies   | Ownership and access control configuration |
| ownership.owner         | string     | no       | Owner of the backup location               |
| ownership.groups        | list       | no       | List of group access configurations        |
| ownership.collaborators | list       | no       | List of collaborator access configurations |
| ownership.public        | dictionary | no       | Public access configuration                |

#### Access Configuration (for groups and collaborators)


| Parameter | Type   | Required | Choices                             | Description                      |
| ----------- | -------- | ---------- | ------------------------------------- | ---------------------------------- |
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
