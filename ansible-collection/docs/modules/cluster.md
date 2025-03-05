# Cluster Module

The cluster module provides comprehensive management of PX-Backup clusters, including creation, modification, deletion, inspection, and access control.

## Synopsis

* Create and manage clusters in PX-Backup
* Control cluster access and sharing settings
* Configure backup sharing capabilities
* Support for multiple cloud providers
* Comprehensive cluster inspection and enumeration

## Requirements

* PX-Backup >= 2.9.0
* Stork >= 24.3.3
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation           | Description                            |
| --------------------- | ---------------------------------------- |
| CREATE              | Create a new cluster                   |
| UPDATE              | Modify existing cluster configuration  |
| DELETE              | Remove a cluster                       |
| INSPECT_ONE         | Get details of a specific cluster      |
| INSPECT_ALL         | List all clusters                      |
| UPDATE_BACKUP_SHARE | Update backup sharing settings         |
| SHARE_CLUSTER       | Share cluster access with users/groups |
| UNSHARE_CLUSTER     | Remove shared access                   |

## Parameters

### Common Parameters


| Parameter | Type       | Required | Default   | Description                                                                           |
| ----------- | ------------ | ---------- | ----------- | --------------------------------------------------------------------------------------- |
| api_url   | string     | yes      |           | PX-Backup API URL                                                                     |
| token     | string     | yes      |           | Authentication token                                                                  |
| name      | string     | yes      |           | Name of the cluster                                                                   |
| org_id    | string     | yes      | `default` | Organization ID                                                                       |
| operation | string     | yes      |           | Operation to perform                                                                  |
| uid       | string     | varies   |           | Cluster unique identifier (required for all operations except CREATE and INSPECT_ALL) |
| ownership | Dictionary | varies   |           | Ownership information                                                                 |
| labels    | string     | no       |           | Label for the cluster                                                                 |

#### Ownership Parameters


| Parameter                        | Type       | Required | Choices                  | Description                                        |
| ---------------------------------- | ------------ | ---------- | -------------------------- | ---------------------------------------------------- |
| ownership                        | dictionary | no       |                          | Cluster ownership and access control configuration |
| ownership.owner                  | string     | no       |                          | Owner of the cluster                               |
| ownership.groups                 | list       | no       |                          | List of group access configurations                |
| ownership.groups[].id            | string     | yes      |                          | Group identifier                                   |
| ownership.groups[].access        | string     | yes      | `Read`, `Write`, `Admin` | Access level for the group                         |
| ownership.collaborators          | list       | no       |                          | List of collaborator access configurations         |
| ownership.collaborators[].id     | string     | yes      |                          | Collaborator identifier                            |
| ownership.collaborators[].access | string     | yes      | `Read`, `Write`, `Admin` | Access level for the collaborator                  |
| ownership.public                 | dictionary | no       |                          | Public access configuration                        |
| ownership.public.type            | string     | no       | `Read`, `Write`, `Admin` | Public access level                                |

### Configuration Parameters


| Parameter                  | Type       | Required | Default  | Description                                                                                 |
| ---------------------------- | ------------ | ---------- | ---------- | --------------------------------------------------------------------------------------------- |
| cloud_type                 | string     | no       | `OTHERS` | Cloud provider type (`OTHERS`, `AWS`, `AZURE`, `GOOGLE`, `IBM`)                             |
| cloud_credential_ref       | dictionary | varies   |          | Reference to cloud credentials (required if cloud_type is`AWS`, `AZURE`, `GOOGLE` or `IBM`) |
| platform_credential_ref    | dictionary | varies   |          | Reference to platform credentials (Required in case of Rancher cluster)                     |
| kubeconfig                 | string     | varies   |          | Kubernetes configuration file content                                                       |
| service_token              | string     | no       |          | Service token for authentication                                                            |
| delete_restores            | string     | varies   |          | Whether to delete restores when cluster is deleted                                          |
| delete_all_cluster_backups | boolean    | no       | false    | Whether to delete all cluster backups (super admin only)                                    |
| validate_certs             | boolean    | no       | `true`   | Whether to validate SSL certificates                                                        |

#### cloud_credential_ref


| Parameter                 | Type   | Required | Description                  |
| --------------------------- | -------- | ---------- | ------------------------------ |
| cloud_credential_ref.name | string | yes      | Name of the cloud credential |
| cloud_credential_ref.uid  | string | yes      | UID of the cloud credential  |

#### platform_credential_ref


| Parameter                    | Type   | Required | Description                     |
| ------------------------------ | -------- | ---------- | --------------------------------- |
| platform_credential_ref.name | string | yes      | Name of the platform credential |
| platform_credential_ref.uid  | string | yes      | UID of the platform credential  |

#### px_config


| Parameter              | Type   | Required | Description               |
| ------------------------ | -------- | ---------- | --------------------------- |
| px_config.access_token | string | yes      | Access token for Portworx |

#### Sharing Parameters


| Parameter     | Type       | Required | Default | Description                   |
| --------------- | ------------ | ---------- | --------- | ------------------------------- |
| backup_share  | dictionary | no       |         | Backup sharing configuration  |
| cluster_share | dictionary | no       |         | Cluster sharing configuration |

#### cluster_share


| Parameter                           | Type    | Required | Default | Description                  |
| ------------------------------------- | --------- | ---------- | --------- | ------------------------------ |
| cluster_share.users                 | list    | no       |         | List of users to share with  |
| cluster_share.groups                | list    | no       |         | List of groups to share with |
| cluster_share.share_cluster_backups | boolean | no       | false   | List of users to share with  |

## Error Handling

The module implements comprehensive error handling:

1. Parameter validation
2. API communication errors
3. Authentication failures
4. Resource state validation
5. Permission checks

Common error scenarios:

- Invalid credentials
- Cluster not found
- Permission denied
- Invalid kubeconfig
- Cloud credential errors
- Network connectivity issues

## Notes

1. **Security Considerations**

   - Secure handling of kubeconfig files
   - Proper access control configuration
   - Token security
2. **Cloud Provider Integration**

   - Specific requirements for each cloud provider
   - Credential management
   - Regional considerations
3. **Best Practices**

   - Regular cluster status monitoring
   - Backup share management
   - Access control review
4. **Limitations**

   - Operation-specific requirements
