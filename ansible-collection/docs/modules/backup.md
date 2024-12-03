# Backup Module

The backup module provides comprehensive management of PX-Backup backups, including creation, modification, deletion, inspection, and backup sharing configuration.

## Synopsis

* Create and manage backups in PX-Backup
* Control backup sharing settings
* Support both Generic and Normal backup types
* Configure namespace and resource selection
* Manage backup execution rules and policies

## Requirements

* PX-Backup >= 2.8.1
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation           | Description                          |
| --------------------- | -------------------------------------- |
| CREATE              | Create a new backup                  |
| UPDATE              | Modify existing backup configuration |
| DELETE              | Remove a backup                      |
| INSPECT_ONE         | Get details of a specific backup     |
| INSPECT_ALL         | List all backups                     |
| UPDATE_BACKUP_SHARE | Update backup sharing settings       |

## Parameters

### Common Parameters


| Parameter      | Type    | Required | Default | Description                                                                                  |
| ---------------- | --------- | ---------- | --------- | ---------------------------------------------------------------------------------------------- |
| api_url        | string  | yes      |         | PX-Backup API URL                                                                            |
| token          | string  | yes      |         | Authentication token                                                                         |
| name           | string  | varies   |         | Name of the backup (required for all operations except INSPECT_ALL)                          |
| org_id         | string  | yes      |         | Organization ID                                                                              |
| operation      | string  | yes      |         | Operation to perform                                                                         |
| uid            | string  | varies   |         | Backup unique identifier (required for UPDATE, DELETE, INSPECT_ONE, and UPDATE_BACKUP_SHARE) |
| validate_certs | boolean | no       | true    | Whether to validate SSL certificates                                                         |

### Backup Configuration Parameters


| Parameter                     | Type       | Required | Default  | Description                                                     |
| ------------------------------- | ------------ | ---------- | ---------- | ----------------------------------------------------------------- |
| backup_location_ref           | dictionary | varies   |          | Reference to backup location                                    |
| cluster_ref                   | dictionary | varies   |          | Reference to cluster                                            |
| pre_exec_rule_ref             | dictionary | varies   |          | Reference to pre exec rule                                      |
| post_exec_rule_ref            | dictionary | varies   |          | Reference to post exec rule                                     |
| backup_type                   | string     | no       | 'Normal' | Type of backup ('Generic' or 'Normal')                          |
| namespaces                    | list       | no       |          | List of namespaces to backup                                    |
| label_selectors               | dictionary | no       |          | Label selectors to choose resources                             |
| resource_types                | list       | no       |          | List of resource types to backup                                |
| exclude_resource_types        | list       | no       |          | List of resource types to exclude                               |
| backup_object_type            | dictionary | no       |          | Backup object type configuration                                |
| ns_label_selectors            | string     | no       |          | Label selectors for namespaces                                  |
| direct_kdmp                   | boolean    | no       | false    | Take backup as direct kdmp                                      |
| skip_vm_auto_exec_rules       | boolean    | no       | false    | Skip auto rules for VirtualMachine backup object type           |
| volume_snapshot_class_mapping | dictionary | no       |          | Volume snapshot class mapping for CSI based backup              |
| backup_share                  | dictionary | varies   |          | Backup sharing configuration (required for UPDATE_BACKUP_SHARE) |

#### backup_location_ref


| Parameter                | Type   | Required | Description                 |
| -------------------------- | -------- | ---------- | ----------------------------- |
| backup_location_ref.name | string | yes      | Name of the backup location |
| backup_location_ref.uid  | string | yes      | UID of the backup location  |

#### backup_object_type


| Parameter               | Type   | Required | Description                                        |
| ------------------------- | -------- | ---------- | ---------------------------------------------------- |
| backup_object_type.type | string | no       | Type of backup ('Invalid','All', 'VirtualMachine') |

#### pre_exec_rule_ref


| Parameter              | Type   | Required | Description               |
| ------------------------ | -------- | ---------- | --------------------------- |
| pre_exec_rule_ref.name | string | yes      | Name of the pre exec rule |
| pre_exec_rule_ref.uid  | string | yes      | UID of the pre exec rule  |

#### post_exec_rule_ref


| Parameter               | Type   | Required | Description                |
| ------------------------- | -------- | ---------- | ---------------------------- |
| post_exec_rule_ref.name | string | yes      | Name of the post exec rule |
| post_exec_rule_ref.uid  | string | yes      | UID of the post exec rule  |

#### cluster_ref


| Parameter        | Type   | Required | Description         |
| ------------------ | -------- | ---------- | --------------------- |
| cluster_ref.name | string | yes      | Name of the cluster |
| cluster_ref.uid  | string | yes      | UID of the cluster  |

### Resource Selection Parameters


| Parameter         | Type       | Required | Description                            |
| ------------------- | ------------ | ---------- | ---------------------------------------- |
| include_resources | list       | no       | List of specific resources to include  |
| resource_types    | list       | no       | List of resource types to backup       |
| label_selectors   | dictionary | no       | Label selectors for resource filtering |

#### include_resources Entry Format


| Parameter                   | Type   | Required | Description        |
| ----------------------------- | -------- | ---------- | -------------------- |
| include_resources.name      | string | yes      | Resource name      |
| include_resources.namespace | string | yes      | Resource namespace |
| include_resources.group     | string | yes      | Resource API group |
| include_resources.kind      | string | yes      | Resource kind      |
| include_resources.version   | string | yes      | Resource version   |

### backup_share Configuration


| Parameter                  | Type | Required | Description                         |
| ---------------------------- | ------ | ---------- | ------------------------------------- |
| backup_share.collaborators | list | no       | List of user access configurations  |
| backup_share.groups        | list | no       | List of group access configurations |

#### Access Configuration Entry Format (for both collaborators and groups)


| Parameter | Type   | Required | Choices                                       | Description              |
| ----------- | -------- | ---------- | ----------------------------------------------- | -------------------------- |
| id        | string | yes      |                                               | User or group identifier |
| access    | string | yes      | 'Invalid', 'View', 'Restorable', 'FullAccess' | Access level             |

### Enumeration Parameters


| Parameter                  | Type    | Required | Description                           |
| ---------------------------- | --------- | ---------- | --------------------------------------- |
| max_objects                | integer | no       | Maximum number of objects to return   |
| name_filter                | string  | no       | Filter backups by name                |
| cluster_name_filter        | string  | no       | Filter backups by cluster name        |
| cluster_uid_filter         | string  | no       | Filter backups by cluster UID         |
| include_detailed_resources | boolean | no       | Include detailed resource information |
| owners                     | list    | no       | Filter backups by owners              |
| status                     | list    | no       | Filter backups by status              |

### Ownership Configuration


| Parameter               | Type       | Required | Description                                |
| ------------------------- | ------------ | ---------- | -------------------------------------------- |
| ownership               | dictionary | no       | Ownership and access control configuration |
| ownership.owner         | string     | no       | Owner of the backup                        |
| ownership.groups        | list       | no       | List of group access configurations        |
| ownership.collaborators | list       | no       | List of collaborator access configurations |
| ownership.public        | dictionary | no       | Public access configuration                |

#### Ownership Access Configuration


| Parameter | Type   | Required | Choices                  | Description                      |
| ----------- | -------- | ---------- | -------------------------- | ---------------------------------- |
| id        | string | yes      |                          | Group or collaborator identifier |
| access    | string | yes      | 'Read', 'Write', 'Admin' | Access level                     |

## Error Handling

The module implements comprehensive error handling:

1. Parameter validation
2. API communication errors
3. Authentication failures
4. Resource state validation
5. Permission checks

Common error scenarios:

- Invalid credentials
- Backup not found
- Permission denied
- Invalid backup configuration
- Cloud provider errors
- Network connectivity issues

## Notes

1. **Security Considerations**

   - Secure token management
   - Proper access control configuration
   - Encryption key handling
2. **Backup Types**

   - Normal backups for standard applications
   - Generic backups for specific use cases
3. **Best Practices**

   - Regular backup validation
   - Proper namespace selection
   - Resource filtering optimization
4. **Limitations**

   - Operation-specific requirements
   - Cloud provider restrictions
