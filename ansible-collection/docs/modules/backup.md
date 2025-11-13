# Backup Module

The backup module provides comprehensive management of PX-Backup backups, including creation, modification, deletion, inspection, and backup sharing configuration.

## Synopsis

* Create and manage backups in PX-Backup
* Control backup sharing settings
* Support both Generic and Normal backup types
* Configure namespace and resource selection
* Manage backup execution rules and policies
* Support for VM-specific backup operations
* Retry failed or partially successful backups
* Enhanced filtering and sorting capabilities

## Requirements

* PX-Backup >= 2.11.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## API Changes Notice

### Enhanced Features in v2.11.0

This module has been updated to support enhanced API capabilities:

- **GetBackupResourceDetails**: Now uses POST method with advanced filtering options
- **LastUpdateTimestamp Sorting**: Sort backups by last modification time for better chronological ordering
- **Enhanced Filtering**: Support for namespace patterns, resource exclusions, GVK filtering, and Virtual Machines.
- **Improved Performance**: Optimized API calls for large datasets

**Backward Compatibility**: Please note that API changes in recent PX-Backup versions may cause incompatibilities - ensure your module version matches your PX-Backup installation version for optimal compatibility.

## Operations

The module supports the following operations:


| Operation                   | Description                                  |
| ----------------------------- | ---------------------------------------------- |
| CREATE                      | Create a new backup                          |
| UPDATE                      | Modify existing backup configuration         |
| DELETE                      | Remove a backup                              |
| INSPECT_ONE                 | Get details of a specific backup             |
| INSPECT_ALL                 | List all backups                             |
| UPDATE_BACKUP_SHARE         | Update backup sharing settings               |
| GET_BACKUP_RESOURCE_DETAILS | Get detailed backup resource information     |
| RETRY_BACKUP_RESOURCES      | Retry failed or partially successful backups |

## Parameters

### Common Parameters


| Parameter      | Type    | Required | Default | Description                                                         |
| ---------------- | --------- | ---------- | --------- | --------------------------------------------------------------------- |
| api_url        | string  | yes      |         | PX-Backup API URL                                                   |
| token          | string  | yes      |         | Authentication token                                                |
| name           | string  | varies   |         | Name of the backup (required for all operations except INSPECT_ALL) |
| org_id         | string  | yes      |         | Organization ID                                                     |
| operation      | string  | yes      |         | Operation to perform                                                |
| uid            | string  | varies   |         | Unique identifier of the backup                                     |
| validate_certs | boolean | no       | true    | Whether to validate SSL certificates                                |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### Backup Configuration Parameters


| Parameter                        | Type       | Required | Default  | Description                                                                 |
| ---------------------------------- | ------------ | ---------- | ---------- | ----------------------------------------------------------------------------- |
| backup_location_ref              | dictionary | varies   |          | Reference to backup location                                                |
| cluster_ref                      | dictionary | varies   |          | Reference to cluster                                                        |
| pre_exec_rule_ref                | dictionary | no       |          | Reference to pre exec rule                                                  |
| post_exec_rule_ref               | dictionary | no       |          | Reference to post exec rule                                                 |
| backup_type                      | string     | no       | 'Normal' | Type of backup ('Generic' or 'Normal')                                      |
| namespaces                       | list       | no       |          | List of namespaces to backup                                                |
| label_selectors                  | dictionary | no       |          | Label selectors to choose resources                                         |
| resource_types                   | list       | no       |          | List of resource types to backup                                            |
| exclude_resource_types           | list       | no       |          | List of resource types to exclude                                           |
| backup_object_type               | dictionary | no       |          | Backup object type configuration                                            |
| ns_label_selectors               | string     | no       |          | Label selectors for namespaces                                              |
| cluster                          | string     | no       |          | Name or UID of the cluster                                                  |
| direct_kdmp                      | boolean    | no       | false    | Take backup as direct kdmp                                                  |
| skip_vm_auto_exec_rules          | boolean    | no       | false    | Skip auto rules for VirtualMachine backup object type                       |
| volume_snapshot_class_mapping    | dictionary | no       |          | Volume snapshot class mapping for CSI based backup                          |
| parallel_backup                  | boolean    | no       | false    | Option to enable parallel schedule backups                                  |
| keep_cr_status                   | boolean    | no       | false    | Option to enable to keep the CR status of the resources in the backup       |
| advanced_resource_label_selector | string     | no       |          | Advanced label selector for resources (string format with operator support) |
| volume_resource_only_policy_ref  | dictionary | no       |          | Reference to Volume Resource Only policy                                    |
| cloud_credential_ref             | dictionary | no       |          | Reference to cloud credentials for backup                                   |

#### backup_location_ref


| Parameter                | Type   | Required | Description                 |
| -------------------------- | -------- | ---------- | ----------------------------- |
| backup_location_ref.name | string | no       | Name of the backup location |
| backup_location_ref.uid  | string | no       | UID of the backup location  |

#### backup_object_type


| Parameter               | Type   | Required | Description                                         |
| ------------------------- | -------- | ---------- | ----------------------------------------------------- |
| backup_object_type.type | string | no       | Type of backup ('Invalid', 'All', 'VirtualMachine') |

#### pre_exec_rule_ref


| Parameter              | Type   | Required | Description               |
| ------------------------ | -------- | ---------- | --------------------------- |
| pre_exec_rule_ref.name | string | no       | Name of the pre exec rule |
| pre_exec_rule_ref.uid  | string | no       | UID of the pre exec rule  |

#### post_exec_rule_ref


| Parameter               | Type   | Required | Description                |
| ------------------------- | -------- | ---------- | ---------------------------- |
| post_exec_rule_ref.name | string | no       | Name of the post exec rule |
| post_exec_rule_ref.uid  | string | no       | UID of the post exec rule  |

#### cluster_ref


| Parameter        | Type   | Required | Description         |
| ------------------ | -------- | ---------- | --------------------- |
| cluster_ref.name | string | no       | Name of the cluster |
| cluster_ref.uid  | string | no       | UID of the cluster  |

#### volume_resource_only_policy_ref


| Parameter                            | Type   | Required | Description                             |
| -------------------------------------- | -------- | ---------- | ----------------------------------------- |
| volume_resource_only_policy_ref.name | string | no       | Name of the Volume Resource Only policy |
| volume_resource_only_policy_ref.uid  | string | no       | UID of the Volume Resource Only policy  |

#### cloud_credential_ref


| Parameter                 | Type   | Required | Description                  |
| --------------------------- | -------- | ---------- | ------------------------------ |
| cloud_credential_ref.name | string | no       | Name of the cloud credential |
| cloud_credential_ref.uid  | string | no       | UID of the cloud credential  |

### Resource Selection Parameters


| Parameter         | Type       | Required | Description                            |
| ------------------- | ------------ | ---------- | ---------------------------------------- |
| include_resources | list       | no       | List of specific resources to include  |
| resource_types    | list       | no       | List of resource types to backup       |
| label_selectors   | dictionary | no       | Label selectors for resource filtering |

#### include_resources Entry Format


| Parameter                   | Type   | Required | Description        |
| ----------------------------- | -------- | ---------- | -------------------- |
| include_resources.name      | string | no       | Resource name      |
| include_resources.namespace | string | no       | Resource namespace |
| include_resources.gvk       | string | yes      | Group-Version-Kind string (e.g., "v1/Service", "apps/v1/Deployment") |

### Backup Sharing Configuration


| Parameter                  | Type       | Required | Description                                                     |
| ---------------------------- | ------------ | ---------- | ----------------------------------------------------------------- |
| backup_share               | dictionary | varies   | Backup sharing configuration (required for UPDATE_BACKUP_SHARE) |
| backup_share.collaborators | list       | no       | List of user access configurations                              |
| backup_share.groups        | list       | no       | List of group access configurations                             |

#### Access Configuration Entry Format (for both collaborators and groups)


| Parameter | Type   | Required | Choices                                       | Description              |
| ----------- | -------- | ---------- | ----------------------------------------------- | -------------------------- |
| id        | string | yes      |                                               | User or group identifier |
| access    | string | yes      | 'Invalid', 'View', 'Restorable', 'FullAccess' | Access level             |

### Metadata and Labels


| Parameter | Type       | Required | Description                    |
| ----------- | ------------ | ---------- | -------------------------------- |
| labels    | dictionary | no       | Labels to attach to the backup |

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

#### Public Access Configuration


| Parameter | Type   | Required | Choices                  | Description         |
| ----------- | -------- | ---------- | -------------------------- | --------------------- |
| type      | string | yes      | 'Read', 'Write', 'Admin' | Public access level |

### Enumeration and Filtering Parameters


| Parameter                  | Type       | Required | Default | Description                                       |
| ---------------------------- | ------------ | ---------- | --------- | --------------------------------------------------- |
| max_objects                | integer    | no       |         | Maximum number of objects to return               |
| name_filter                | string     | no       |         | Filter backups by name                            |
| cluster_name_filter        | string     | no       |         | Filter backups by cluster name                    |
| cluster_uid_filter         | string     | no       |         | Filter backups by cluster UID                     |
| include_detailed_resources | boolean    | no       | false   | Include detailed resource information             |
| owners                     | list       | no       |         | Filter backups by owners (list of owner UIDs)     |
| status                     | list       | no       |         | Filter backups by status (list of status strings) |
| schedule_policy_ref        | list       | no       |         | List of schedule policy references to filter by   |
| backup_schedule_ref        | list       | no       |         | List of backup schedule references to filter by   |
| sort_option                | dictionary | no       |         | Sorting configuration for backup enumeration      |

### New Filtration Parameters (v2.11.0+)

| Parameter                  | Type    | Required | Default | Description                    |
| ---------------------------- | --------- | ---------- | --------- | -------------------------------- |
| vm_volume_name             | string  | no       |         | Filter VM that matches the resource_info and has volume vm_volume_name attached to it |
| exclude_failed_resource    | boolean | no       | false   | Filter to exclude failed resources while enumerating objects |

#### Schedule Policy/Backup Schedule Reference Format


| Parameter | Type   | Required | Description                                 |
| ----------- | -------- | ---------- | --------------------------------------------- |
| name      | string | yes      | Name of the schedule policy/backup schedule |
| uid       | string | no       | UID of the schedule policy/backup schedule  |

#### Sort Option Format


| Parameter  | Type   | Required | Choices                                                                                    | Default             | Description      |
| ------------ | -------- | ---------- | -------------------------------------------------------------------------------------------- | --------------------- | ------------------ |
| sort_by    | string | no       | 'CreationTimestamp', 'Name', 'ClusterName', 'Size', 'RestoreBackupName', 'LastUpdateTimestamp' | 'CreationTimestamp' | Field to sort by |
| sort_order | string | no       | 'Ascending', 'Descending'                                                                  | 'Descending'        | Sort order       |

## Return Values


| Name    | Type       | Description                                      |
| --------- | ------------ | -------------------------------------------------- |
| changed | boolean    | Whether the operation changed the backup         |
| backup  | dictionary | Details of the backup for single-item operations |
| backups | list       | List of backups (for INSPECT_ALL operation)      |
| message | string     | Operation result message                         |

### Backup Object Structure

The returned backup object contains:

```yaml
backup:
  metadata:
    name: string
    org_id: string
    uid: string
    labels: dict
    ownership:
      owner: string
      groups: list
      collaborators: list
      public: dict
  backup_info:
    cluster: string
    namespaces: list
    backup_type: string
    label_selectors: dict
    resources: list
    status:
      status: string
      reason: string
    backup_path: string
    total_size: int
    resource_count: int
    stork_version: string
    backup_object_type: string
    direct_kdmp: boolean
    completion_time_info:
      volumes_completion_time: string
      resources_completion_time: string
      total_completion_time: string
```

## Examples

### Create a New Backup

```yaml
- name: Create backup
  backup:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-backup"
    org_id: "default"
    backup_location_ref:
      name: "s3-location"
      uid: "location-uid"
    cluster_ref:
      name: "prod-cluster"
      uid: "cluster-uid"
    namespaces:
      - "app1"
      - "app2"
    backup_type: "Normal"
    advanced_resource_label_selector: "env=prod"
    labels:
      environment: "production"
      team: "platform"
```

### Update Backup with Ownership

```yaml
- name: Update backup ownership
  backup:
    operation: UPDATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-backup"
    org_id: "default"
    uid: "backup-uid"
    ownership:
      owner: "admin@company.com"
      groups:
        - id: "platform-team"
          access: "Write"
        - id: "devops"
          access: "Admin"
      collaborators:
        - id: "john.doe@company.com"
          access: "Read"
      public:
        type: "Read"
```

### List All Backups with Filtering

```yaml
- name: List all backups
  backup:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    cluster_name_filter: "prod-cluster"
    schedule_policy_ref:
      - name: "daily-policy"
        uid: "policy-uid-123"
    sort_option:
      sort_by: "CreationTimestamp"
      sort_order: "Descending"
    max_objects: 50

# List backups sorted by last update timestamp
- name: List recently updated backups
  backup:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    sort_option:
      sort_by: "LastUpdateTimestamp"
      sort_order: "Descending"
    max_objects: 20
```

### Update Backup Sharing

```yaml
- name: Update backup sharing
  backup:
    operation: UPDATE_BACKUP_SHARE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-backup"
    org_id: "default"
    uid: "backup-uid"
    backup_share:
      collaborators:
        - id: "user1@example.com"
          access: "View"
        - id: "user2@example.com"
          access: "Restorable"
      groups:
        - id: "backup-viewers"
          access: "View"
        - id: "backup-admins"
          access: "FullAccess"
```

### Get Backup Resource Details

```yaml
- name: Get VM backup details
  backup:
    operation: GET_BACKUP_RESOURCE_DETAILS
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "vm-backup"
    org_id: "default"
    uid: "backup-uid"
```

#### Advanced Usage with Filtering

```yaml
- name: Get VM backup details with advanced filtering
  backup:
    operation: GET_BACKUP_RESOURCE_DETAILS
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "vm-backup"
    org_id: "default"
    uid: "backup-uid"
    # Enhanced filtering options
    force_resync: false
    sync_namespaces_only: false
    max_objects: 100
    object_index: 0
    resource_status_filter:
      - "Success"
      - "Failed"
    namespace_filter:
      namespace_name_pattern: "prod-*"
      include_namespaces:
        - "production"
        - "staging"
      gvks:
        - "apps/v1/Deployment"
        - "v1/Pod"
      resource_name_pattern: "app-*"
    virtual_machine_filter:
      vm_name_pattern: "vm-prod-*"
```

### Retry Failed Backup

```yaml
- name: Retry failed VM backup
  backup:
    operation: RETRY_BACKUP_RESOURCES
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "failed-backup"
    org_id: "default"
    uid: "backup-uid"
    skip_vm_auto_exec_rules: true
    include_resources:
      - name: "vm-1"
        namespace: "default"
        gvk: "kubevirt.io/v1/VirtualMachine"
```

### Delete Backup

```yaml
- name: Delete backup
  backup:
    operation: DELETE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "old-backup"
    org_id: "default"
    uid: "backup-uid"
    cluster_ref:
      name: "prod-cluster"
      uid: "cluster-uid"
```

## Error Handling

The module implements comprehensive error handling:

1. **Parameter validation**

   - Required parameter checks
   - Format validation
   - Reference validation
2. **API communication errors**

   - Network connectivity issues
   - API endpoint availability
   - Request/response handling
3. **Authentication failures**

   - Invalid tokens
   - Expired credentials
   - Permission denied
4. **Resource state validation**

   - Backup existence checks
   - State compatibility
   - Operation prerequisites
5. **Permission checks**

   - Access control validation
   - Organization permissions
   - Resource ownership

Common error scenarios:

- Invalid credentials
- Backup not found
- Permission denied
- Invalid backup configuration
- Cloud provider errors
- Network connectivity issues
- Missing references (cluster, location)
- Invalid label selectors

## Notes

1. **Security Considerations**

   - Secure token management (use Ansible vault)
   - Proper access control configuration
   - Encryption key handling
2. **Backup Types**

   - Normal backups for standard applications
   - Generic backups for specific use cases
   - VirtualMachine backups for VM workloads
3. **Best Practices**

   - Regular backup validation
   - Proper namespace selection
   - Resource filtering optimization
   - Use labels for organization
   - Monitor backup status
   - Configure appropriate retention
   - Test restore procedures
4. **Performance Considerations**

   - Optimize resource selection
   - Consider backup window timing
   - Monitor resource usage
5. **Limitations**

   - Operation-specific requirements
   - Cloud provider restrictions
   - Storage capacity constraints
   - Network bandwidth considerations
6. **Version Compatibility**

   - GET_BACKUP_RESOURCE_DETAILS requires newer PX-Backup versions
   - RETRY_BACKUP_RESOURCES requires newer PX-Backup versions
   - Some filtering options require specific versions
   - Check PX-Backup release notes for feature availability

## GVK Format Guidelines

When specifying Group-Version-Kind (GVK) in resource filtering:

- **Core resources**: Use `"version/kind"` format (e.g., `"v1/Service"`, `"v1/Pod"`, `"v1/ConfigMap"`)
- **Non-core resources**: Use `"group/version/kind"` format (e.g., `"apps/v1/Deployment"`, `"batch/v1/Job"`)
- **Custom resources**: Use full `"group/version/kind"` format (e.g., `"kubevirt.io/v1/VirtualMachine"`)

### Examples:

```yaml
include_resources:
  # Core resources (no group)
  - name: "my-service"
    namespace: "default"
    gvk: "v1/Service"
  - name: "my-configmap"
    namespace: "default"
    gvk: "v1/ConfigMap"

  # Apps group resources
  - name: "my-deployment"
    namespace: "production"
    gvk: "apps/v1/Deployment"

  # Batch resources
  - name: "my-job"
    namespace: "default"
    gvk: "batch/v1/Job"

  # Custom resources
  - name: "my-vm"
    namespace: "vms"
    gvk: "kubevirt.io/v1/VirtualMachine"
```

### Server-Side Validation

The Ansible module acts as a pure facilitator, allowing the PX-Backup server to handle all business logic validation:

- **Ansible validates**: Required parameters, parameter types, SSL certificates
- **Server validates**: Resource existence, parameter conflicts, business rules
- **Result**: Clean separation of concerns with authoritative server validation

## Troubleshooting

1. **Backup Creation Issues**

   - Verify cluster connectivity
   - Check backup location accessibility
   - Ensure namespaces exist
   - Validate label selector syntax
   - Review resource permissions
2. **Filtering and Enumeration Issues**

   - Use POST method for complex queries
   - Verify filter syntax
   - Check parameter combinations
   - Review API version support
3. **Sharing and Access Issues**

   - Verify user/group identifiers
   - Check access level compatibility
   - Ensure organization membership
   - Review sharing permissions
4. **Retry Operation Issues**

   - Verify backup state (failed/partial)
   - Check resource specifications
   - Ensure cluster connectivity
   - Review execution rules
