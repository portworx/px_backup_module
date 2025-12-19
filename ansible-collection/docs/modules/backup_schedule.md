# Backup Schedule Module

The backup schedule module enables management of automated backup schedules in PX-Backup, providing capabilities for creating, modifying, inspecting, and deleting backup schedules.

## Synopsis

* Create and manage backup schedules in PX-Backup
* Configure scheduled backups with customization options
* Support for multiple backup types and configurations
* Comprehensive resource selection and filtering
* Flexible scheduling policies and retention controls
* Enhanced filtering and sorting in 2.9.0+
* VM-specific backup capabilities
* Cluster scope support (2.11.0+)

## Requirements

* PX-Backup >= 2.11.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation                | Description                                           |
| -------------------------- | ------------------------------------------------------- |
| CREATE                   | Create a new backup schedule                          |
| UPDATE                   | Modify existing backup schedule                       |
| DELETE                   | Remove a backup schedule                              |
| INSPECT_ONE              | Get details of a specific backup schedule             |
| INSPECT_ALL              | List all backup schedules (GET method)                |
| INSPECT_ALL_POST_REQUEST | List all backup schedules using POST request (2.9.0+) |

## Parameters

### Common Parameters

| Parameter      | Type    | Required | Default | Description                             | Supported Versions |
| ---------------- | --------- | ---------- | --------- | ----------------------------------------- | ------------------- |
| api_url        | string  | yes      |         | PX-Backup API URL                       |
| token          | string  | yes      |         | Authentication token                    |
| operation      | string  | yes      |         | Operation to perform                    |
| name           | string  | yes      |         | Name of the backup schedule             |
| org_id         | string  | yes      |         | Organization ID                         |
| uid            | string  | varies   |         | Unique identifier                       |
| owner          | string  | no       |         | Owner name or uid                       |
| validate_certs | boolean | no       | true    | Verify SSL certificates                 |
| labels         | dict    | no       |         | Labels to attach to the Backup Schedule |
| remark         | string  | no       |         | Last remark made during update operation|  2.10.0

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### Schedule Configuration Parameters


| Parameter                        | Type    | Required | Default  | Description                                                                    |
| ---------------------------------- | --------- | ---------- | ---------- | -------------------------------------------------------------------------------- |
| reclaim_policy                   | string  | no       |          | Policy for backup retention (`Invalid`, `Delete`, `Retain`)                    |
| backup_type                      | string  | no       | `Normal` | Type of backup (`Invalid`, `Generic`, `Normal`)                                |
| suspend                          | boolean | no       | `false`  | Whether to suspend the schedule                                                |
| direct_kdmp                      | boolean | no       | `false`  | Enable direct KDMP backup                                                      |
| skip_vm_auto_exec_rules          | boolean | no       | `false`  | Skip automatic execution rules for VMs                                         |
| parallel_backup                  | boolean | no       | `false`  | Option to enable parallel schedule backups                                     |
| keep_cr_status                   | boolean | no       | `false`  | Option to enable to keep the CR status of the resources in the backup schedule |
| advanced_resource_label_selector | string  | no       |          | Advanced label selector for resources (string format with operator support)    |

### Resource Selection Parameters


| Parameter              | Type   | Required | Default | Description                            |
| ------------------------ | -------- | ---------- | --------- | ---------------------------------------- |
| namespaces             | list   | no       |         | List of namespaces to backup           |
| resource_types         | list   | no       |         | List of resource types to include      |
| exclude_resource_types | list   | no       |         | Resource types to exclude              |
| label_selectors        | dict   | no       |         | Label selectors for resource filtering |
| ns_label_selectors     | string | no       |         | Namespace label selectors              |
| include_resources      | list   | no       |         | Specific resources to include          |

#### include_resources Entry Format


| Parameter                   | Type   | Required | Description        |
| ----------------------------- | -------- | ---------- | -------------------- |
| include_resources.name      | string | yes      | Resource name      |
| include_resources.namespace | string | yes      | Resource namespace |
| include_resources.group     | string | yes      | Resource API group |
| include_resources.kind      | string | yes      | Resource kind      |
| include_resources.version   | string | yes      | Resource version   |

### Reference Parameters


| Parameter                       | Type | Required | Default | Description                              |
| --------------------------------- | ------ | ---------- | --------- | ------------------------------------------ |
| schedule_policy_ref             | dict | yes      |         | Reference to schedule policy             |
| backup_location_ref             | dict | yes      |         | Reference to backup location             |
| cluster_ref                     | dict | yes      |         | Reference to target cluster              |
| pre_exec_rule_ref               | dict | no       |         | Reference to pre-execution rule          |
| post_exec_rule_ref              | dict | no       |         | Reference to post-execution rule         |
| volume_resource_only_policy_ref | dict | no       |         | Reference to Volume Resource Only policy |

#### schedule_policy_ref


| Parameter                | Type   | Required | Description                 |
| -------------------------- | -------- | ---------- | ----------------------------- |
| schedule_policy_ref.name | string | yes      | Name of the schedule policy |
| schedule_policy_ref.uid  | string | no       | UID of the schedule policy  |

#### cluster_ref


| Parameter        | Type   | Required | Description         |
| ------------------ | -------- | ---------- | --------------------- |
| cluster_ref.name | string | yes      | Name of the cluster |
| cluster_ref.uid  | string | no       | UID of the cluster  |

#### backup_location_ref


| Parameter                | Type   | Required | Description                 |
| -------------------------- | -------- | ---------- | ----------------------------- |
| backup_location_ref.name | string | yes      | Name of the backup location |
| backup_location_ref.uid  | string | no       | UID of the backup location  |

#### pre_exec_rule_ref


| Parameter              | Type   | Required | Description               |
| ------------------------ | -------- | ---------- | --------------------------- |
| pre_exec_rule_ref.name | string | yes      | Name of the pre exec rule |
| pre_exec_rule_ref.uid  | string | no       | UID of the pre exec rule  |

#### post_exec_rule_ref


| Parameter               | Type   | Required | Description                |
| ------------------------- | -------- | ---------- | ---------------------------- |
| post_exec_rule_ref.name | string | yes      | Name of the post exec rule |
| post_exec_rule_ref.uid  | string | no       | UID of the post exec rule  |

#### volume_resource_only_policy_ref


| Parameter                            | Type   | Required | Description                             |
| -------------------------------------- | -------- | ---------- | ----------------------------------------- |
| volume_resource_only_policy_ref.name | string | yes      | Name of the Volume Resource Only policy |
| volume_resource_only_policy_ref.uid  | string | no       | UID of the Volume Resource Only policy  |

### Backup Object Configuration


| Parameter                     | Type   | Required | Default | Description                                          |
| ------------------------------- | -------- | ---------- | --------- | ------------------------------------------------------ |
| backup_object_type            | dict   | no       |         | Backup object configuration                          |
| backup_object_type.type       | string | no       |         | Type of backup object (`Invalid`, `NS`, `VM`, `All`) |
| volume_snapshot_class_mapping | dict   | no       |         | Volume snapshot class mappings                       |

### Ownership Parameters


| Parameter               | Type   | Required | Default | Description                                                               |
| ------------------------- | -------- | ---------- | --------- | --------------------------------------------------------------------------- |
| ownership.owner         | string | no       |         | Owner of the schedule                                                     |
| ownership.groups        | list   | no       |         | Group access configurations (refer Ownership Access Configuration)        |
| ownership.collaborators | list   | no       |         | Collaborator access configurations (refer Ownership Access Configuration) |
| ownership.public        | dict   | no       |         | Public access configuration  (refer Ownership Access Configuration)       |

#### Ownership Access Configuration


| Parameter | Type   | Required | Choices                  | Description                      |
| ----------- | -------- | ---------- | -------------------------- | ---------------------------------- |
| id        | string | yes      |                          | Group or collaborator identifier |
| access    | string | yes      | 'Read', 'Write', 'Admin' | Access level                     |

### Enhanced Filtering and Bulk Operations (2.9.0+)


| Parameter       | Type   | Required | Default | Description                                                     |
| ----------------- | -------- | ---------- | --------- | ----------------------------------------------------------------- |
| policy_ref      | list   | no       |         | List of schedule policy references to filter by                 |
| include_objects | list   | no       |         | List of exact backup schedules to include (name + UID required) |
| exclude_objects | list   | no       |         | List of exact backup schedules to exclude (name + UID required) |
| include_filter  | string | no       |         | Substring or regex pattern to match backup schedules to include |
| exclude_filter  | string | no       |         | Substring or regex pattern to match backup schedules to exclude |

#### policy_ref Entry Format


| Parameter | Type   | Required | Description |
| ----------- | -------- | ---------- | ------------- |
| name      | string | yes      | Policy name |
| uid       | string | no       | Policy UID  |

#### include_objects / exclude_objects Entry Format


| Parameter | Type   | Required | Description   |
| ----------- | -------- | ---------- | --------------- |
| name      | string | yes      | Schedule name |
| uid       | string | no       | Schedule UID  |

### Cluster Scope Configuration (2.9.0+)


| Parameter                  | Type    | Required | Default | Description                                |
| ---------------------------- | --------- | ---------- | --------- | -------------------------------------------- |
| cluster_scope              | dict    | no       |         | Cluster scope configuration for operations |
| cluster_scope.cluster_refs | list    | no       |         | List of cluster references                 |
| cluster_scope.all_clusters | boolean | no       |         | Apply operation to all clusters            |

#### cluster_scope.cluster_refs Entry Format


| Parameter | Type   | Required | Description         |
| ----------- | -------- | ---------- | --------------------- |
| name      | string | yes      | Name of the cluster |
| uid       | string | no       | Cluster UID         |

### Enumeration Options


| Parameter                                    | Type    | Required | Default | Description                                                |
| ---------------------------------------------- | --------- | ---------- | --------- | ------------------------------------------------------------ |
| enumerate_options.labels                     | dict    | no       |         | Label selectors for filtering                              |
| enumerate_options.max_objects                | string  | no       |         | Maximum objects to return                                  |
| enumerate_options.name_filter                | string  | no       |         | Filter by name                                             |
| enumerate_options.status                     | list    | no       |         | Filter based on the object status (list of status strings) |
| enumerate_options.cluster_name_filter        | string  | no       |         | Filter by cluster name                                     |
| enumerate_options.object_index               | string  | no       |         | Index from where object fetch has to happen                |
| enumerate_options.owners                     | list    | no       |         | Filter by owners (list of owner IDs)                       |
| enumerate_options.backup_object_type         | string  | no       |         | Filter based on backup object type                         |
| enumerate_options.include_detailed_resources | boolean | no       |         | Include detailed resource information                      |
| enumerate_options.cluster_uid_filter         | string  | no       |         | Filter by cluster UID                                      |
| enumerate_options.time_range                 | dict    | no       |         | Time range filter                                          |
| enumerate_options.time_range.start_time      | string  | no       |         | Time range filter start time                               |
| enumerate_options.time_range.end_time        | string  | no       |         | Time range filter end time                                 |
| enumerate_options.schedule_policy_ref        | list    | no       |         | Filter by schedule policy references                       |
| enumerate_options.backup_schedule_ref        | list    | no       |         | Filter by backup schedule references                       |
| enumerate_options.sort_option                | dict    | no       |         | Sorting options for results                                |

#### enumerate_options.schedule_policy_ref / backup_schedule_ref Entry Format


| Parameter | Type   | Required | Description          |
| ----------- | -------- | ---------- | ---------------------- |
| name      | string | no       | Policy/Schedule name |
| uid       | string | no       | Policy/Schedule UID  |

#### enumerate_options.sort_option Format


| Parameter      | Type   | Required | Description                                                                                          |
| ---------------- | -------- | ---------- | ------------------------------------------------------------------------------------------------------ |
| sortBy         | dict   | no       | Field to sort by                                                                                     |
| sortBy.type    | string | no       | Sort field type (`Invalid`, `CreationTimestamp`, `Name`, `ClusterName`, `Size`, `RestoreBackupName`) |
| sortOrder      | dict   | no       | Sort order                                                                                           |
| sortOrder.type | string | no       | Sort order type (`Invalid`, `Ascending`, `Descending`)                                               |

### Deprecated Parameters

The following parameters are deprecated but maintained for backward compatibility:


| Parameter               | Type   | Description             | Replacement                   |
| ------------------------- | -------- | ------------------------- | ------------------------------- |
| pre_exec_rule           | string | Pre exec Rule name      | pre_exec_rule_ref             |
| post_exec_rule          | string | Post exec Rule name     | post_exec_rule_ref            |
| csi_snapshot_class_name | string | CSI Snapshot Class Name | volume_snapshot_class_mapping |

## Return Values


| Name             | Type   | Description                                            |
| ------------------ | -------- | -------------------------------------------------------- |
| backup_schedule  | dict   | Details of the backup schedule (for single operations) |
| backup_schedules | list   | List of backup schedules (for INSPECT_ALL)             |
| message          | string | Operation result message                               |

## Examples

### Create Basic Backup Schedule

```yaml
- name: Create backup schedule
  backup_schedule:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "daily-backup"
    org_id: "default"
    namespaces:
      - "production"
      - "staging"
    schedule_policy_ref:
      name: "daily-policy"
      uid: "policy-123"
    backup_location_ref:
      name: "s3-backup-location"
      uid: "location-456"
    cluster_ref:
      name: "prod-cluster"
      uid: "cluster-789"
    reclaim_policy: "Retain"
```

### Create VM Backup Schedule with Execution Rules

```yaml
- name: Create VM backup schedule
  backup_schedule:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "vm-backup-schedule"
    org_id: "default"
    backup_object_type:
      type: "VM"
    schedule_policy_ref:
      name: "weekly-policy"
      uid: "policy-456"
    backup_location_ref:
      name: "azure-backup-location"
      uid: "location-789"
    cluster_ref:
      name: "vm-cluster"
      uid: "cluster-123"
    pre_exec_rule_ref:
      name: "vm-shutdown"
      uid: "rule-123"
    post_exec_rule_ref:
      name: "vm-startup"
      uid: "rule-456"
    skip_vm_auto_exec_rules: false
    parallel_backup: true
```

### Update Backup Schedule

```yaml
- name: Update backup schedule
  backup_schedule:
    operation: UPDATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "daily-backup"
    org_id: "default"
    uid: "schedule-uid-123"
    suspend: true
    reclaim_policy: "Delete"
```

### List All Backup Schedules with Filtering

```yaml
- name: List backup schedules with filters
  backup_schedule:
    operation: INSPECT_ALL_POST_REQUEST
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    enumerate_options:
      name_filter: "prod-*"
      cluster_name_filter: "production"
      max_objects: "50"
      include_detailed_resources: true
      sort_option:
        sortBy:
          type: "CreationTimestamp"
        sortOrder:
          type: "Descending"
```

### Advanced Filtering (2.9.0+)

```yaml
- name: List schedules with advanced filtering
  backup_schedule:
    operation: INSPECT_ALL_POST_REQUEST
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    policy_ref:
      - name: "daily-policy"
        uid: "policy-123"
      - name: "weekly-policy"
        uid: "policy-456"
    include_filter: "prod-*"
    cluster_scope:
      cluster_refs:
        - name: "prod-cluster-1"
          uid: "cluster-123"
        - name: "prod-cluster-2"
          uid: "cluster-456"
```

### Delete Multiple Schedules (2.9.0+)

```yaml
- name: Delete backup schedules with pattern
  backup_schedule:
    operation: DELETE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    exclude_filter: "test-*"
    cluster_scope:
      all_clusters: true
```

### Inspect Specific Schedule

```yaml
- name: Get backup schedule details
  backup_schedule:
    operation: INSPECT_ONE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "daily-backup"
    org_id: "default"
    uid: "schedule-uid-123"
```

### update backup schedule with Remark

```yaml
- name: Update backup schedule with remark
  backup_schedule:
    operation: UPDATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "my-schedule"
    uid: "schedule-uid"
    suspend: true
    remark: "Suspended for maintenance window"
```

## Error Handling

The module implements comprehensive error handling:

1. **Validation Checks**

   - Required parameter validation
   - Format validation
   - Reference validation
   - Permission checks
2. **Common Error Scenarios**

   - Invalid configurations
   - Missing references
   - Permission issues
   - Network connectivity problems
   - API errors

## Notes

1. **Configuration Best Practices**

   - Use descriptive schedule names
   - Configure appropriate retention policies
   - Set reasonable resource limits
   - Regular schedule review
   - Monitor execution status
2. **Resource Management**

   - Careful namespace selection
   - Appropriate label selectors
   - Resource type filtering
   - Volume snapshot configuration
3. **Security Considerations**

   - Access control configuration
   - Credential management
   - Secure token handling
   - SSL certificate validation
4. **Limitations**

   - Schedule-specific constraints
   - Resource selection limits
   - Cloud provider dependencies
   - Storage requirements
5. **Version Considerations**

   - Features marked with (2.9.0+) require PX-Backup version 2.9.0 or later
   - Use INSPECT_ALL_POST_REQUEST for advanced filtering capabilities
   - Cluster scope operations are available in 2.9.0+

## Troubleshooting

1. **Schedule Creation Issues**

   - Verify references
   - Check permissions
   - Validate configurations
   - Review resource selections
2. **Execution Problems**

   - Check cluster connectivity
   - Verify storage access
   - Monitor resource usage
   - Review execution logs
3. **Configuration Issues**

   - Validate policy references
   - Check location access
   - Verify namespace existence
   - Review label selectors
4. **Filtering Issues**

   - Use INSPECT_ALL_POST_REQUEST for complex filters
   - Verify filter syntax for include_filter/exclude_filter
   - Check enumerate_options structure
   - Validate sort options
