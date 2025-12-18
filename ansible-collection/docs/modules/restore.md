# Restore Module

The restore module enables management of backup restoration operations in PX-Backup, providing capabilities for creating, inspecting, and managing restores from existing backups.

## Synopsis

* Create and manage restores from PX-Backup backups
* Support for default and custom restore configurations
* Single File Restore (SFR) for VirtualMachine backups (PX-Backup 2.11.0+)
* Flexible resource selection and mapping
* Namespace and storage class mapping capabilities
* Rancher project integration
* Advanced enumeration filtering options

## Requirements

* PX-Backup >= 2.10.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation   | Description                       |
| ------------- | ----------------------------------- |
| CREATE      | Create a new restore operation    |
| DELETE      | Remove a restore operation        |
| INSPECT_ONE | Get details of a specific restore |
| INSPECT_ALL | List all restore operations       |

## Parameters

### Common Parameters


| Parameter      | Type    | Required | Default | Description          |
| ---------------- | --------- | ---------- | --------- | ---------------------- |
| api_url        | string  | yes      |         | PX-Backup API URL    |
| token          | string  | yes      |         | Authentication token |
| operation      | string  | yes      |         | Operation to perform |
| name           | string  | varies   |         | Name of the restore  |
| org_id         | string  | yes      |         | Organization ID      |
| uid            | string  | varies   |         | Unique identifier    |
| validate_certs | boolean | true     |         | validate certificate |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### Backup Reference Parameters


| Parameter       | Type   | Required | Description                        |
| ----------------- | -------- | ---------- | ------------------------------------ |
| backup_ref.name | string | yes      | Name of the backup to restore from |
| backup_ref.uid  | string | no       | UID of the backup to restore from  |

### Target Configuration


| Parameter             | Type   | Required | Description                            |
| ----------------------- | -------- | ---------- | ---------------------------------------- |
| cluster_ref           | dict   | no       | Target cluster reference               |
| cluster_ref.name      | string | yes      | Target cluster name                    |
| cluster_ref.uid       | string | no       | Target cluster UID                     |
| namespace_mapping     | dict   | no       | Source to target namespace mapping     |
| storage_class_mapping | dict   | no       | Source to target storage class mapping |

### Resource Selection


| Parameter          | Type   | Required | Description                            | Choices                          |
| -------------------- | -------- | ---------- | ---------------------------------------- | ---------------------------------- |
| include_resources  | list   | no       | Specific resources to restore          |                                  |
| backup_object_type | string | no       | Type of backup objects to restore      | `Invalid`,`All`,`VirtualMachine` |
| replace_policy     | string | no       | Policy for handling existing resources | `Invalid`, `Retain`, `Delete`    |

#### include_resources Entry Format


| Parameter                   | Type   | Required | Description        |
| ----------------------------- | -------- | ---------- | -------------------- |
| include_resources.name      | string | yes      | Resource name      |
| include_resources.namespace | string | yes      | Resource namespace |
| include_resources.group     | string | yes      | Resource API group |
| include_resources.kind      | string | yes      | Resource kind      |
| include_resources.version   | string | yes      | Resource version   |

### Rancher Integration


| Parameter                          | Type   | Required | Description                                 |
| ------------------------------------ | -------- | ---------- | --------------------------------------------- |
| rancher_project_mapping            | dict   | no       | Source to target project mapping            |
| rancher_project_mapping.key        | string | yes      | Source to target project mapping key        |
| rancher_project_mapping.value      | string | yes      | Source to target project mapping value      |
| rancher_project_name_mapping       | dict   | no       | Source to target project name mapping       |
| rancher_project_name_mapping.key   | string | yes      | Source to target project name mapping key   |
| rancher_project_name_mapping.value | string | yes      | Source to target project name mapping value |

### Single File Restore (SFR) Parameters


| Parameter                                    | Type    | Required | Default | Description                                    |
| ---------------------------------------------- | --------- | ---------- | --------- | ------------------------------------------------ |
| is_sfr                                       | boolean | no       | false   | Enable Single File Restore mode               |
| file_level_restore_info                      | dict    | no       |         | File-level restore configuration              |
| file_level_restore_info.virtual_machine_name | string  | yes*     |         | Name of the virtual machine to restore from   |
| file_level_restore_info.volume_name          | string  | yes*     |         | Name of the volume to restore from            |
| file_level_restore_info.restore_files        | list    | yes*     |         | List of files/directories to restore          |


*Required when `is_sfr` is true

#### restore_files Entry Format


| Parameter        | Type    | Required | Description                                      |
| ------------------ | --------- | ---------- | -------------------------------------------------- |
| source_path      | string  | yes      | Source file/directory path (must be relative)   |
| destination_path | string  | no      | Destination path (must be relative), keep Empty if file is restored to the source path  |
| is_dir           | boolean | no       | Whether the source path is a directory          |
| partition_info       | string  | no          | Partition info if volume is partitioned       |
### Enumeration Options


| Parameter                  | Type    | Required | Default | Description                         |
| ---------------------------- | --------- | ---------- | --------- | ------------------------------------- |
| max_objects                | int     | no       |         | Maximum objects to return           |
| cluster_uid_filter         | string  | no       |         | Filter by cluster UID              |
| owners                     | list    | no       |         | Filter by owners                    |
| status                     | list    | no       |         | Filter by status                    |
| name_filter                | string  | no       |         | Filter by restore name              |
| cluster_name_filter        | string  | no       |         | Filter by cluster name              |
| include_detailed_resources | boolean | no       | false   | Include detailed resource info      |

## Examples

### Standard Restore

```yaml
- name: Create standard restore
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "standard-restore"
    org_id: "{{ org_id }}"
    backup_ref:
      name: "my-backup"
      uid: "backup-uid-123"
    cluster_ref:
      name: "target-cluster"
    replace_policy: "Delete"
```

### Restore with Namespace Mapping

```yaml
- name: Restore with namespace mapping
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "mapped-restore"
    org_id: "{{ org_id }}"
    backup_ref:
      name: "prod-backup"
    cluster_ref:
      name: "staging-cluster"
    namespace_mapping:
      prod-namespace: staging-namespace
      app-prod: app-staging
```

### Enumerate Restores with Filtering

```yaml
- name: List successful restores only
  restore:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "{{ org_id }}"
    status:
      - "Success"
      - "PartialSuccess"
    max_objects: 10
```

### Single File Restore (SFR)

```yaml
- name: Restore specific configuration files
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "config-file-restore"
    org_id: "{{ org_id }}"
    backup_ref:
      name: "vm-backup"
    cluster_ref:
      name: "recovery-cluster"
    is_sfr: true
    file_level_restore_info:
      virtual_machine_name: "database-server"
      volume_name: "data-volume"
      restore_files:
        - source_path: "etc/mysql/my.cnf"
          destination_path: "/tmp/mysql-config.cnf"
          is_dir: false
        - source_path: "var/log/mysql/"
          destination_path: "/tmp/mysql-logs/"
          is_dir: true
```

## Error Handling

1. Parameter Validation

   - Required parameter checks
   - Format validation
   - Reference validation
   - Policy validation
   - SFR path validation
2. Common Error Scenarios

   - Missing backup references
   - Invalid cluster references
   - Namespace conflicts
   - Storage class mismatches
   - Resource conflicts
   - SFR validation failures
3. Error Response Format

   - Detailed error messages
   - Operation status
   - Resource status
   - Validation failures

## Single File Restore (SFR) Usage PX-Backup 2.11.0+

### Basic SFR Example

```yaml
- name: Restore specific files from VM backup
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "vm-file-restore"
    org_id: "{{ org_id }}"
    backup_ref:
      name: "vm-backup-20241218"
    cluster_ref:
      name: "target-cluster"
    is_sfr: true
    file_level_restore_info:
      virtual_machine_name: "web-server"
      volume_name: "app-data"
      restore_files:
        - source_path: "config/app.conf"
          destination_path: "/tmp/app.conf"
          is_dir: false
        - source_path: "logs/"
          destination_path: "/tmp/logs/"
          is_dir: true
```

### SFR Requirements and Limitations

- Source paths must be relative (cannot start with /)
- Destination paths must be absolute, can be left empty if the destination is same as source.
- Requires valid virtual machine and volume names from the backup
- Partition information may be required for partitioned volumes
- use is_dir: flag to specify if the restore is at directory/file level. 

## Notes

1. **Restore Strategy Considerations**

   - Resource conflict handling
   - Namespace mapping strategy
   - Storage class compatibility
   - Resource dependencies
   - Data consistency
   - SFR vs full restore selection
2. **Best Practices**

   - Validate backup availability
   - Verify target cluster readiness
   - Test namespace mappings
   - Monitor storage requirements
   - Consider resource dependencies
   - Use SFR for granular file recovery
   - Validate file paths before restore
3. **Security Considerations**

   - Access control validation
   - Resource permissions
   - Namespace restrictions
   - Storage class access
   - Credential management
   - File path validation
4. **Limitations**

   - Resource type restrictions
   - Storage class compatibility
   - Namespace constraints
   - Version compatibility
   - Cloud provider limitations
   - SFR limited to Unix based VMs (for px-backup 2.11.0)

## Troubleshooting

1. **Restore Creation Issues**

   - Verify backup exists
   - Check cluster access
   - Validate namespace mappings
   - Confirm storage availability
   - Check resource permissions
   - For SFR: Verify VM and volume names exist in backup
2. **Resource Conflicts**

   - Review replace policy
   - Check namespace conflicts
   - Verify storage class mapping
   - Validate resource names
   - Check dependencies
3. **SFR-Specific Issues**

   - Verify source paths are relative
   - Check virtual machine name exists in backup
   - Validate volume name exists for the VM
   - Confirm file paths exist in the backup
   - Check partition information if required

5. **Performance Considerations**

   - Resource quantity
   - Data volume
   - Network bandwidth
   - Storage performance
   - Cluster resources
   - SFR file size and count
6. **Common Solutions**

   - Use appropriate replace policy
   - Monitor restore progress
   - Check operation logs
   - Verify resource status
   - Review error messages
   - Monitor target cluster
   - For SFR: Validate file paths and VM details
