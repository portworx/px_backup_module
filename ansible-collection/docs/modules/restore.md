# Restore Module

The restore module enables management of backup restoration operations in PX-Backup, providing capabilities for creating, inspecting, and managing restores from existing backups.

## Synopsis

* Create and manage restores from PX-Backup backups
* Support for default and custom restore configurations
* Single File Restore (SFR) for VirtualMachine backups (PX-Backup 2.11.0+)
* Flexible resource selection and mapping
* Advanced resource exclusion capabilities (v2.11.0)
* Enhanced filtering with namespace and VM patterns (v2.11.0)
* Namespace and storage class mapping capabilities
* Rancher project integration
* Advanced enumeration filtering options

## Requirements

* PX-Backup >= 2.10.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## API Changes Notice

### Enhanced Features in v2.11.0

This module has been updated with comprehensive restore capabilities:

- **Complete Resource Management**: `include_resources`, `exclude_resources`, `include_optional_resource_types`
- **Advanced Filtering**: Full namespace and VM filtering with pattern matching, include/exclude lists, and GVK specifications
- **Namespace Management**: `namespace_mapping`, `target_namespace_prefix`, `use_source_as_target_namespace` (mutually exclusive)
- **VM Restore Options**: `skip_mac_masking`, `skip_vm_restart` for virtual machine restores
- **Infrastructure Mapping**: Enhanced Rancher project mapping with both ID and name mapping
- **Backup Object Types**: Support for `Invalid`, `All`, and `VirtualMachine` backup object types

**Backward Compatibility**: Please note that API changes in recent PX-Backup versions may cause incompatibilities - ensure your module version matches your PX-Backup installation version for optimal compatibility.

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


| Parameter                      | Type    | Required | Description                                      |
| -------------------------------- | --------- | ---------- | -------------------------------------------------- |
| cluster_ref                    | dict    | no       | Target cluster reference                         |
| cluster_ref.name               | string  | yes      | Target cluster name                              |
| cluster_ref.uid                | string  | no       | Target cluster UID                               |
| namespace_mapping              | dict    | no       | Source to target namespace mapping               |
| target_namespace_prefix        | string  | no       | Prefix for all target namespaces                |
| use_source_as_target_namespace | boolean | no       | Use source namespace as target                   |
| storage_class_mapping          | dict    | no       | Source to target storage class mapping          |

**Note**: `namespace_mapping`, `target_namespace_prefix`, and `use_source_as_target_namespace` are mutually exclusive.

### Resource Selection


| Parameter                      | Type   | Required | Description                            | Choices                          |
| -------------------------------- | -------- | ---------- | ---------------------------------------- | ---------------------------------- |
| include_resources              | list   | no       | Specific resources to restore          |                                  |
| exclude_resources              | list   | no       | Specific resources to exclude          |                                  |
| include_optional_resource_types | list   | no       | Optional resource types to include     | `Jobs`, `CronJobs`, etc.         |
| backup_object_type             | dict   | no       | Type of backup objects to restore      |                                  |
| backup_object_type.type        | string | yes      | Backup object type                     | `Invalid`,`All`,`VirtualMachine` |
| replace_policy                 | string | no       | Policy for handling existing resources | `Invalid`, `Retain`, `Delete`    |

#### Resource Entry Format (include_resources/exclude_resources)


| Parameter                   | Type   | Required | Description                                    |
| ----------------------------- | -------- | ---------- | ------------------------------------------------ |
| name                        | string | yes      | Resource name                                  |
| namespace                   | string | no       | Resource namespace (optional for cluster-scoped) |
| gvk                         | string | yes      | Group-Version-Kind string (e.g., "v1/Service", "apps/v1/Deployment") |

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

### New Filtration Parameters (v2.11.0+)

| Parameter                  | Type    | Required | Default | Description                    |
| ---------------------------- | --------- | ---------- | --------- | -------------------------------- |
| vm_volume_name             | string  | no       |         | Filter VM that matches the resource_info and has volume vm_volume_name attached to it |
| exclude_failed_resource    | boolean | no       | false   | Filter to exclude failed resources while enumerating objects |

### Advanced Filtering Options

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| filter | dict | no | Advanced filtering configuration |
| filter.namespace_filter | dict | no | Namespace-based filtering |
| filter.virtual_machine_filter | dict | no | Virtual machine filtering |

#### Namespace Filter Options

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| namespace_name_pattern | string | no | Pattern to match namespace names (regex) |
| include_namespaces | list | no | List of namespaces to include |
| exclude_namespaces | list | no | List of namespaces to exclude |
| include_resources | list | no | Specific resources to include |
| exclude_resources | list | no | Specific resources to exclude |
| gvks | list | no | Group-Version-Kind specifications |
| resource_name_pattern | string | no | Pattern to match resource names |

#### Virtual Machine Filter Options

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| vm_name_pattern | string | no | Pattern to match VM names |
| os_name | list | no | List of OS names to include |
| include_vms | list | no | Specific VMs to include |
| exclude_vms | list | no | Specific VMs to exclude |

#### Virtual Machine Restore Options

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| virtual_machine_restore_options | dict | no | | VM-specific restore options |
| skip_mac_masking | boolean | no | false | Skip MAC address masking |
| skip_vm_restart | boolean | no | false | Skip VM restart during restore |

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

## Enhanced Filtering (v2.11.0)
The restore module now supports comprehensive filtering capabilities for granular control over what gets restored.

### Resource Filtering

Include or exclude specific resources from restore operations:

```yaml
- name: Create restore with resource selection
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "selective-restore"
    org_id: "default"
    backup_ref:
      name: "my-backup"
    cluster_ref:
      name: "target-cluster"
    # Include specific resources
    include_resources:
      - name: "critical-deployment"
        namespace: "production"
        gvk: "apps/v1/Deployment"
    # Exclude sensitive resources
    exclude_resources:
      - name: "database-secret"
        namespace: "default"
        gvk: "v1/Secret"
    # Include optional resource types
    include_optional_resource_types:
      - "Jobs"
      - "CronJobs"
```

### Namespace Management Options

Choose from three mutually exclusive namespace management strategies:

```yaml
# Option 1: Direct namespace mapping
- name: Create restore with namespace mapping
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "mapped-restore"
    org_id: "default"
    backup_ref:
      name: "cluster-backup"
    cluster_ref:
      name: "target-cluster"
    namespace_mapping:
      "source-ns": "target-ns"
      "prod": "production"

# Option 2: Namespace prefix
- name: Create restore with namespace prefix
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "prefixed-restore"
    org_id: "default"
    backup_ref:
      name: "cluster-backup"
    cluster_ref:
      name: "target-cluster"
    target_namespace_prefix: "restored-"

# Option 3: Use source as target
- name: Create restore using source namespaces
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "source-target-restore"
    org_id: "default"
    backup_ref:
      name: "cluster-backup"
    cluster_ref:
      name: "target-cluster"
    use_source_as_target_namespace: true
```

### Advanced Filtering

Use comprehensive filtering for precise control over what gets restored:

```yaml
- name: Create restore with namespace filtering
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "namespace-filtered-restore"
    org_id: "default"
    backup_ref:
      name: "cluster-backup"
    cluster_ref:
      name: "target-cluster"
    filter:
      namespace_filter:
        namespace_name_pattern: "prod-*"
        exclude_namespaces:
          - "kube-system"
          - "kube-public"
        include_namespaces:
          - "prod-web"
          - "prod-api"
        gvks:
          - "apps/v1/Deployment"
          - "v1/Service"
          - "v1/ConfigMap"
        resource_name_pattern: "web-*"
        include_resources:
          - name: "critical-deployment"
            namespace: "prod-web"
            gvk: "apps/v1/Deployment"
      virtual_machine_filter:
        vm_name_pattern: "prod-vm-*"
        os_name: ["ubuntu", "centos"]
        include_vms:
          - name: "prod-vm-1"
            namespace: "production"
            os_name: "ubuntu"
        exclude_vms:
          - name: "prod-vm-test"
            namespace: "production"
```

### Virtual Machine Restore Options

Configure VM-specific restore behavior:

```yaml
- name: Create VM restore with custom options
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "vm-restore-custom"
    org_id: "default"
    backup_ref:
      name: "vm-backup"
    cluster_ref:
      name: "vm-cluster"
    backup_object_type:
      type: "VirtualMachine"
    virtual_machine_restore_options:
      skip_mac_masking: true
      skip_vm_restart: false
    filter:
      virtual_machine_filter:
        vm_name_pattern: "prod-vm-*"
        os_name: ["ubuntu", "centos"]
```

### Complete Configuration Example

Combine all available options for maximum control:

```yaml
- name: Create comprehensive restore with all options
  restore:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "comprehensive-restore"
    org_id: "default"
    backup_ref:
      name: "full-backup"
      uid: "backup-uid-123"
    cluster_ref:
      name: "target-cluster"
      uid: "cluster-uid-456"
    replace_policy: "Retain"
    target_namespace_prefix: "restored-"
    storage_class_mapping:
      "fast-ssd": "premium-ssd"
      "standard": "gp2"
    rancher_project_mapping:
      key: "source-project-id"
      value: "target-project-id"
    rancher_project_name_mapping:
      key: "source-project"
      value: "target-project"
    backup_object_type:
      type: "All"
    include_optional_resource_types:
      - "Jobs"
      - "CronJobs"
    exclude_resources:
      - name: "temp-secret"
        namespace: "default"
        gvk: "v1/Secret"
    filter:
      namespace_filter:
        namespace_name_pattern: "prod-*"
        exclude_namespaces: ["kube-system"]
        gvks: ["apps/v1/Deployment", "v1/Service"]
      virtual_machine_filter:
        vm_name_pattern: "prod-vm-*"
        os_name: ["ubuntu"]
    virtual_machine_restore_options:
      skip_mac_masking: true
      skip_vm_restart: false
```
Filter restores by specific VM volume names:

```yaml
- name: Get restores for specific VM volume
  restore:
    operation: INSPECT_ALL
    org_id: "default"
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    vm_volume_name: "production-vm-volume"
```

### Exclude Failed Resources

Filter out failed resources from restore enumeration:

```yaml
- name: Get successful restores only
  restore:
    operation: INSPECT_ALL
    org_id: "default"
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    exclude_failed_resource: true
```

### Combined Filtration

Use both filtration parameters together:

```yaml
- name: Get successful restores for specific VM volume
  restore:
    operation: INSPECT_ALL
    org_id: "default"
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    vm_volume_name: "critical-app-volume"
    exclude_failed_resource: true
    max_objects: 10
    sort_option:
      sort_by: "CreationTimestamp"
      sort_order: "Descending"
```

### Advanced Filtering with Additional Parameters

Combine new filtration with existing parameters:

```yaml
- name: Get filtered restores with comprehensive options
  restore:
    operation: INSPECT_ALL
    org_id: "default"
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    vm_volume_name: "database-volume"
    exclude_failed_resource: true
    cluster_name_filter: "production-cluster"
    status: ["Success"]
    include_detailed_resources: false
    backup_object_type:
      type: "VirtualMachine"
```

### GVK Format Guidelines

When specifying Group-Version-Kind (GVK) in filtering:

- **Core resources**: Use `"version/kind"` format (e.g., `"v1/Service"`, `"v1/Pod"`)
- **Non-core resources**: Use `"group/version/kind"` format (e.g., `"apps/v1/Deployment"`)
- **Custom resources**: Use full `"group/version/kind"` format

### Server-Side Validation

The Ansible module acts as a pure facilitator, allowing the PX-Backup server to handle all business logic validation:

- **Ansible validates**: Required parameters, parameter types, SSL certificates
-  **Server validates**: Resource existence, parameter conflicts, business rules
-  **Result**: Clean separation of concerns with authoritative server validation
