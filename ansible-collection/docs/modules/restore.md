# Restore Module

The restore module enables management of backup restoration operations in PX-Backup, providing capabilities for creating, inspecting, and managing restores from existing backups.

## Synopsis

* Create and manage restores from PX-Backup backups
* Support for default and custom restore configurations
* Flexible resource selection and mapping
* Advanced resource exclusion capabilities (v2.11.0)
* Enhanced filtering with namespace and VM patterns (v2.11.0)
* Namespace and storage class mapping capabilities
* Rancher project integration

## Requirements

* PX-Backup >= 2.9.0
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

### Enumeration Options


| Parameter                  | Type    | Required | Default | Description                    |
| ---------------------------- | --------- | ---------- | --------- | -------------------------------- |
| max_objects                | int     | no       |         | Maximum objects to return      |
| cluster_uid_filter         | string  | no       |         | Filter by cluster name         |
| owners                     | string  | no       |         | Filter by owners               |
| status                     | string  | no       |         | Filter by status               |
| name_filter                | string  | no       |         | Filter by restore name         |
| cluster_name_filter        | string  | no       |         | Filter by cluster name         |
| include_detailed_resources | boolean | no       | false   | Include detailed resource info |

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
2. Common Error Scenarios

   - Missing backup references
   - Invalid cluster references
   - Namespace conflicts
   - Storage class mismatches
   - Resource conflicts
3. Error Response Format

   - Detailed error messages
   - Operation status
   - Resource status
   - Validation failures

## Notes

1. **Restore Strategy Considerations**

   - Resource conflict handling
   - Namespace mapping strategy
   - Storage class compatibility
   - Resource dependencies
   - Data consistency
2. **Best Practices**

   - Validate backup availability
   - Verify target cluster readiness
   - Test namespace mappings
   - Monitor storage requirements
   - Consider resource dependencies
3. **Security Considerations**

   - Access control validation
   - Resource permissions
   - Namespace restrictions
   - Storage class access
   - Credential management
4. **Limitations**

   - Resource type restrictions
   - Storage class compatibility
   - Namespace constraints
   - Version compatibility
   - Cloud provider limitations

## Troubleshooting

1. **Restore Creation Issues**

   - Verify backup exists
   - Check cluster access
   - Validate namespace mappings
   - Confirm storage availability
   - Check resource permissions
2. **Resource Conflicts**

   - Review replace policy
   - Check namespace conflicts
   - Verify storage class mapping
   - Validate resource names
   - Check dependencies
3. **Performance Considerations**

   - Resource quantity
   - Data volume
   - Network bandwidth
   - Storage performance
   - Cluster resources
4. **Common Solutions**

   - Use appropriate replace policy
   - Monitor restore progress
   - Check operation logs
   - Verify resource status
   - Review error messages
   - Monitor target cluster

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
