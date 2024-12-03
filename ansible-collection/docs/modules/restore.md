# Restore Module

The restore module enables management of backup restoration operations in PX-Backup, providing capabilities for creating, inspecting, and managing restores from existing backups.

## Synopsis

* Create and manage restores from PX-Backup backups
* Support for default and custom restore configurations
* Flexible resource selection and mapping
* Namespace and storage class mapping capabilities
* Rancher project integration

## Requirements

* PX-Backup >= 2.8.1
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

### Backup Reference Parameters


| Parameter       | Type   | Required | Description                        |
| ----------------- | -------- | ---------- | ------------------------------------ |
| backup_ref.name | string | yes      | Name of the backup to restore from |
| backup_ref.uid  | string | yes      | UID of the backup to restore from  |

### Target Configuration


| Parameter             | Type   | Required | Description                            |
| ----------------------- | -------- | ---------- | ---------------------------------------- |
| cluster_ref           | dict   | no       | Target cluster reference               |
| cluster_ref.name      | string | yes      | Target cluster name                    |
| cluster_ref.uid       | string | yes      | Target cluster UID                     |
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
