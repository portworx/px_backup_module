# Resource Collector Module

The resource collector module interfaces with PX-Backup's ResourceCollector service to query and list supported Kubernetes resource types that can be included in backup operations. This module enables users to discover available resources on connected clusters.

## Synopsis

The resource collector module provides essential functionality for:

* Querying supported Kubernetes resource types for backup operations
* Listing available resources on connected clusters
* Validating resource compatibility for backup planning
* Integrating with PX-Backup's resource management system

## Requirements

* PX-Backup >= 2.9.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## Parameters

### Common Parameters


| Parameter | Type   | Required | Default | Description          |
| ----------- | -------- | ---------- | --------- | ---------------------- |
| api_url   | string | yes      |         | PX-Backup API URL    |
| token     | string | yes      |         | Authentication token |
| org_id    | string | yes      |         | Organization ID      |

### Cluster Reference Parameters


| Parameter        | Type   | Required | Description                     |
| ------------------ | -------- | ---------- | --------------------------------- |
| cluster_ref      | dict   | yes      | Reference to the target cluster |
| cluster_ref.name | string | yes      | Name of the cluster             |
| cluster_ref.uid  | string | yes      | UID of the cluster              |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

## Return Values


| Parameter      | Type    | Description                                           |
| ---------------- | --------- | ------------------------------------------------------- |
| resource_types | list    | List of supported Kubernetes resource types           |
| message        | string  | Operation result message                              |
| changed        | boolean | Whether the operation changed anything (always false) |

## Error Handling

The module implements comprehensive error handling for:

1. Parameter validation
2. API communication errors
3. Authentication failures
4. Cluster connectivity issues
5. Permission checks

Common error scenarios:

- Invalid credentials
- Cluster not found
- Permission denied
- Network connectivity issues
- Invalid cluster reference

## Notes

### Security Considerations

* Secure token management is essential
* Proper authentication must be configured
* Access control should be properly configured

### Best Practices

* Perform regular resource type validation
* Integrate with backup planning workflows
* Implement proper error handling in playbooks
* Verify resource compatibility before backup configuration

### Limitations

* Support for read-only operations only
* Functionality depends on cluster connectivity
* Resource availability varies by cluster configuration
* Operation-specific requirements may apply

### Integration Considerations

* Designed to work seamlessly with PX-Backup's backup module
* Facilitates backup configuration validation
* Enables automated resource discovery
