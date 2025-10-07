# Role Module

The role module manages roles in PX-Backup, enabling management of admin or user roles.

## Synopsis

* Create and manage roles in PX-Backup
* Access control and ownership management
* Comprehensive role inspection capabilities

## Requirements

* PX-Backup >= 2.9.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation   | Description                     |
| ------------- | --------------------------------- |
| CREATE      | Create a new role               |
| UPDATE      | Modify existing role            |
| DELETE      | Remove a role                   |
| INSPECT_ONE | Get details of a specific role  |
| INSPECT_ALL | List all roles                  |
| PERMISSION  | List all permissions for a role |

## Parameters

### Common Parameters


| Parameter      | Type       | Required | Default | Description                          | Choices |
| ---------------- | ------------ | ---------- | --------- | -------------------------------------- | --------- |
| api_url        | string     | yes      |         | PX-Backup API URL                    |         |
| token          | string     | yes      |         | Authentication token                 |         |
| operation      | string     | yes      | CREATE  | Operation to perform                 |         |
| name           | string     | varies   |         | Name of the role                     |         |
| org_id         | string     | yes      |         | Organization ID                      |         |
| uid            | string     | varies   |         | Unique identifier                    |         |
| owner          | string     | no       |         | Owner name                           |         |
| rules          | list       | varies   |         | List of rules                        |         |
| labels         | dictionary | no       |         | Label for the role                   |         |
| validate_certs | boolean    | no       | `true`  | Whether to validate SSL certificates |         |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### Ownership Parameters


| Parameter                        | Type   | Required | Choices          | Description               |
| ---------------------------------- | -------- | ---------- | ------------------ | --------------------------- |
| ownership.owner                  | string | no       |                  | Owner of the role         |
| ownership.groups[].id            | string | yes      |                  | Group identifier          |
| ownership.groups[].access        | string | yes      | Read/Write/Admin | Group access level        |
| ownership.collaborators[].id     | string | yes      |                  | Collaborator identifier   |
| ownership.collaborators[].access | string | yes      | Read/Write/Admin | Collaborator access level |
| ownership.public.type            | string | no       | Read/Write/Admin | Public access level       |

### Rules Parameters


| Parameter      | Type         | Required | Choices | Description                           |
| ---------------- | -------------- | ---------- | --------- | --------------------------------------- |
| rules.services | list(string) | yes      |         | Services that the role has access to  |
| rules.apis     | list(string) | yes      |         | API actions that the role can perform |

## Error Handling

The module implements comprehensive error handling:

1. Parameter Validation

   - Required parameter checks
   - Format validation
   - Reference validation
2. Common Error Scenarios

   - Missing required configurations
   - Permission issues
   - Network connectivity problems
   - API errors

## Notes

1. **Security Considerations**

   - Access control configuration
   - Token security
   - SSL certificate validation
   - Secret key protection
2. **Best Practices**

   - Regular credential rotation
   - Minimal permission scope
   - Access control review
   - Audit logging
   - Encryption at rest
3. **Limitations**

   - Permission boundaries
   - Update constraints

## Troubleshooting

1. **Creation Issues**

   - Check permissions
   - Validate configurations
   - Ensure unique names
2. **Access Problems**

   - Verify ownership settings
   - Check group permissions
   - Validate token access
   - Review public access
3. **Update Failures**

   - Confirm role exists
   - Check update permissions
   - Validate new configurations
   - Review ownership rights
4. **Common Solutions**

   - Check network connectivity
   - Verify SSL certificates
   - Review error messages
   - Check API endpoints
