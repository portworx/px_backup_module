# Role Module

The role module manages roles in PX-Backup, enabling management of admin or user roles.

## Synopsis

* Create and manage roles in PX-Backup
* Access control and ownership management
* Comprehensive role inspection capabilities

## Requirements

* PX-Backup >= 2.10.0
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

### Keycloak Integration Parameters

| Parameter           | Type       | Required | Default                    | Description                                    |
| ------------------- | ---------- | -------- | -------------------------- | ---------------------------------------------- |
| auth_url           | string     | no       |                            | Keycloak authentication server URL             |
| role_id            | string     | no       |                            | Existing Keycloak role ID to associate        |
| skip_keycloak_deletion | boolean | no       | false                      | Skip deletion of associated Keycloak role during DELETE operation |
| keycloak_description| string     | no       | "Role created via ansible" | Description for auto-created Keycloak role    |
| keycloak_attributes | dictionary | no       | {}                         | Custom attributes for Keycloak role           |

#### Keycloak Integration Behavior

**CREATE Operation:**
- If `role_id` is provided: Associates the PX-Backup role with the existing Keycloak role
- If `role_id` is not provided and `auth_url` is provided: Automatically creates a new Keycloak role
- If neither is provided: Creates only the PX-Backup role

**UPDATE Operation:**
- If `auth_url` is provided with `keycloak_description` or `keycloak_attributes`: Updates the associated Keycloak role
- If `auth_url` is not provided: Updates only the PX-Backup role

**DELETE Operation:**
- If `skip_keycloak_deletion` is true: Deletes only the PX-Backup role (takes precedence over auth_url)
- If `skip_keycloak_deletion` is false and `auth_url` is provided: Deletes both PX-Backup and associated Keycloak roles
- If `skip_keycloak_deletion` is false and `auth_url` is not provided: Deletes only the PX-Backup role

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



## Examples

### Basic Role Creation

```yaml
- name: Create a basic role
  role:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "backup-operator"
    rules:
      - services: ["backup"]
        apis: ["create", "inspect*"]
      - services: ["restore"]
        apis: ["create", "inspect*"]
```

### Role Creation with Keycloak Integration

```yaml
- name: Create role with automatic Keycloak role creation
  role:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "backup-admin"
    auth_url: "{{ pxcentral_auth_url }}"
    keycloak_description: "PX-Backup Administrator Role"
    keycloak_attributes:
      department: "IT"
      environment: "production"
    rules:
      - services: ["backup", "restore", "schedule"]
        apis: ["*"]
```

### Role Update with Keycloak Sync

```yaml
- name: Update role and sync with Keycloak
  role:
    operation: UPDATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "backup-admin"
    uid: "role-uuid-here"
    auth_url: "{{ pxcentral_auth_url }}"
    keycloak_description: "Updated PX-Backup Administrator Role"
    keycloak_attributes:
      department: "DevOps"
      environment: "production"
      updated_by: "ansible"
    rules:
      - services: ["backup", "restore", "schedule", "cloudcredential"]
        apis: ["*"]
```

### Role Deletion Examples

```yaml
# Delete both PX-Backup and Keycloak roles
- name: Delete role with Keycloak cleanup
  role:
    operation: DELETE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "backup-admin"
    auth_url: "{{ pxcentral_auth_url }}"

# Delete only PX-Backup role, preserve Keycloak role (method 1: no auth_url)
- name: Delete PX-Backup role only
  role:
    operation: DELETE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "backup-admin"
    # No auth_url provided - Keycloak role preserved

# Delete only PX-Backup role, preserve Keycloak role (method 2: skip flag)
- name: Delete PX-Backup role only with skip flag
  role:
    operation: DELETE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "backup-admin"
    auth_url: "{{ pxcentral_auth_url }}"
    skip_keycloak_deletion: true
```

## Return Values

| Key     | Type   | Description                                    |
| ------- | ------ | ---------------------------------------------- |
| changed | bool   | Whether the operation resulted in changes      |
| role    | dict   | Role details (for single role operations)     |
| roles   | list   | List of roles (for INSPECT_ALL operation)     |
| rules   | list   | Permission rules (for PERMISSION operation)   |
| message | string | Operation result message                       |

### Example Return Value

```json
{
    "changed": true,
    "role": {
        "metadata": {
            "name": "backup-admin",
            "org_id": "default",
            "uid": "role-uuid-here",
            "create_time": "2024-01-01T00:00:00Z",
            "labels": {
                "environment": "production"
            }
        },
        "role_id": "keycloak-role-uuid",
        "rules": [
            {
                "services": ["backup", "restore"],
                "apis": ["*"]
            }
        ]
    },
    "message": "Role created successfully"
}
```

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
