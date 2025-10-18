# Keycloak Role Module

The keycloak_role module manages roles in Keycloak, providing comprehensive role management capabilities for the master realm using the Keycloak Admin REST API.

## Synopsis

* Create new roles in Keycloak
* Update existing role properties
* Delete roles from Keycloak
* Inspect individual roles
* List all roles with pagination support
* Uses Bearer token authentication from the auth module
* Supports SSL/TLS certificate configuration

## Requirements

* Python >= 3.9
* The `requests` Python package
* Valid Bearer token with admin privileges in Keycloak
* Network connectivity to Keycloak server

## Operations

The module supports the following role management operations:

| Operation    | Description                                    |
| ------------ | ---------------------------------------------- |
| CREATE       | Create a new role with specified properties   |
| UPDATE       | Update an existing role's properties          |
| DELETE       | Remove a role from Keycloak                   |
| INSPECT_ONE  | Retrieve details of a specific role           |
| INSPECT_ALL  | List all roles with optional pagination       |

## Parameters

### Required Parameters

| Parameter | Type   | Required | Default | Description                                    |
| --------- | ------ | -------- | ------- | ---------------------------------------------- |
| operation | string | yes      |         | Operation to perform (CREATE/UPDATE/DELETE/INSPECT_ONE/INSPECT_ALL) |
| auth_url  | string | yes      |         | Keycloak authentication server URL            |
| token     | string | yes      |         | Bearer authentication token from auth module  |

### Operation-Specific Parameters

| Parameter   | Type   | Required For                    | Default | Description                           |
| ----------- | ------ | ------------------------------- | ------- | ------------------------------------- |
| name        | string | CREATE, UPDATE, DELETE, INSPECT_ONE |         | Name of the role (must be unique)    |
| description | string | CREATE, UPDATE (optional)       |         | Human-readable description of role   |
| attributes  | dict   | CREATE, UPDATE (optional)       | `{}`    | Custom attributes for the role        |

### Pagination Parameters (INSPECT_ALL only)

| Parameter | Type | Required | Default | Description                              |
| --------- | ---- | -------- | ------- | ---------------------------------------- |
| first     | int  | no       | `0`     | Starting index for pagination           |
| max       | int  | no       | `100`   | Maximum number of roles to return       |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

* Certificate validation options
* Custom CA certificate support
* Mutual TLS authentication
* Self-signed certificate handling

| Parameter  | Type | Required | Default | Description                                |
| ---------- | ---- | -------- | ------- | ------------------------------------------ |
| ssl_config | dict | no       | `{}`    | SSL/TLS configuration options              |

## Configuration with Group Variables

The keycloak_role module supports configuration through Ansible group variables, making it easier to manage role definitions and settings across multiple playbooks.

### Group Variables Structure

The module uses variables from `inventory/group_vars/keycloak_role/` directory:

```
inventory/group_vars/keycloak_role/
├── create.yaml      # Role definitions for creation
├── delete.yaml      # Deletion settings and safety options
├── enumerate.yaml   # Pagination and display options
├── inspect.yaml     # Roles to inspect and options
└── update.yaml      # Update configurations and options
```

### Using Group Variables in Playbooks

```yaml
# Example playbook using group_vars
- name: Create Keycloak Role with Group Variables
  hosts: keycloak_role  # This host group loads the group_vars
  gather_facts: false
  vars:
    # Use default role configuration from group_vars
    role_config: "{{ default_role_config }}"

    # Or use a specific role from the predefined list
    # role_config: "{{ keycloak_roles[0] }}"  # px-backup-operator
    # role_config: "{{ keycloak_roles[1] }}"  # px-backup-admin

  tasks:
    - name: Create role using group_vars configuration
      keycloak_role:
        operation: CREATE
        auth_url: "{{ pxcentral_auth_url }}"
        token: "{{ keycloak_token }}"
        name: "{{ role_config.name }}"
        description: "{{ role_config.description }}"
        attributes: "{{ role_config.attributes }}"
```

### Group Variables Configuration Examples

See the example configurations in:
- `inventory/group_vars/keycloak_role/create.yaml` - Predefined role configurations
- `inventory/group_vars/keycloak_role/delete.yaml` - Safety settings for deletion
- `inventory/group_vars/keycloak_role/enumerate.yaml` - Pagination and filtering options
- `inventory/group_vars/keycloak_role/update.yaml` - Update scenarios and options

## Examples

### Basic Role Management

```yaml
# Create a new role
- name: Create backup administrator role
  keycloak_role:
    operation: CREATE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "backup-admin"
    description: "Administrator role for backup operations"
    attributes:
      department: "IT"
      level: "admin"

# Update an existing role
- name: Update role description
  keycloak_role:
    operation: UPDATE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "backup-admin"
    description: "Updated administrator role for backup operations"
    attributes:
      department: "Operations"
      level: "senior-admin"

# Delete a role
- name: Remove obsolete role
  keycloak_role:
    operation: DELETE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "backup-admin"
```

### Role Inspection

```yaml
# Get details of a specific role
- name: Inspect backup admin role
  keycloak_role:
    operation: INSPECT_ONE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "backup-admin"
  register: role_details

- name: Display role information
  debug:
    var: role_details.role

# List all roles with pagination
- name: Get first 50 roles
  keycloak_role:
    operation: INSPECT_ALL
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    first: 0
    max: 50
  register: roles_list

- name: Display roles count
  debug:
    msg: "Found {{ roles_list.roles | length }} roles"
```

### Complete Workflow with Authentication

```yaml
- name: Complete Keycloak role management workflow
  hosts: localhost
  vars:
    pxcentral_auth_url: "http://10.13.162.146:32282"
    pxcentral_client_id: "pxcentral"
    pxcentral_username: "admin"
    pxcentral_password: "{{ admin_password }}"

  tasks:
    # Step 1: Get authentication token
    - name: Get Keycloak admin token
      auth:
        auth_url: "{{ pxcentral_auth_url }}"
        client_id: "{{ pxcentral_client_id }}"
        username: "{{ pxcentral_username }}"
        password: "{{ pxcentral_password }}"
        token_duration: "1h"
      register: auth_result

    # Step 2: Create role
    - name: Create custom role
      keycloak_role:
        operation: CREATE
        auth_url: "{{ pxcentral_auth_url }}"
        token: "{{ auth_result.access_token }}"
        name: "px-backup-operator"
        description: "Operator role for PX-Backup management"
        attributes:
          service: "px-backup"
          access_level: "operator"

    # Step 3: Verify role creation
    - name: Verify role was created
      keycloak_role:
        operation: INSPECT_ONE
        auth_url: "{{ pxcentral_auth_url }}"
        token: "{{ auth_result.access_token }}"
        name: "px-backup-operator"
      register: created_role

    - name: Display created role
      debug:
        msg: "Created role: {{ created_role.role.name }} - {{ created_role.role.description }}"
```

## Return Values

### For CREATE, UPDATE, and INSPECT_ONE operations

| Field   | Type | Description                                    |
| ------- | ---- | ---------------------------------------------- |
| role    | dict | Complete role object from Keycloak           |
| message | str  | Operation result message                       |
| changed | bool | Whether the operation modified anything        |

### For INSPECT_ALL operation

| Field   | Type | Description                                    |
| ------- | ---- | ---------------------------------------------- |
| roles   | list | Array of role objects from Keycloak          |
| message | str  | Operation result message                       |
| changed | bool | Always false for inspection operations        |

### For DELETE operation

| Field   | Type | Description                                    |
| ------- | ---- | ---------------------------------------------- |
| message | str  | Operation result message                       |
| changed | bool | Always true for successful deletions          |

## Notes

1. **Authentication Requirements**
   - Requires a valid Bearer token with admin privileges
   - Token must be obtained from the auth module
   - Token must not be expired

2. **Role Management**
   - Role names must be unique within the realm
   - Roles are created in the master realm
   - Custom attributes support key-value pairs

3. **Security Considerations**
   - SSL certificate validation enabled by default
   - Bearer tokens are marked as sensitive (no_log)
   - Secure credential handling

4. **Error Handling**
   - Comprehensive error messages for API failures
   - HTTP status code validation
   - Network timeout protection (30 seconds)

5. **Best Practices**
   - Use descriptive role names and descriptions
   - Implement proper token management
   - Use SSL certificate validation in production
   - Handle role dependencies before deletion

## Limitations

- Only supports master realm role management
- No support for composite roles in this version
- No client-specific role management
- Limited to basic role attributes

## Related Modules

- [auth](auth.md) - Authentication token generation
- [role](role.md) - PX-Backup role management (different from Keycloak roles)

## API Reference

This module uses the Keycloak Admin REST API endpoints:
- `GET /auth/admin/realms/master/roles` - List roles
- `POST /auth/admin/realms/master/roles` - Create role
- `GET /auth/admin/realms/master/roles/{role-name}` - Get specific role
- `PUT /auth/admin/realms/master/roles/{role-name}` - Update role
- `DELETE /auth/admin/realms/master/roles/{role-name}` - Delete role
