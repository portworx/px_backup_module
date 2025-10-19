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
* Manages role attributes and descriptions
* Provides comprehensive error handling
* Supports check mode for validation

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
| INSPECT  | Retrieve details of a specific role           |
| ENUMERATE  | List all roles with optional pagination       |

## Parameters

### Required Parameters

| Parameter | Type   | Required | Default | Description                                    |
| --------- | ------ | -------- | ------- | ---------------------------------------------- |
| operation | string | yes      |         | Operation to perform (CREATE/UPDATE/DELETE/INSPECT/ENUMERATE) |
| auth_url  | string | yes      |         | Keycloak authentication server URL            |
| token     | string | yes      |         | Bearer authentication token from auth module  |

### Operation-Specific Parameters

| Parameter   | Type   | Required For                    | Default | Description                           |
| ----------- | ------ | ------------------------------- | ------- | ------------------------------------- |
| name        | string | CREATE, UPDATE, DELETE, INSPECT |         | Name of the role (must be unique)    |
| description | string | CREATE, UPDATE (optional)       |         | Human-readable description of role   |
| attributes  | dict   | CREATE, UPDATE (optional)       | `{}`    | Custom attributes for the role        |

### Pagination Parameters (ENUMERATE only)

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

| Parameter                 | Type    | Required | Default | Description                                    |
| ------------------------- | ------- | -------- | ------- | ---------------------------------------------- |
| ssl_config                | dict    | no       | `{}`    | SSL/TLS configuration options                  |
| ssl_config.validate_certs | boolean | no       | `true`  | Verify SSL certificates                        |
| ssl_config.ca_cert        | path    | no       |         | Path to CA certificate file                   |
| ssl_config.client_cert    | path    | no       |         | Path to client certificate file               |
| ssl_config.client_key     | path    | no       |         | Path to client private key file               |

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
    operation: INSPECT
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
    operation: ENUMERATE
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
        operation: INSPECT
        auth_url: "{{ pxcentral_auth_url }}"
        token: "{{ auth_result.access_token }}"
        name: "px-backup-operator"
      register: created_role

    - name: Display created role
      debug:
        msg: "Created role: {{ created_role.role.name }} - {{ created_role.role.description }}"
```

### Advanced SSL Configuration

```yaml
- name: Create role with mutual TLS authentication
  keycloak_role:
    operation: CREATE
    auth_url: "https://keycloak.secure.example.com"
    token: "{{ px_backup_token }}"
    name: "secure-backup-admin"
    description: "Secure administrator role with mTLS"
    attributes:
      security_level: "high"
      created_via: "ansible"
    ssl_config:
      validate_certs: true
      ca_cert: "/etc/ssl/certs/keycloak-ca.pem"
      client_cert: "/etc/ssl/certs/ansible-client.pem"
      client_key: "/etc/ssl/private/ansible-client.key"
```

### Bulk Role Management

```yaml
- name: Create multiple roles for different access levels
  keycloak_role:
    operation: CREATE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "{{ item.name }}"
    description: "{{ item.description }}"
    attributes: "{{ item.attributes | default({}) }}"
  loop:
    - name: "px-backup-viewer"
      description: "Read-only access to PX-Backup"
      attributes:
        access_level: "read"
        department: "support"
    - name: "px-backup-operator"
      description: "Operator access to PX-Backup"
      attributes:
        access_level: "write"
        department: "operations"
    - name: "px-backup-admin"
      description: "Full administrative access to PX-Backup"
      attributes:
        access_level: "admin"
        department: "platform"
  register: role_creation_results

- name: Display creation results
  debug:
    msg: "Created role: {{ item.role.name }}"
  loop: "{{ role_creation_results.results }}"
  when: item.changed
```

### Check Mode and Validation

```yaml
- name: Validate role creation without making changes
  keycloak_role:
    operation: CREATE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "test-role"
    description: "Test role for validation"
  check_mode: true
  register: validation_result

- name: Show what would be created
  debug:
    msg: "{{ validation_result.message }}"
```

## Return Values

| Name    | Type   | Description                                      |
| ------- | ------ | ------------------------------------------------ |
| role    | dict   | Role information (CREATE, UPDATE, INSPECT)      |
| roles   | list   | List of roles (ENUMERATE only)                  |
| message | string | Operation result message                         |
| changed | bool   | Whether the operation changed anything           |

### Role Object Structure

The `role` field contains a complete Keycloak role object with the following structure:

```json
{
  "id": "12345678-1234-1234-1234-123456789012",
  "name": "backup-admin",
  "description": "Administrator role for backup operations",
  "composite": false,
  "clientRole": false,
  "containerId": "master",
  "attributes": {
    "department": "IT",
    "level": "admin",
    "created_by": "ansible"
  }
}
```

### Return Value Examples

#### CREATE Operation Success
```json
{
  "role": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "px-backup-operator",
    "description": "Operator role for PX-Backup management",
    "composite": false,
    "clientRole": false,
    "containerId": "master",
    "attributes": {
      "service": "px-backup",
      "access_level": "operator"
    }
  },
  "message": "Role 'px-backup-operator' created successfully",
  "changed": true
}
```

#### ENUMERATE Operation Success
```json
{
  "roles": [
    {
      "id": "role-1-id",
      "name": "admin",
      "description": "Administrator role",
      "composite": false,
      "clientRole": false,
      "containerId": "master"
    },
    {
      "id": "role-2-id",
      "name": "user",
      "description": "Standard user role",
      "composite": false,
      "clientRole": false,
      "containerId": "master"
    }
  ],
  "message": "Retrieved 2 roles",
  "changed": false
}
```

#### DELETE Operation Success
```json
{
  "message": "Role 'obsolete-role' deleted successfully",
  "changed": true
}
```

## Error Handling

The module implements comprehensive error handling for Keycloak role management scenarios:

1. **Parameter Validation**
   - Required parameter checks
   - Format validation
   - Value constraints
   - SSL configuration validation

2. **Common Error Scenarios**
   - Invalid credentials or expired tokens
   - Network connectivity issues
   - SSL certificate validation failures
   - Invalid Keycloak URLs
   - Role not found errors
   - Permission denied errors
   - Malformed API responses

3. **Error Response Format**
   - Structured error messages
   - Clear failure reasons
   - Actionable error information
   - HTTP status code details

## Notes

### Authentication Requirements

* Requires a valid Bearer token with admin privileges
* Token must be obtained from the auth module
* Token must not be expired
* Admin privileges required in Keycloak master realm

### Role Management

* Role names must be unique within the realm
* Roles are created in the master realm
* Custom attributes support key-value pairs
* Attributes are stored as arrays in Keycloak format
* Role descriptions are optional but recommended

### Security Considerations

* SSL certificate validation enabled by default
* Bearer tokens are marked as sensitive (no_log)
* Secure credential handling
* Use HTTPS for production environments
* Implement proper access control for role management

### Performance Considerations

* Use pagination for large role lists
* Implement appropriate timeouts for network operations
* Consider batch operations for multiple role management
* Monitor Keycloak server performance during bulk operations

### Best Practices

* Use descriptive role names and descriptions
* Implement consistent attribute naming conventions
* Regular role auditing and cleanup
* Implement proper error handling in playbooks
* Use check mode for validation before making changes
* Document role purposes and attribute meanings

## Limitations

* Only supports master realm role management
* No support for composite roles in this version
* No client-specific role management
* Limited to basic role attributes
* Requires admin privileges in Keycloak
* Token must be valid and not expired
* SSL certificate validation is enabled by default

## Troubleshooting

### Authentication Issues

1. **Token Validation Errors**
   ```
   Error: Failed to create role 'test-role': Keycloak API request failed: 401 Client Error: Unauthorized
   ```
   - Verify token validity and expiration
   - Check admin privileges in Keycloak
   - Ensure token was obtained with correct credentials

2. **Invalid Auth URL**
   ```
   Error: Failed to create role 'test-role': Keycloak API request failed: Connection refused
   ```
   - Validate auth_url format and accessibility
   - Check network connectivity to Keycloak server
   - Verify Keycloak service is running

### Role Operation Failures

1. **Role Already Exists**
   ```
   Error: Failed to create role 'admin': HTTP 409: Conflict
   ```
   - Verify role name uniqueness for CREATE operations
   - Use UPDATE operation for existing roles
   - Check existing roles with ENUMERATE operation

2. **Role Not Found**
   ```
   Error: Failed to get role 'nonexistent': HTTP 404: Not Found
   ```
   - Check role existence for UPDATE/DELETE operations
   - Verify role name spelling and case sensitivity
   - Use ENUMERATE to list available roles

3. **Permission Denied**
   ```
   Error: Failed to create role 'test': HTTP 403: Forbidden
   ```
   - Verify admin privileges in Keycloak
   - Check realm-level permissions
   - Ensure token has role management permissions

### Network and SSL Issues

1. **SSL Certificate Validation**
   ```
   Error: SSL certificate verification failed
   ```
   - Test connectivity to Keycloak server
   - Verify SSL certificate paths and permissions
   - Check certificate chain and trust store
   - Consider using ca_cert parameter for custom CAs

2. **Client Certificate Issues**
   ```
   Error: SSL error occurred: [SSL: CERTIFICATE_VERIFY_FAILED]
   ```
   - Verify client certificate and key file paths
   - Check file permissions and accessibility
   - Ensure certificate and key match
   - Validate certificate chain

### API Response Issues

1. **Malformed JSON Response**
   ```
   Error: Failed to parse JSON response
   ```
   - Check Keycloak API version compatibility
   - Verify JSON response format
   - Review HTTP status codes and error messages
   - Monitor Keycloak server health and performance

2. **Timeout Issues**
   ```
   Error: Request timeout after 30 seconds
   ```
   - Check network latency to Keycloak server
   - Monitor Keycloak server performance
   - Consider increasing timeout values
   - Verify server resource availability

### Common Solutions

1. **Verify Keycloak Configuration**
   ```bash
   # Test Keycloak API accessibility
   curl -k "https://your-keycloak-server/auth/realms/master"
   ```

2. **Check Token Validity**
   ```bash
   # Decode JWT token to check expiration
   echo "your-token" | cut -d. -f2 | base64 -d | jq .exp
   ```

3. **Test SSL Configuration**
   ```bash
   # Test SSL connection
   openssl s_client -connect your-keycloak-server:443 -servername your-keycloak-server
   ```

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
