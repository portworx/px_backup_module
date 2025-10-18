#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Keycloak Role Management Module

This Ansible module manages roles in Keycloak, providing operations for:
- Creating roles
- Updating existing roles
- Deleting roles
- Inspecting roles (single or all)
- Listing roles with pagination

The module uses the Keycloak Admin REST API and requires a valid Bearer token
obtained from the auth module.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: keycloak_role

short_description: Manage roles in Keycloak

version_added: "2.9.0"

description:
    - Manage roles in Keycloak using the Admin REST API
    - Supports creating, updating, deleting, and inspecting roles
    - Uses Bearer token authentication from the auth module
    - Provides role management for the master realm
    - Handles SSL/TLS certificate configuration
    - Supports pagination for role listing

options:
    operation:
        description:
            - "- Operation to perform on the role"
            - "- CREATE creates a new role"
            - "- UPDATE modifies an existing role"
            - "- DELETE removes a role"
            - "- INSPECT retrieves details of a specific role"
            - "- ENUMERATE lists all roles with optional pagination"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'INSPECT', 'ENUMERATE']
    auth_url:
        description: 
            - Keycloak authentication server URL
            - This should be the same URL used with the auth module
            - Example: "http://10.13.162.146:32282"
        required: true
        type: str
    token:
        description: 
            - Bearer authentication token
            - Should be obtained from the auth module
            - Token must have admin privileges for role management
        required: true
        type: str
        no_log: true
    name:
        description: 
            - Name of the role
            - Required for CREATE, UPDATE, DELETE, and INSPECT operations
            - Must be unique within the realm
        required: false
        type: str
    description:
        description: 
            - Description of the role
            - Optional for CREATE and UPDATE operations
            - Provides human-readable information about the role's purpose
        required: false
        type: str
    attributes:
        description: 
            - Custom attributes for the role
            - Dictionary of key-value pairs
            - Optional for CREATE and UPDATE operations
        required: false
        type: dict
        default: {}
    first:
        description: 
            - Starting index for pagination in ENUMERATE operation
            - Used to control which roles are returned in large datasets
        required: false
        type: int
        default: 0
    max:
        description: 
            - Maximum number of roles to return in ENUMERATE operation
            - Used to limit the size of the response
        required: false
        type: int
        default: 100
    ssl_config:
        description: SSL/TLS certificate configuration
        required: false
        type: dict
        default: {}
        suboptions:
            validate_certs:
                description: Enable SSL certificate validation
                type: bool
                default: true
            ca_cert:
                description: Path to custom CA certificate file
                type: path
            client_cert:
                description: Path to client certificate file for mutual TLS
                type: path
            client_key:
                description: Path to client private key file for mutual TLS
                type: path

requirements:
    - python >= 3.9
    - requests

notes:
    - "Requires admin privileges in Keycloak"
    - "Token must be valid and not expired"
    - "Role names must be unique within the realm"
    - "SSL certificate validation is enabled by default"
    - "When using client certificates, both client_cert and client_key must be provided"

author:
    - PX-Backup Ansible Collection Team
'''

EXAMPLES = r'''
# Create a new role
- name: Create Keycloak role
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
- name: Update Keycloak role
  keycloak_role:
    operation: UPDATE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "backup-admin"
    description: "Updated description for backup administrator role"
    attributes:
      department: "Operations"
      level: "senior-admin"

# Delete a role
- name: Delete Keycloak role
  keycloak_role:
    operation: DELETE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "backup-admin"

# Get details of a specific role
- name: Inspect specific role
  keycloak_role:
    operation: INSPECT
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "backup-admin"
  register: role_details

# List all roles with pagination
- name: List all roles
  keycloak_role:
    operation: ENUMERATE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    first: 0
    max: 50
  register: all_roles

# Create role with SSL configuration
- name: Create role with SSL config
  keycloak_role:
    operation: CREATE
    auth_url: "{{ pxcentral_auth_url }}"
    token: "{{ px_backup_token }}"
    name: "secure-role"
    description: "Role created with SSL configuration"
    ssl_config:
      validate_certs: true
      ca_cert: "/etc/ssl/certs/custom-ca.pem"
'''

RETURN = r'''
role:
    description: Role information for CREATE, UPDATE, and INSPECT operations
    type: dict
    returned: success (except DELETE and ENUMERATE)
    sample: {
        "id": "12345678-1234-1234-1234-123456789012",
        "name": "backup-admin",
        "description": "Administrator role for backup operations",
        "composite": false,
        "clientRole": false,
        "containerId": "master",
        "attributes": {
            "department": ["IT"],
            "level": ["admin"]
        }
    }
roles:
    description: List of roles for ENUMERATE operation
    type: list
    returned: success (ENUMERATE only)
    sample: [
        {
            "id": "12345678-1234-1234-1234-123456789012",
            "name": "backup-admin",
            "description": "Administrator role for backup operations",
            "composite": false,
            "clientRole": false,
            "containerId": "master"
        }
    ]
message:
    description: Operation result message
    type: str
    returned: always
    sample: "Role 'backup-admin' created successfully"
changed:
    description: Whether the operation changed anything
    type: bool
    returned: always
    sample: true
'''


def make_keycloak_request(auth_url, endpoint, method='GET', data=None, params=None, token=None, ssl_config=None):
    """
    Make HTTP request to Keycloak Admin API with proper authentication and SSL handling.

    Args:
        auth_url (str): Base Keycloak authentication URL
        endpoint (str): API endpoint path
        method (str): HTTP method (GET, POST, PUT, DELETE)
        data (dict): Request payload for POST/PUT operations
        params (dict): Query parameters
        token (str): Bearer authentication token
        ssl_config (dict): SSL configuration options

    Returns:
        dict: Response data from Keycloak API

    Raises:
        Exception: If request fails or returns error status
    """
    # Ensure auth_url has protocol
    if not auth_url.startswith(('http://', 'https://')):
        auth_url = f"http://{auth_url}"

    # Construct full URL
    base_url = auth_url.rstrip('/')
    url = f"{base_url}/auth/admin/realms/master/roles{endpoint}"

    # Prepare headers
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    # Extract SSL configuration
    if ssl_config is None:
        ssl_config = {}

    verify_ssl = ssl_config.get('validate_certs', True)
    ca_cert = ssl_config.get('ca_cert')
    client_cert = ssl_config.get('client_cert')
    client_key = ssl_config.get('client_key')

    # Prepare SSL verification
    verify = verify_ssl
    if ca_cert:
        verify = ca_cert

    # Prepare client certificate
    cert = None
    if client_cert and client_key:
        cert = (client_cert, client_key)

    try:
        # Make the request
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            json=data,  # Use json parameter instead of data to let requests handle serialization
            params=params,
            verify=verify,
            cert=cert,
            timeout=30
        )

        # Check for HTTP errors
        if response.status_code >= 400:
            error_msg = f"HTTP {response.status_code}: {response.reason}"
            try:
                error_detail = response.json()
                if 'error' in error_detail:
                    error_msg += f" - {error_detail['error']}"
                if 'error_description' in error_detail:
                    error_msg += f": {error_detail['error_description']}"
            except:
                error_msg += f" - {response.text}"
            raise Exception(error_msg)

        # Return JSON response for successful requests
        if response.status_code == 204:  # No Content (successful DELETE)
            return {}

        if response.content:
            return response.json()
        else:
            return {}

    except requests.exceptions.RequestException as e:
        raise Exception(f"Request failed: {str(e)}")


def convert_attributes_to_keycloak_format(attributes):
    """Convert attributes from dict format to Keycloak format where values are arrays."""
    if not attributes:
        return {}

    keycloak_attributes = {}
    for key, value in attributes.items():
        if isinstance(value, list):
            keycloak_attributes[key] = value
        else:
            keycloak_attributes[key] = [str(value)]

    return keycloak_attributes


def convert_attributes_from_keycloak_format(keycloak_attributes):
    """Convert attributes from Keycloak format (arrays) to simple dict format."""
    if not keycloak_attributes:
        return {}

    simple_attributes = {}
    for key, value_list in keycloak_attributes.items():
        if isinstance(value_list, list) and len(value_list) > 0:
            # If single value, return as string; if multiple values, return as list
            simple_attributes[key] = value_list[0] if len(value_list) == 1 else value_list
        else:
            simple_attributes[key] = value_list

    return simple_attributes


def create_role(auth_url, token, name, description=None, attributes=None, ssl_config=None):
    """Create a new role in Keycloak."""
    role_data = {
        'name': name,
        'description': description or '',
        'attributes': convert_attributes_to_keycloak_format(attributes)
    }

    try:
        make_keycloak_request(
            auth_url=auth_url,
            endpoint='',
            method='POST',
            data=role_data,
            token=token,
            ssl_config=ssl_config
        )

        # Get the created role details
        created_role = get_role_by_name(auth_url, token, name, ssl_config)
        return created_role, f"Role '{name}' created successfully"

    except Exception as e:
        raise Exception(f"Failed to create role '{name}': {str(e)}")


def update_role(auth_url, token, name, description=None, attributes=None, ssl_config=None):
    """Update an existing role in Keycloak."""
    # First get the current role to ensure it exists
    current_role = get_role_by_name(auth_url, token, name, ssl_config)

    # Prepare update data
    role_data = {
        'name': name,
        'description': description if description is not None else current_role.get('description', ''),
        'attributes': convert_attributes_to_keycloak_format(attributes) if attributes is not None else current_role.get('attributes', {})
    }

    try:
        make_keycloak_request(
            auth_url=auth_url,
            endpoint=f'/{name}',
            method='PUT',
            data=role_data,
            token=token,
            ssl_config=ssl_config
        )

        # Get the updated role details
        updated_role = get_role_by_name(auth_url, token, name, ssl_config)
        return updated_role, f"Role '{name}' updated successfully"

    except Exception as e:
        raise Exception(f"Failed to update role '{name}': {str(e)}")


def delete_role(auth_url, token, name, ssl_config=None):
    """Delete a role from Keycloak."""
    try:
        # First verify the role exists
        get_role_by_name(auth_url, token, name, ssl_config)

        # Delete the role
        make_keycloak_request(
            auth_url=auth_url,
            endpoint=f'/{name}',
            method='DELETE',
            token=token,
            ssl_config=ssl_config
        )

        return None, f"Role '{name}' deleted successfully"

    except Exception as e:
        raise Exception(f"Failed to delete role '{name}': {str(e)}")


def get_role_by_name(auth_url, token, name, ssl_config=None):
    """Get a specific role by name from Keycloak."""
    try:
        response = make_keycloak_request(
            auth_url=auth_url,
            endpoint=f'/{name}',
            method='GET',
            token=token,
            ssl_config=ssl_config
        )

        # Convert attributes to simple format for user-friendly output
        if 'attributes' in response:
            response['attributes'] = convert_attributes_from_keycloak_format(response['attributes'])

        return response

    except Exception as e:
        raise Exception(f"Failed to get role '{name}': {str(e)}")


def get_all_roles(auth_url, token, first=0, max_results=100, ssl_config=None):
    """Get all roles from Keycloak with pagination."""
    params = {
        'first': first,
        'max': max_results
    }

    try:
        response = make_keycloak_request(
            auth_url=auth_url,
            endpoint='',
            method='GET',
            params=params,
            token=token,
            ssl_config=ssl_config
        )

        # Convert attributes to simple format for user-friendly output
        if isinstance(response, list):
            for role in response:
                if 'attributes' in role:
                    role['attributes'] = convert_attributes_from_keycloak_format(role['attributes'])

        return response

    except Exception as e:
        raise Exception(f"Failed to get roles: {str(e)}")


def run_module():
    """Main module execution function."""
    module_args = dict(
        operation=dict(
            type='str',
            required=True,
            choices=['CREATE', 'UPDATE', 'DELETE', 'INSPECT', 'ENUMERATE']
        ),
        auth_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        name=dict(type='str', required=False),
        description=dict(type='str', required=False),
        attributes=dict(type='dict', required=False, default={}),
        first=dict(type='int', required=False, default=0),
        max=dict(type='int', required=False, default=100),
        ssl_config=dict(
            type='dict',
            required=False,
            default={},
            options=dict(
                validate_certs=dict(type='bool', default=True),
                ca_cert=dict(type='path'),
                client_cert=dict(type='path'),
                client_key=dict(type='path', no_log=False)
            )
        )
    )

    result = dict(
        changed=False,
        message='',
        role=None,
        roles=None
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Extract parameters
    operation = module.params['operation']
    auth_url = module.params['auth_url']
    token = module.params['token']
    name = module.params['name']
    description = module.params['description']
    attributes = module.params['attributes']
    first = module.params['first']
    max_results = module.params['max']
    ssl_config = module.params['ssl_config']

    # Validate required parameters for specific operations
    if operation in ['CREATE', 'ENUMERATE', 'DELETE', 'INSPECT']:
        if not name:
            module.fail_json(msg=f"Parameter 'name' is required for {operation} operation")

    # Validate SSL configuration
    if ssl_config.get('client_cert') and not ssl_config.get('client_key'):
        module.fail_json(msg="ssl_config.client_key is required when ssl_config.client_cert is provided")
    if ssl_config.get('client_key') and not ssl_config.get('client_cert'):
        module.fail_json(msg="ssl_config.client_cert is required when ssl_config.client_key is provided")

    try:
        if operation == 'CREATE':
            if module.check_mode:
                result['message'] = f"Would create role '{name}'"
                result['changed'] = True
            else:
                role, message = create_role(auth_url, token, name, description, attributes, ssl_config)
                result['role'] = role
                result['message'] = message
                result['changed'] = True

        elif operation == 'UPDATE':
            if module.check_mode:
                result['message'] = f"Would update role '{name}'"
                result['changed'] = True
            else:
                role, message = update_role(auth_url, token, name, description, attributes, ssl_config)
                result['role'] = role
                result['message'] = message
                result['changed'] = True

        elif operation == 'DELETE':
            if module.check_mode:
                result['message'] = f"Would delete role '{name}'"
                result['changed'] = True
            else:
                _, message = delete_role(auth_url, token, name, ssl_config)
                result['message'] = message
                result['changed'] = True

        elif operation == 'INSPECT':
            role = get_role_by_name(auth_url, token, name, ssl_config)
            result['role'] = role
            result['message'] = f"Retrieved role '{name}'"
            result['changed'] = False

        elif operation == 'ENUMERATE':
            roles = get_all_roles(auth_url, token, first, max_results, ssl_config)
            result['roles'] = roles
            result['message'] = f"Retrieved {len(roles)} roles"
            result['changed'] = False

    except Exception as e:
        module.fail_json(msg=str(e))

    module.exit_json(**result)


if __name__ == '__main__':
    run_module()
