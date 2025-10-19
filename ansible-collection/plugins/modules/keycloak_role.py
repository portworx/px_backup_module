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

from typing import Dict, Optional, Any
import logging
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule
import requests

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

# Configure logging
logger = logging.getLogger('keycloak_role')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class KeycloakRoleError(Exception):
    """Base exception for Keycloak role operations"""
    pass

class ValidationError(KeycloakRoleError):
    """Raised when validation fails"""
    pass

class APIError(KeycloakRoleError):
    """Raised when API requests fail"""
    pass

@dataclass
class OperationResult:
    """Data class for operation results"""
    success: bool
    changed: bool
    data: Optional[Dict[str, Any]] = None
    message: str = ""
    error: Optional[str] = None


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

        # Check for HTTP error status codes and raise for unsuccessful responses
        response.raise_for_status()

        # Return JSON response for successful requests
        if response.status_code == 204:  # No Content (successful DELETE)
            return {}

        if response.content:
            return response.json()
        else:
            return {}

    except requests.exceptions.RequestException as e:
        # Enhanced error handling consistent with other modules
        error_msg = str(e)
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        raise APIError(f"Keycloak API request failed: {error_msg}")


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
    try:
        role_data = {
            'name': name,
            'description': description or '',
            'attributes': convert_attributes_to_keycloak_format(attributes)
        }

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
        logger.exception(f"Failed to create role '{name}'")
        raise APIError(f"Failed to create role '{name}': {str(e)}")


def update_role(auth_url, token, name, description=None, attributes=None, ssl_config=None):
    """Update an existing role in Keycloak."""
    try:
        # First get the current role to ensure it exists
        current_role = get_role_by_name(auth_url, token, name, ssl_config)

        # Prepare update data
        role_data = {
            'name': name,
            'description': description if description is not None else current_role.get('description', ''),
            'attributes': convert_attributes_to_keycloak_format(attributes) if attributes is not None else current_role.get('attributes', {})
        }

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
        logger.exception(f"Failed to update role '{name}'")
        raise APIError(f"Failed to update role '{name}': {str(e)}")


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
        logger.exception(f"Failed to delete role '{name}'")
        raise APIError(f"Failed to delete role '{name}': {str(e)}")


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
    try:
        params = {
            'first': first,
            'max': max_results
        }

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
        logger.exception("Failed to get roles")
        raise APIError(f"Failed to get roles: {str(e)}")


def handle_api_error(e: Exception, operation: str) -> str:
    """
    Handle API errors and format error message

    Args:
        e: Exception object
        operation: Operation being performed

    Returns:
        Formatted error message
    """
    error_msg = str(e)
    if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
        try:
            error_detail = e.response.json()
            error_msg = f"{error_msg}: {error_detail}"
        except ValueError:
            error_msg = f"{error_msg}: {e.response.text}"
    return f"Failed to {operation.lower()} role: {error_msg}"


def perform_operation(module: AnsibleModule, operation: str) -> OperationResult:
    """
    Perform the requested operation

    Args:
        module: Ansible module instance
        operation: Operation to perform

    Returns:
        OperationResult with success status and data
    """
    try:
        # Extract common parameters
        auth_url = module.params['auth_url']
        token = module.params['token']
        name = module.params.get('name')
        description = module.params.get('description')
        attributes = module.params.get('attributes')
        ssl_config = module.params.get('ssl_config')
        first = module.params.get('first', 0)
        max_results = module.params.get('max', 100)

        if operation == 'CREATE':
            role, message = create_role(auth_url, token, name, description, attributes, ssl_config)
            return OperationResult(
                success=True,
                changed=True,
                data={'role': role},
                message=message
            )

        elif operation == 'UPDATE':
            role, message = update_role(auth_url, token, name, description, attributes, ssl_config)
            return OperationResult(
                success=True,
                changed=True,
                data={'role': role},
                message=message
            )

        elif operation == 'DELETE':
            _, message = delete_role(auth_url, token, name, ssl_config)
            return OperationResult(
                success=True,
                changed=True,
                message=message
            )

        elif operation == 'INSPECT':
            role = get_role_by_name(auth_url, token, name, ssl_config)
            return OperationResult(
                success=True,
                changed=False,
                data={'role': role},
                message=f"Retrieved role '{name}'"
            )

        elif operation == 'ENUMERATE':
            roles = get_all_roles(auth_url, token, first, max_results, ssl_config)
            return OperationResult(
                success=True,
                changed=False,
                data={'roles': roles},
                message=f"Retrieved {len(roles)} roles"
            )

    except Exception as e:
        logger.exception(f"Operation {operation} failed")
        return OperationResult(
            success=False,
            changed=False,
            error=handle_api_error(e, operation)
        )


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
    name = module.params.get('name')
    ssl_config = module.params.get('ssl_config', {})

    try:
        # Validate required parameters for specific operations
        if operation in ['CREATE', 'UPDATE', 'DELETE', 'INSPECT']:
            if not name:
                raise ValidationError(f"Parameter 'name' is required for {operation} operation")

         # Validate certificate files exist if provided in ssl_config and validation is enabled
        import os
        for cert_param in ['ca_cert', 'client_cert', 'client_key']:
            cert_path = ssl_config.get(cert_param)
            if cert_path:
                if not os.path.exists(cert_path):
                    module.fail_json(msg=f"ssl_config.{cert_param} file not found: {cert_path}")
                if not os.access(cert_path, os.R_OK):
                    module.fail_json(msg=f"ssl_config.{cert_param} file not readable: {cert_path}")

        # Validate SSL configuration
        if ssl_config.get('client_cert') and not ssl_config.get('client_key'):
            raise ValidationError("ssl_config.client_key is required when ssl_config.client_cert is provided")
        if ssl_config.get('client_key') and not ssl_config.get('client_cert'):
            raise ValidationError("ssl_config.client_cert is required when ssl_config.client_key is provided")

        # Handle check mode
        if module.check_mode:
            if operation in ['CREATE', 'UPDATE', 'DELETE']:
                result.update(
                    changed=True,
                    message=f"Would {operation.lower()} role '{name}'"
                )
            else:
                result.update(
                    changed=False,
                    message=f"Would {operation.lower()} role(s)"
                )
            module.exit_json(**result)

        # Perform operation
        operation_result = perform_operation(module, operation)

        if not operation_result.success:
            module.fail_json(msg=operation_result.error)

        # Update result with operation outcome
        result.update(
            changed=operation_result.changed,
            message=operation_result.message
        )
        if operation_result.data:
            result.update(operation_result.data)

    except ValidationError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        logger.exception("Unexpected error occurred")
        module.fail_json(msg=f"Unexpected error: {str(e)}")

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
