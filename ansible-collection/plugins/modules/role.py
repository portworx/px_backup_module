#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Role Management Module

This Ansible module manages roles in PX-Backup, providing operations for:
- Creating roles
- Updating existing roles
- Deleting roles
- Inspecting roles (single or all)
- Fetching list of permissions for a user

"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import typing
from typing import Dict, List, Tuple, Optional, Any, Union
import logging
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.px_backup.api import PXBackupClient
import requests

DOCUMENTATION = r'''
---
module: role

short_description: Manage roles in PX-Backup

version_added: "2.9.0"

description: 
    - Manage roles in PX-Backup using different operations
    - Supports CRUD operations, and ownership management
    - Provides both single role and bulk inspection capabilities

options:
    operation:
        description:
            - "- Operation to perform on the role "
            - "- CREATE creates a new role "
            - "- UPDATE modifies an existing role "
            - "- DELETE removes a role "
            - "- INSPECT_ONE retrieves details of a specific role "
            - "- INSPECT_ALL lists all roles "
            - "- PERMISSION returns list of services, APIs permission for given user"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL', 'PERMISSION']
    api_url:
        description: PX-Backup API URL
        required: true
        type: str
    token:
        description: Authentication token
        required: true
        type: str
    name:
        description: 
            - Name of the role
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description: 
            - Unique identifier of the role
            - Required for UPDATE, DELETE, VALIDATE, INSPECT_ONE, and PERMISSION operations
        required: false
        type: str
    labels:
        description: Labels to attach to the role
        required: false
        type: dict
    ssl_config:
        description:
            - SSL configuration dictionary containing certificate settings
            - Contains validate_certs, ca_cert, client_cert, and client_key options
            - If not provided, defaults to standard SSL verification
        required: false
        type: dict
        default: {}
        options:
            validate_certs:
                description:
                    - Verify SSL certificates
                    - Can be set to false for self-signed certificates
                type: bool
                default: true
            ca_cert:
                description:
                    - Path to CA certificate file for SSL verification
                    - If provided, this CA certificate will be used instead of system CA certificates
                type: path
            client_cert:
                description:
                    - Path to client certificate file for mutual TLS authentication
                    - Must be used together with client_key
                type: path
            client_key:
                description:
                    - Path to client private key file for mutual TLS authentication
                    - Required if client_cert is provided
                    - File permissions should be restricted (e.g., 600)
                type: path
        version_added: "2.10.0"
    rules:
        description: List of rules
        required: False
        type: list
        elements: dict
        suboptions:
            services:
                description: List of services
                type: list
                elements: str
            apis:
                description: List of APIs allowed
                type: list
                elements: str
    ownership:
        description: Ownership configuration for the role
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the role
                type: str
            groups:
                description: List of group access configurations
                type: list
                elements: dict
                suboptions:
                    id:
                        description: Group ID
                        type: str
                    access:
                        description: Access level
                        choices: ['Invalid', 'Read', 'Write', 'Admin']
                        type: str
            collaborators:
                description: List of collaborator access configurations
                type: list
                elements: dict
                suboptions:
                    id:
                        description: Collaborator ID
                        type: str
                    access:
                        description: Access level
                        choices: ['Invalid', 'Read', 'Write', 'Admin']
                        type: str
            public:
                description: Public access configuration
                type: dict
                suboptions:
                    type:
                        description: Public access type
                        choices: ['Invalid', 'Read', 'Write', 'Admin']
                        type: str
    role_id:
        description:
            - Keycloak role ID to associate with the PX-Backup role
            - This Keycloak role ID will be associated with the PX-Backup role
            - If not provided for CREATE operation, a Keycloak role will be automatically created
            - This ensures proper integration between PX-Backup roles and Keycloak authentication
            - Format: UUID string (e.g., 3fe6c733-6df6-4058-91b8-bcd3344c8564)
        required: false
        type: str
    auth_url:
        description:
            - Keycloak authentication server URL
            - For CREATE operation: required if role_id is not provided (used to automatically create Keycloak roles)
            - For DELETE operation: optional (if provided, the associated Keycloak role will also be deleted; if not provided, only PX-Backup role is deleted)
            - Note: skip_keycloak_deletion takes precedence over auth_url for DELETE operations
        required: false
        type: str
    skip_keycloak_deletion:
        description:
            - Skip deletion of the associated Keycloak role during DELETE operation
            - When set to true, only the PX-Backup role will be deleted, preserving the Keycloak role
            - This is useful when the Keycloak role is shared across multiple systems or when you want to preserve it for other purposes
            - Takes precedence over auth_url setting for DELETE operations
            - Only applicable for DELETE operation
        required: false
        type: bool
        default: false
    keycloak_description:
        description:
            - Description for the auto-created Keycloak role
            - Only used when role_id is not provided for CREATE operation
            - Default: "Role created via ansible"
        required: false
        type: str
        default: "Role created via ansible"
    keycloak_attributes:
        description:
            - Custom attributes for the auto-created Keycloak role
            - Only used when role_id is not provided for CREATE operation
            - Dictionary of key-value pairs
        required: false
        type: dict
        default: {}

requirements:
    - python >= 3.9
    - requests

notes:
    - "Operation-specific required parameters:"
    - "CREATE: name, rules (role_id optional - if not provided and auth_url is provided, a Keycloak role will be automatically created)"    
    - "UPDATE: name, rules (role_id optional - if not provided and auth_url is provided, a Keycloak role will be automatically updated)"    
    - "DELETE: org_id, name (auth_url optional - if provided and skip_keycloak_deletion is false, the associated Keycloak role will be deleted)"
    - "INSPECT_ONE: org_id, name"
    - "INSPECT_ALL: org_id"
    - "PERMISSION: org_id"
'''

# Configure logging
logger = logging.getLogger('role')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class RoleError(Exception):
    """Base exception for role operations"""
    pass

def delete_keycloak_role(auth_url, token, name, ssl_config=None):
    """Delete a role from Keycloak."""
    try:
        # Ensure auth_url has protocol
        if not auth_url.startswith(('http://', 'https://')):
            auth_url = f"http://{auth_url}"

        # Construct full URL
        base_url = auth_url.rstrip('/')
        url = f"{base_url}/auth/admin/realms/master/roles/{name}"

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

        # Prepare client certificates
        cert = None
        if client_cert and client_key:
            cert = (client_cert, client_key)

        # Make the request
        response = requests.delete(url, headers=headers, verify=verify, cert=cert)
        response.raise_for_status()

        return f"Keycloak role '{name}' deleted successfully"

    except Exception as e:
        raise Exception(f"Failed to delete Keycloak role '{name}': {str(e)}")

class ValidationError(RoleError):
    """Raised when validation fails"""
    pass

class APIError(RoleError):
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

def validate_params(params: Dict[str, Any], operation: str, required_params: List[str]) -> None:
    """
    Validate parameters for the given operation
    
    Args:
        params: Module parameters
        operation: Operation being performed
        required_params: List of required parameters

    Raises:
        ValidationError: If validation fails
    """
    missing = [param for param in required_params if not params.get(param)]
    if missing:
        raise ValidationError(f"Operation '{operation}' requires parameters: {', '.join(missing)}")
    

def create_role(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new role"""
    try:
        # Get module parameters directly
        params = dict(module.params)
        role_request = build_role_request(params)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/role',
            data=role_request
        )
        
        # Return the response
        return response, True
            
        
    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to create role: {error_msg}")

def update_role(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing role"""
    try:
        # Build request using module.params
        params = dict(module.params)
        role_request = build_role_request(params)
        role_request['metadata']['uid'] = params.get('uid', '')
        
        # Get current state for comparison
        current = inspect_role(module, client)
        if not needs_update(current, role_request):
            return current, False
            
        # Make update request
        response = client.make_request(
            method='PUT',
            endpoint='v1/role',
            data=role_request
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update role: {str(e)}")

def permission_role(module, client):
    """Fetch all permissions"""

    params = {
        'org_id': module.params.get('org_id', "")
    }
    
    try:
        response = client.make_request('GET', f"v1/role", params=params)
        return response['rules']
    except Exception as e:
        module.fail_json(msg=f"Failed to fetch permissions: {str(e)}")

def enumerate_roles(module, client):
    """List all roles"""
    params = {
        'labels': module.params.get('labels', {})
    }
    
    try:
        response = client.make_request('GET', f"v1/role/{module.params['org_id']}", params=params)
        return response.get('roles', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate roles: {str(e)}")

def inspect_role(module, client):
    """Get details of a specific role"""
    
    try:
        response = client.make_request(
            'GET',
            f"v1/role/{module.params['org_id']}/{module.params['name']}",
            params={}
        )
        return response
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect role: {str(e)}")

def delete_role(module, client):
    """Delete a role"""
    try:
        # Standard delete by name approach
        endpoint = f"v1/role/{module.params['org_id']}/{module.params['name']}"
        params = {}

        response = client.make_request(
            'DELETE',
            endpoint,
            params=params
        )

        auth_url = module.params.get('auth_url')
        skip_keycloak_deletion = module.params.get('skip_keycloak_deletion', False)

        # Check if Keycloak role deletion should be skipped
        if skip_keycloak_deletion:
            logger.info(f"Skipping Keycloak role deletion for '{module.params['name']}' due to skip_keycloak_deletion=true")
        elif auth_url:
            try:
                keycloak_role_name = f"{module.params['name']}"
                ssl_config = module.params.get('ssl_config', {})
                token = module.params.get('token')

                delete_keycloak_role(auth_url, token, keycloak_role_name, ssl_config)
                logger.info(f"Associated Keycloak role '{keycloak_role_name}' deleted successfully")
            except Exception as keycloak_error:
                # Log the error but don't fail - PX-Backup role was already deleted
                logger.warning(f"Failed to delete associated Keycloak role: {str(keycloak_error)}")
        else:
            logger.info(f"No auth_url provided - skipping Keycloak role deletion for '{module.params['name']}'")

        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete role: {str(e)}")


def build_role_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build role request object
    
    Args:
        params: Module parameters
    
    Returns:
        Dict containing the request object
    """
    request = {
        "metadata": {
            "name": params.get('name'),
            "org_id": params.get('org_id')
        }
    }

    # Add rules if provided
    if params.get('rules'):
        request['rules'] = params['rules']

    # Add optional configurations safely
    if params.get('labels'):
        request['metadata']['labels'] = params['labels']
        
    if params.get('ownership'):
        request['metadata']['ownership'] = params['ownership']

    return request

def needs_update(current, desired):
    """Compare current and desired state to determine if update is needed"""
    # Add sophisticated comparison logic here
    def normalize_dict(d):
        """Normalize dictionary for comparison by removing None values and sorting lists"""
        if not isinstance(d, dict):
            return d
        return {k: normalize_dict(v) for k, v in d.items() if v is not None}
    
    current_normalized = normalize_dict(current)
    desired_normalized = normalize_dict(desired)
    return current_normalized != desired_normalized


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

def perform_operation(module: AnsibleModule, client: PXBackupClient, operation: str) -> OperationResult:
    """
    Perform the requested operation
    
    Args:
        module: Ansible module instance
        client: PX-Backup API client
        operation: Operation to perform
    
    Returns:
        OperationResult containing operation outcome
    """
    try:
        if operation == 'CREATE':
            role, changed = create_role(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'role': role},
                message="Role created successfully"
            )
        
        elif operation == 'INSPECT_ALL':
            roles = enumerate_roles(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'roles': roles},
                message=f"Found {len(roles)} roles"
            )

        elif operation == 'INSPECT_ONE':
            role = inspect_role(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'role': role},
                message="Successfully retrieved role details"
            )

        elif operation == 'UPDATE':
            role, changed = update_role(module, client)
            return OperationResult(
            success=True,
            changed=changed,
            data={'role': role},
            message="Role updated successfully"
            )

        elif operation == 'PERMISSION':
            rules = permission_role(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'rules': rules},
                message="Role permissions fetched successfully"
            )
        
        elif operation == 'DELETE':
            role, changed = delete_role(module, client)
            return OperationResult(
            success=True,
            changed=changed,
            data={'role': role},
            message="Role deleted successfully"
            )

    except Exception as e:
        logger.exception(f"Operation {operation} failed")
        return OperationResult(
            success=False,
            changed=False,
            error=handle_api_error(e, operation)
        )

def run_module():
    """Main module execution"""
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(
            type='str',
            required=True,
            choices=[
                'CREATE',
                'UPDATE',
                'DELETE',
                'INSPECT_ONE',
                'INSPECT_ALL',
                'PERMISSION'
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        role_id=dict(type='str', required=False),
        auth_url=dict(type='str', required=False),
        skip_keycloak_deletion=dict(type='bool', required=False, default=False),
        keycloak_description=dict(type='str', required=False),
        keycloak_attributes=dict(type='dict', required=False, default={}),
        rules=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                services=dict(
                    type='list',
                    elements='str',
                    required=True
                ),
                apis=dict(
                    type='list',
                    elements='str',
                    required=True
                )
            )
        ),
        labels=dict(type='dict', required=False),
        ownership=dict(
            type='dict',
            required=False,
            options=dict(
                owner=dict(type='str'),
                groups=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        id=dict(type='str'),
                        access=dict(
                            type='str',
                            choices=['Read', 'Write', 'Admin']
                        )
                    )
                ),
                collaborators=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        id=dict(type='str'),
                        access=dict(
                            type='str',
                            choices=['Read', 'Write', 'Admin']
                        )
                    )
                ),
                public=dict(
                    type='dict',
                    options=dict(
                        type=dict(
                            type='str',
                            choices=['Read', 'Write', 'Admin']
                        )
                    )
                )
            )
        ),
        # SSL cert implementation
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
        ),
    )

    result = dict(
        changed=False,
        role={},
        roles=[],
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'rules'],
        'UPDATE': ['name','rules'],
        'DELETE': ['name'],
        'INSPECT_ONE': ['name'],
        'INSPECT_ALL': ['org_id'],
        'PERMISSION': ['org_id']
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    try:
        # Validate operation parameters
        operation = module.params['operation']
        validate_params(module.params, operation, operation_requirements[operation])

        if module.check_mode:
            module.exit_json(**result)

        # Get SSL configuration
        ssl_config = module.params.get('ssl_config', {})

        # Validate certificate files exist if provided in ssl_config
        import os
        for cert_param in ['ca_cert', 'client_cert', 'client_key']:
            cert_path = ssl_config.get(cert_param)
            if cert_path:
                if not os.path.exists(cert_path):
                    module.fail_json(msg=f"ssl_config.{cert_param} file not found: {cert_path}")
                if not os.access(cert_path, os.R_OK):
                    module.fail_json(msg=f"ssl_config.{cert_param} file not readable: {cert_path}")

        # Validate that if client_cert is provided, client_key must also be provided
        if ssl_config.get('client_cert') and not ssl_config.get('client_key'):
            module.fail_json(msg="ssl_config.client_key is required when ssl_config.client_cert is provided")
        if ssl_config.get('client_key') and not ssl_config.get('client_cert'):
            module.fail_json(msg="ssl_config.client_cert is required when ssl_config.client_key is provided")

        # Initialize client
        client = PXBackupClient(
            api_url=module.params['api_url'],
            token=module.params['token'],
            validate_certs=ssl_config.get('validate_certs', True),
            ca_cert=ssl_config.get('ca_cert'),
            client_cert=ssl_config.get('client_cert'),
            client_key=ssl_config.get('client_key')
        )

        # Perform operation
        operation_result = perform_operation(module, client, operation)
        
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