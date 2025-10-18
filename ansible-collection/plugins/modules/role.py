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
import base64

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
    - For CREATE operations, requires a pre-existing Keycloak role ID (use keycloak_role module first)

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
            - "- GET_CURRENT_USER_ROLES returns roles owned by the current user (from token)"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL', 'PERMISSION', 'GET_CURRENT_USER_ROLES']
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
            - Required for CREATE operation - the Keycloak role must be created first using the keycloak_role module
            - This ensures proper integration between PX-Backup roles and Keycloak authentication
            - Format: UUID string (e.g., 3fe6c733-6df6-4058-91b8-bcd3344c8564)
            - To create the Keycloak role, use the keycloak_role module with operation CREATE before calling this module
        required: true
        type: str

requirements:
    - python >= 3.9
    - requests

notes:
    - "Operation-specific required parameters:"
    - "CREATE: name, rules"
    - "UPDATE: name, rules"
    - "DELETE: org_id, name"
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

        # Validate that role_id is provided
        if not params.get('role_id'):
            module.fail_json(msg="role_id is required for role creation. Please create the Keycloak role first using the keycloak_role module.")

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

def get_current_user_from_token(token):
    """Extract user information from JWT token"""
    try:
        # JWT tokens have 3 parts: header.payload.signature
        # We want the payload (middle part)
        parts = token.split('.')
        if len(parts) != 3:
            return None

        payload_b64 = parts[1]

        # Add padding if needed (base64 strings must be multiples of 4)
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += '=' * padding

        # Decode base64 and parse JSON
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        user_info = json.loads(payload_json)

        return {
            'user_id': user_info.get('sub', ''),
            'email': user_info.get('email', ''),
            'issuer': user_info.get('iss', ''),
            'audience': user_info.get('aud', ''),
            'issued_at': user_info.get('iat', ''),
            'expires_at': user_info.get('exp', ''),
            'jwt_id': user_info.get('jti', '')
        }
    except Exception:
        return None

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

def get_current_user_roles(module, client):
    """Get roles owned by the current user"""
    try:
        # Get user info from token
        token = module.params.get('token', '')
        user_info = get_current_user_from_token(token)

        if not user_info or not user_info.get('user_id'):
            module.fail_json(msg="Failed to extract user information from token")

        # Get all roles
        params = {
            'labels': module.params.get('labels', {})
        }
        response = client.make_request('GET', f"v1/role/{module.params['org_id']}", params=params)
        all_roles = response.get('roles', [])

        # Filter roles owned by current user
        current_user_id = user_info['user_id']
        user_roles = [
            role for role in all_roles
            if role.get('metadata', {}).get('ownership', {}).get('owner') == current_user_id
        ]

        return {
            'user_info': user_info,
            'roles': user_roles,
            'total_user_roles': len(user_roles),
            'total_all_roles': len(all_roles)
        }
    except Exception as e:
        module.fail_json(msg=f"Failed to get current user roles: {str(e)}")

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
        response = client.make_request(
            'DELETE',
            f"v1/role/{module.params['org_id']}/{module.params['name']}",
            params={}
        )
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
        },
        "role_id": params['role_id']
    }

    # Add rules if provided
    if params.get('rules'):
        request['rules'] = params['rules']

    # Add optional configurations safely
    if params.get('labels'):
        request['metadata']['labels'] = params['labels']
        
    if params.get('ownership'):
        # Use explicitly provided ownership
        request['metadata']['ownership'] = params['ownership']
    else:
        # Determine owner ID: use role_id if provided, otherwise extract from token
        owner_id = params.get('role_id')

        if not owner_id:
            # Extract from current user token as fallback
            token = params.get('token', '')
            user_info = get_current_user_from_token(token)
            if user_info and user_info.get('user_id'):
                owner_id = user_info['user_id']

        # Set ownership if we have an owner ID
        if owner_id:
            request['metadata']['ownership'] = {
                "owner": owner_id,
                "public": {
                    "type": "Read"
                }
            }

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

        elif operation == 'GET_CURRENT_USER_ROLES':
                result = get_current_user_roles(module, client)
                return OperationResult(
                    success=True,
                    changed=False,
                    data=result,
                    message=f"Found {result['total_user_roles']} roles owned by current user"
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
                'PERMISSION',
                'GET_CURRENT_USER_ROLES'
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        role_id=dict(type='str', required=False),
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
        'CREATE': ['name', 'rules', 'role_id'],
        'UPDATE': ['name','rules'],
        'DELETE': ['name'],
        'INSPECT_ONE': ['name'],
        'INSPECT_ALL': ['org_id'],
        'PERMISSION': ['org_id'],
        'GET_CURRENT_USER_ROLES': []
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