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
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
import requests

DOCUMENTATION = r'''
---
module: role

short_description: Manage roles in PX-Backup

version_added: "2.8.1"

description: 
    - Manage roles in PX-Backup using different operations
    - Supports CRUD operations, and ownership management
    - Provides both single role and bulk inspection capabilities

options:
    operation:
        description:
            - " Operation to perform on the role "
            - " CREATE creates a new role "
            - " UPDATE modifies an existing role "
            - " DELETE removes a role "
            - " INSPECT_ONE retrieves details of a specific role "
            - " INSPECT_ALL lists all roles "
            - " PERMISSION returns list of services, APIs permission for given user"
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
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    rules:
        description: 
        required: False
        type: list
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

requirements:
    - python >= 3.9
    - requests

notes:
    - "Operation-specific required parameters:"
    - "CREATE: name, rules"
    - "UPDATE: name, uid, rules"
    - "DELETE: org_id, name, uid"
    - "INSPECT_ONE: org_id, name, uid"
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
        role_request['metadata']['uid'] = params['uid']
        
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

def permission(module, client):
    """Fetch permissions of a role"""

    params = {
        'org_id': module.params.get('org_id', "")
    }
    
    try:
        response = client.make_request('GET', 'v1/role', params=params)
        return response
    except Exception as e:
        module.fail_json(msg=f"Failed to fetch role permission: {str(e)}")

def enumerate_roles(module, client):
    """List all roles"""
    params = {
        'labels': module.params.get('labels', {})
    }
    
    try:
        response = client.make_request('GET', f"v1/role/{module.params['org_id']}", params=params)
        return response['roles']
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate roles: {str(e)}")

def inspect_role(module, client):
    """Get details of a specific role"""
    
    try:
        response = client.make_request(
            'GET',
            f"v1/role/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}",
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
            f"v1/role/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}",
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
        "rules": params.get('rules'),
    }

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
            role = permission(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'role': role},
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
        rules = dict(
            type='list',  
            required=False, 
            elements=dict(
                type='dict', 
                schema=dict( 
                    services=dict(
                        type='list',  
                        elements=dict(type='str')  
                    ),
                    apis=dict(
                        type='list',  
                        elements=dict(type='str')  
                    )
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
        validate_certs=dict(type='bool', default=True),
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
        'UPDATE': ['name', 'uid', 'rules'],
        'DELETE': ['name', 'uid'],
        'INSPECT_ONE': ['name', 'uid'],
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

        # Initialize client
        client = PXBackupClient(
            module.params['api_url'],
            module.params['token'],
            module.params['validate_certs']
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