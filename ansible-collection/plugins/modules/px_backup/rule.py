#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Rule Management Module

This Ansible module manages rules in PX-Backup, providing operations for:
- Creating rules
- Updating existing rules
- Deleting rules
- Inspecting rules (single or all)
- Managing rule ownership

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
module: rule

short_description: Manage rules in PX-Backup

version_added: "2.8.1"

description: 
    - Manage rules in PX-Backup using different operations
    - Supports CRUD operations, and ownership management
    - Provides both single location and bulk inspection capabilities

options:
    operation:
        description:
            - " Operation to perform on the rule "
            - " CREATE creates a new rule "
            - " UPDATE modifies an existing rule "
            - " DELETE removes a rule "
            - " INSPECT_ONE retrieves details of a specific rule "
            - " INSPECT_ALL lists all rules "
            - " UPDATE_OWNERSHIP' updates ownership settings of a rule "
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL', 'UPDATE_OWNERSHIP']
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
            - Name of the rule
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description: 
            - Unique identifier of the rule
            - Required for UPDATE, DELETE, VALIDATE, INSPECT_ONE, and UPDATE_OWNERSHIP operations
        required: false
        type: str
    labels:
        description: Labels to attach to the rule
        required: false
        type: dict
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    rules:
        description: 
            - List of rules to apply
            - Required for CREATE and UPDATE operations
        required: false
        type: list
        suboptions:
            pod_selector:
                description: Pod selector for the rule
                type: dict
                required: true
            actions:
                description: List of actions to perform
                type: list
                elements: dict
                required: false
                suboptions:
                    background:
                        description: Run the action in the background
                        type: bool
                        default: true
                    run_in_single_pod:
                        description: Run the action in a single pod
                        type: bool
                        default: true
                    value:
                        description: Action to perform
                        type: str
            container:
                description: Container to apply the rule to
                type: str
    ownership:
        description: 
            - Ownership configuration for the rule
            - Required for UPDATE_OWNERSHIP operation
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the rule
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
    - "UPDATE_OWNERSHIP: org_id, name, uid, ownership"
'''

# Configure logging
logger = logging.getLogger('rule')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class RuleError(Exception):
    """Base exception for rule operations"""
    pass

class ValidationError(RuleError):
    """Raised when validation fails"""
    pass

class APIError(RuleError):
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
    

def create_rule(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new rule"""
    try:
        # Get module parameters directly
        params = dict(module.params)
        rule_request = build_rule_request(params)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/rule',
            data=rule_request
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
        module.fail_json(msg=f"Failed to create rule: {error_msg}")

def update_rule(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing rule"""
    try:
        # Build request using module.params
        params = dict(module.params)
        rule_request = build_rule_request(params)
        rule_request['metadata']['uid'] = params['uid']
        
        # Get current state for comparison
        current = inspect_rule(module, client)
        if not needs_update(current, rule_request):
            return current, False
            
        # Make update request
        response = client.make_request(
            method='PUT',
            endpoint='v1/rule',
            data=rule_request
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update rule: {str(e)}")

def update_ownership(module, client):
    """Update ownership of a rule"""
    ownership_request = {
        "org_id": module.params['org_id'],
        "name": module.params['name'],
        "ownership": module.params['ownership'],
        "uid": module.params['uid']
    }
    
    try:
        response = client.make_request('PUT', 'v1/rule/updateownership', ownership_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update rule ownership: {str(e)}")

def enumerate_rules(module, client):
    """List all rules"""
    params = {
        'labels': module.params.get('labels', {})
    }
    
    try:
        response = client.make_request('GET', f"v1/rule/{module.params['org_id']}", params=params)
        return response['rules']
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate rules: {str(e)}")

def inspect_rule(module, client):
    """Get details of a specific rule"""
    
    try:
        response = client.make_request(
            'GET',
            f"v1/rule/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}",
            params={}
        )
        return response
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect rule: {str(e)}")

def delete_rule(module, client):
    """Delete a rule"""
    try:
        response = client.make_request(
            'DELETE',
            f"v1/rule/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}",
            params={}
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete rule: {str(e)}")


def build_rule_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build rule request object
    
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
        "rules_info": {
            "rules": params.get('rules'),
        }
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
    return f"Failed to {operation.lower()} rule: {error_msg}"

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
            rule, changed = create_rule(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'rule': rule},
                message="rule created successfully"
            )
        
        elif operation == 'INSPECT_ALL':
            rules = enumerate_rules(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'rules': rules},
                message=f"Found {len(rules)} rules"
            )

        elif operation == 'INSPECT_ONE':
            rule = inspect_rule(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'rule': rule},
                message="Successfully retrieved rule details"
            )

        elif operation == 'UPDATE':
            rule, changed = update_rule(module, client)
            return OperationResult(
            success=True,
            changed=changed,
            data={'rule': rule},
            message="rule updated successfully"
            )

        elif operation == 'UPDATE_OWNERSHIP':
            rule, changed = update_ownership(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'rule': rule},
                message="rule ownership updated successfully"
            )
        
        elif operation == 'DELETE':
            rule, changed = delete_rule(module, client)
            return OperationResult(
            success=True,
            changed=changed,
            data={'rule': rule},
            message="rule deleted successfully"
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
                'UPDATE_OWNERSHIP'
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        rules=dict(
            type='list',
            elements='dict',
            options=dict(
                pod_selector=dict(type='dict', required=True),  
                actions=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        background=dict(type='bool', default=True),
                        run_in_single_pod=dict(type='bool', default=True),
                        value=dict(type='str', required=False)
                    )
                ),
                container=dict(type='str', required=False)
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
        rule={},
        rules=[],
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'rules'],
        'UPDATE': ['name', 'uid', 'rules'],
        'DELETE': ['name', 'uid'],
        'INSPECT_ONE': ['name', 'uid'],
        'INSPECT_ALL': ['org_id'],
        'UPDATE_OWNERSHIP': ['name', 'uid', 'ownership']
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