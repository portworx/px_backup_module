#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Recipient Management Module

This Ansible module manages alert recipients in PX-Backup, providing operations for:
- Creating recipients
- Updating existing recipients
- Deleting recipients
- Inspecting recipients (single or all)
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
from typing import Dict, List, Tuple, Optional, Any, Union
import logging
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
import requests

DOCUMENTATION = r'''
---
module: recipient

short_description: Manage alert recipients in PX-Backup

version_added: "2.8.3"

description: 
    - Manage alert recipients in PX-Backup using different operations
    - Supports CRUD operations
    - Links recipients to receivers
    - Provides both single recipient and bulk inspection capabilities
    - Configure alert severity levels

options:
    operation:
        description:
            - Operation to perform on the recipient
            - " - CREATE: creates a new recipient"
            - " - UPDATE: modifies an existing recipient"
            - " - DELETE: removes a recipient"
            - " - INSPECT_ONE: retrieves details of a specific recipient"
            - " - INSPECT_ALL: lists all recipients"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL']
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
            - Name of the recipient
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description: 
            - Unique identifier of the recipient
            - Required for UPDATE, DELETE, and INSPECT_ONE operations
        required: false
        type: str
    recipient_type:
        description: Type of recipient
        required: false
        type: str
        choices: ['EMAIL']
        default: 'EMAIL'
    recipient_ids:
        description: List of recipient email addresses
        required: false
        type: list
        elements: str
    active:
        description: Whether the recipient is active
        required: false
        type: bool
        default: true
    receiver_ref:
        description: Reference to the receiver
        required: false
        type: dict
        suboptions:
            name:
                description: Name of the receiver
                type: str
            uid:
                description: UID of the receiver
                type: str
    severity:
        description: Alert severity level
        required: false
        type: str
        choices: ['UNKNOWN', 'CRITICAL', 'WARNING']
        default: 'WARNING'
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    labels:
        description: Labels to attach to the recipient
        required: false
        type: dict

requirements:
    - python >= 3.9
    - requests
'''

EXAMPLES = r'''
# Create an email recipient
- name: Create email recipient
  recipient:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "dev-team"
    org_id: "default"
    recipient_type: "EMAIL"
    recipient_ids: 
      - "dev1@example.com"
      - "dev2@example.com"
    receiver_ref:
      name: "smtp-server"
      uid: "receiver-uid"
    severity: "CRITICAL"
    active: true

# List all recipients
- name: List all recipients
  recipient:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
'''

RETURN = r'''
recipient:
    description: Details of the recipient for single-item operations
    type: dict
    returned: success
    sample: {
        "metadata": {
            "name": "dev-team",
            "org_id": "default",
            "uid": "123-456"
        },
        "recipient_info": {
            "type": "EMAIL",
            "recipient_id": ["dev1@example.com", "dev2@example.com"],
            "active": true,
            "severity": "CRITICAL",
            "receiver_ref": {
                "name": "smtp-server",
                "uid": "receiver-uid"
            }
        }
    }
recipients:
    description: List of recipients for INSPECT_ALL operation
    type: list
    returned: when operation is INSPECT_ALL
    sample: [
        {
            "metadata": {
                "name": "team1",
                "org_id": "default"
            }
        },
        {
            "metadata": {
                "name": "team2",
                "org_id": "default"
            }
        }
    ]
message:
    description: Operation result message
    type: str
    returned: always
changed:
    description: Whether the operation changed the recipient
    type: bool
    returned: always
'''

# Configure logging
logger = logging.getLogger('recipient')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class RecipientError(Exception):
    """Base exception for recipient operations"""
    pass

class ValidationError(RecipientError):
    """Raised when validation fails"""
    pass

class APIError(RecipientError):
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
    """Validate parameters for the given operation"""
    missing = [param for param in required_params if not params.get(param)]
    if missing:
        raise ValidationError(f"Operation '{operation}' requires parameters: {', '.join(missing)}")

def create_recipient(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new recipient"""
    try:
        recipient_request = build_recipient_request(module.params)
        response = client.make_request(
            method='POST',
            endpoint='v1/recipient',
            data=recipient_request
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to create recipient: {str(e)}")

def update_recipient(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing recipient"""
    try:
        recipient_request = build_recipient_request(module.params)
        recipient_request['metadata']['uid'] = module.params['uid']
        current = inspect_recipient(module, client)
        if not needs_update(current, recipient_request):
            return current, False

        response = client.make_request(
            method='PUT',
            endpoint='v1/recipient',
            data=recipient_request
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update recipient: {str(e)}")

def enumerate_recipients(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all recipients"""
    try:
        # Map recipient type string to integer value
        type_map = {
            'EMAIL': 1,
            'INVALID': 0
        }
        
        params = {
            'type': type_map.get(module.params.get('recipient_type', 'EMAIL'), 1)  # Default to EMAIL (1)
        }
        
        response = client.make_request(
            method='GET',
            endpoint=f"v1/recipient/{module.params['org_id']}",
            params=params
        )
        return response.get('recipients', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate recipients: {str(e)}")

def inspect_recipient(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific recipient"""
    try:
        response = client.make_request(
            method='GET',
            endpoint=f"v1/recipient/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}"
        )
        return response.get('recipient', {})
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect recipient: {str(e)}")

def delete_recipient(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a recipient"""
    try:
        response = client.make_request(
            method='DELETE',
            endpoint=f"v1/recipient/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}"
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete recipient: {str(e)}")

def build_recipient_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """Build recipient request object"""
    request = {
        "metadata": {
            "name": params['name'],
            "org_id": params['org_id']
        },
        "recipient_info": {
            "type": params.get('recipient_type', 'EMAIL'),
            "recipient_id": params.get('recipient_ids', []),
            "active": params.get('active', True),
            "severity": params.get('severity', 'WARNING')
        }
    }

    if params.get('labels'):
        request['metadata']['labels'] = params['labels']

    if params.get('receiver_ref'):
        request['recipient_info']['receiver_ref'] = {
            "name": params['receiver_ref'].get('name'),
            "uid": params['receiver_ref'].get('uid')
        }

    return request

def needs_update(current: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """Compare current and desired state to determine if update is needed"""
    def normalize_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(d, dict):
            return d
        return {k: normalize_dict(v) for k, v in d.items() if v is not None}

    current_normalized = normalize_dict(current)
    desired_normalized = normalize_dict(desired)
    return current_normalized != desired_normalized

def run_module():
    """Main module execution"""
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(
            type='str',
            required=True,
            choices=['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL']
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        recipient_type=dict(
            type='str',
            default='EMAIL',
            choices=['EMAIL']
        ),
        recipient_ids=dict(type='list', elements='str', required=False),
        active=dict(type='bool', default=True),
        receiver_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),
        severity=dict(
            type='str',
            default='WARNING',
            choices=['UNKNOWN', 'CRITICAL', 'WARNING']
        ),
        validate_certs=dict(type='bool', default=True),
        labels=dict(type='dict', required=False)
    )

    result = dict(
        changed=False,
        recipient={},
        recipients=[],
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'recipient_ids', 'receiver_ref'],
        'UPDATE': ['name', 'uid'],
        'DELETE': ['name', 'uid'],
        'INSPECT_ONE': ['name', 'uid'],
        'INSPECT_ALL': ['org_id']
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('operation', 'CREATE', ['name', 'recipient_ids', 'receiver_ref']),
            ('operation', 'UPDATE', ['name', 'uid']),
            ('operation', 'DELETE', ['name', 'uid']),
            ('operation', 'INSPECT_ONE', ['name', 'uid'])
        ]
    )

    try:
        operation = module.params['operation']
        validate_params(module.params, operation, operation_requirements[operation])

        if module.check_mode:
            module.exit_json(**result)

        client = PXBackupClient(
            module.params['api_url'],
            module.params['token'],
            module.params['validate_certs']
        )

        try:
            if operation == 'CREATE':
                recipient, changed = create_recipient(module, client)
                result.update({
                    'changed': changed,
                    'recipient': recipient,
                    'message': 'Recipient created successfully'
                })

            elif operation == 'UPDATE':
                recipient, changed = update_recipient(module, client)
                result.update({
                    'changed': changed,
                    'recipient': recipient,
                    'message': 'Recipient updated successfully'
                })

            elif operation == 'DELETE':
                _, changed = delete_recipient(module, client)
                result.update({
                    'changed': changed,
                    'message': 'Recipient deleted successfully'
                })

            elif operation == 'INSPECT_ONE':
                recipient = inspect_recipient(module, client)
                result.update({
                    'changed': False,
                    'recipient': recipient,
                    'message': 'Successfully retrieved recipient details'
                })

            elif operation == 'INSPECT_ALL':
                recipients = enumerate_recipients(module, client)
                result.update({
                    'changed': False,
                    'recipients': recipients,
                    'message': f'Found {len(recipients)} recipients'
                })

        except Exception as e:
            error_msg = str(e)
            if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
                try:
                    error_detail = e.response.json()
                    error_msg = f"{error_msg}: {error_detail}"
                except ValueError:
                    error_msg = f"{error_msg}: {e.response.text}"
            module.fail_json(msg=error_msg)

    except ValidationError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg=f"Unexpected error: {str(e)}")

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()