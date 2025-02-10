#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Receiver Management Module

This Ansible module manages alert receivers in PX-Backup, providing operations for:
- Creating receivers (currently supports Email type)
- Updating existing receivers
- Deleting receivers
- Validating SMTP configurations
- Inspecting receivers (single or all)
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
module: receiver

short_description: Manage alert receivers in PX-Backup

version_added: "2.8.3"

description: 
    - Manage alert receivers in PX-Backup using different operations
    - Supports CRUD operations and SMTP validation
    - Currently supports Email type receivers
    - Provides both single receiver and bulk inspection capabilities

options:
    operation:
        description:
            - Operation to perform on the receiver
            - " - CREATE: creates a new receiver"
            - " - UPDATE: modifies an existing receiver"
            - " - DELETE: removes a receiver"
            - " - VALIDATE_SMTP: validates SMTP configuration"
            - " - INSPECT_ONE: retrieves details of a specific receiver"
            - " - INSPECT_ALL: lists all receivers"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'VALIDATE_SMTP', 'INSPECT_ONE', 'INSPECT_ALL']
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
            - Name of the receiver
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description: 
            - Unique identifier of the receiver
            - Required for UPDATE, DELETE, and INSPECT_ONE operations
        required: false
        type: str
    receiver_type:
        description: Type of receiver (currently only EMAIL is supported)
        required: false
        type: str
        choices: ['EMAIL']
        default: 'EMAIL'
    email_config:
        description: Email receiver configuration
        required: false
        type: dict
        suboptions:
            from_address:
                description: Sender email address
                type: str
            host:
                description: SMTP host address
                type: str
            port:
                description: SMTP port
                type: str
            encryption_ssl:
                description: Enable SSL encryption
                type: bool
                default: false
            encryption_starttls:
                description: Enable STARTTLS encryption
                type: bool
                default: false
            authentication:
                description: Enable SMTP authentication
                type: bool
                default: false
            auth_username:
                description: SMTP authentication username
                type: str
            auth_password:
                description: SMTP authentication password
                type: str
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    include_secrets:
        description: Include sensitive information in response
        type: bool
        default: false
    labels:
        description: Labels to attach to the receiver
        required: false
        type: dict

requirements:
    - python >= 3.9
    - requests
'''

EXAMPLES = r'''
# Create an email receiver
- name: Create email receiver
  receiver:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "alerts-email"
    org_id: "default"
    receiver_type: "EMAIL"
    email_config:
       from_address: "alerts@example.com"
      host: "smtp.example.com"
      port: "587"
      encryption_starttls: true
      authentication: true
      auth_username: "alerts@example.com"
      auth_password: "{{ smtp_password }}"

# List all receivers
- name: List all receivers
  receiver:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"

# Validate SMTP configuration
- name: Validate SMTP settings
  receiver:
    operation: VALIDATE_SMTP
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "alerts-email"
    org_id: "default"
    uid: "receiver-uid"
'''

RETURN = r'''
receiver:
    description: Details of the receiver for single-item operations
    type: dict
    returned: success
    sample: {
        "metadata": {
            "name": "alerts-email",
            "org_id": "default",
            "uid": "123-456"
        },
        "receiver_info": {
            "type": "EMAIL",
            "email_config": {
                "from": "alerts@example.com",
                "host": "smtp.example.com",
                "port": "587"
            }
        }
    }
receivers:
    description: List of receivers for INSPECT_ALL operation
    type: list
    returned: when operation is INSPECT_ALL
    sample: [
        {
            "metadata": {
                "name": "receiver1",
                "org_id": "default"
            }
        },
        {
            "metadata": {
                "name": "receiver2",
                "org_id": "default"
            }
        }
    ]
message:
    description: Operation result message
    type: str
    returned: always
changed:
    description: Whether the operation changed the receiver
    type: bool
    returned: always
'''

# Configure logging
logger = logging.getLogger('receiver')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class ReceiverError(Exception):
    """Base exception for receiver operations"""
    pass

class ValidationError(ReceiverError):
    """Raised when validation fails"""
    pass

class APIError(ReceiverError):
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

def create_receiver(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new receiver"""
    try:
        receiver_request = build_receiver_request(module.params)
        response = client.make_request(
            method='POST',
            endpoint='v1/receiver',
            data=receiver_request
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to create receiver: {str(e)}")

def update_receiver(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing receiver"""
    try:
        receiver_request = build_receiver_request(module.params)
        receiver_request['metadata']['uid'] = module.params['uid']
        
        current = inspect_receiver(module, client)
        if not needs_update(current, receiver_request):
            return current, False

        response = client.make_request(
            method='PUT',
            endpoint='v1/receiver',
            data=receiver_request
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update receiver: {str(e)}")

def validate_smtp(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Validate SMTP configuration"""
    try:
        validate_request = {
            "metadata": {
                "name": module.params['name'],
                "org_id": module.params['org_id']
            },
            "recipient_id": module.params.get('recipient_id', []),
            "receiver_info_config": build_receiver_request(module.params)['receiver_info']
        }
        
        response = client.make_request(
            method='POST',
            endpoint='v1/receiver/validate',
            data=validate_request
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to validate SMTP configuration: {str(e)}")

def enumerate_receivers(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all receivers"""
    try:
        params = {
            'include_secrets': module.params.get('include_secrets', False)
        }
        response = client.make_request(
            method='GET',
            endpoint=f"v1/receiver/{module.params['org_id']}",
            params=params
        )
        return response.get('receivers', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate receivers: {str(e)}")

def inspect_receiver(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific receiver"""
    try:
        response = client.make_request(
            method='GET',
            endpoint=f"v1/receiver/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}/{module.params['include_secrets']}/{module.params['receiver_type']}",
            params={}
        )
        return response.get('receiver', {})
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect receiver: {str(e)}")

def delete_receiver(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a receiver"""
    try:
        response = client.make_request(
            method='DELETE',
            endpoint=f"v1/receiver/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}"
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete receiver: {str(e)}")

def build_receiver_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """Build receiver request object"""
    request = {
        "metadata": {
            "name": params['name'],
            "org_id": params['org_id']
        },
        "receiver_info": {
            "type": params.get('receiver_type', 'EMAIL')
        }
    }

    if params.get('labels'):
        request['metadata']['labels'] = params['labels']

    if params.get('email_config'):
        request['receiver_info']['email_config'] = {
            "from": params['email_config'].get('from_address'),
            "host": params['email_config'].get('host'),
            "port": params['email_config'].get('port'),
            "encryption_ssl": params['email_config'].get('encryption_ssl', False),
            "encryption_starttls": params['email_config'].get('encryption_starttls', False),
            "authentication": params['email_config'].get('authentication', False)
        }
        
        if params['email_config'].get('authentication'):
            request['receiver_info']['email_config'].update({
                "auth_username": params['email_config'].get('auth_username'),
                "auth_password": params['email_config'].get('auth_password')
            })

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
            choices=['CREATE', 'UPDATE', 'DELETE', 'VALIDATE_SMTP', 'INSPECT_ONE', 'INSPECT_ALL']
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        receiver_type=dict(
            type='str',
            default='EMAIL',
            choices=['EMAIL']
        ),
        email_config=dict(
            type='dict',
            required=False,
            options=dict(
                from_address=dict(type='str', required=True),
                host=dict(type='str', required=True),
                port=dict(type='str', required=True),
                encryption_ssl=dict(type='bool', default=False),
                encryption_starttls=dict(type='bool', default=False),
                authentication=dict(type='bool', default=False),
                auth_username=dict(type='str', no_log=True),
                auth_password=dict(type='str', no_log=True)
            )
        ),
        validate_certs=dict(type='bool', default=True),
        include_secrets=dict(type='bool', default=False),
        labels=dict(type='dict', required=False),
        recipient_id=dict(type='list', elements='str', required=False)
    )

    result = dict(
        changed=False,
        receiver={},
        receivers=[],
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'email_config'],
        'UPDATE': ['name', 'uid', 'email_config'],
        'DELETE': ['name', 'uid'],
        'VALIDATE_SMTP': ['name', 'email_config'],
        'INSPECT_ONE': ['name', 'uid'],
        'INSPECT_ALL': ['org_id']
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('operation', 'CREATE', ['name', 'email_config']),
            ('operation', 'UPDATE', ['name', 'uid', 'email_config']),
            ('operation', 'DELETE', ['name', 'uid']),
            ('operation', 'VALIDATE_SMTP', ['name', 'email_config']),
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
                receiver, changed = create_receiver(module, client)
                result.update({
                    'changed': changed,
                    'receiver': receiver,
                    'message': 'Receiver created successfully'
                })

            elif operation == 'UPDATE':
                receiver, changed = update_receiver(module, client)
                result.update({
                    'changed': changed,
                    'receiver': receiver,
                    'message': 'Receiver updated successfully'
                })

            elif operation == 'DELETE':
                _, changed = delete_receiver(module, client)
                result.update({
                    'changed': changed,
                    'message': 'Receiver deleted successfully'
                })

            elif operation == 'VALIDATE_SMTP':
                _, changed = validate_smtp(module, client)
                result.update({
                    'changed': changed,
                    'message': 'SMTP configuration validated successfully'
                })

            elif operation == 'INSPECT_ONE':
                receiver = inspect_receiver(module, client)
                result.update({
                    'changed': False,
                    'receiver': receiver,
                    'message': 'Successfully retrieved receiver details'
                })

            elif operation == 'INSPECT_ALL':
                receivers = enumerate_receivers(module, client)
                result.update({
                    'changed': False,
                    'receivers': receivers,
                    'message': f'Found {len(receivers)} receivers'
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