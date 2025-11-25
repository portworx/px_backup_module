# !/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Schedule Policy Management Module

This Ansible module manages schedule policies in PX-Backup, providing operations for:
- Creating policies
- Updating existing policies
- Deleting policies
- Inspecting policies (single or all)
- Managing policy ownership
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from typing import Dict, Any, Tuple, Optional, List, Union  # Fixed imports
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
import requests

DOCUMENTATION = r'''
---
module: schedule_policy

short_description: Manage schedule policy in PX-Backup

version_added: "2.9.0"

description: 
    - Manage schedule policy in PX-Backup
    - Supports create, update, update_ownership, delete, and list operations

options:
    api_url:
        description: PX-Backup API URL
        required: true
        type: str
    token:
        description: Authentication token
        required: true
        type: str
    operation:
        description: 
            - Operation to be perform
            - "- CREATE:  create new schedule policy"
            - "- DELETE:  delete schedule policy"
            - "- UPDATE:  update schedule policy"
            - "- UPDATE_OWNERSHIP: updates ownership settings of a schedule policy"
            - "- INSPECT_ALL: lists all schedule policies"
            - "- INSPECT_ONE: retrieves details of a specific schedule policy"
        choices: ['CREATE', 'DELETE', 'UPDATE', 'UPDATE_OWNERSHIP','INSPECT_ALL','INSPECT_ONE']
        default: CREATE
        type: str
    name:
        description: Name of the schedule policy
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    owner:
        description: Owner name
        required: false
        type: str
    uid:
        description: Unique identifier of the schedule policy
        required: false
        type: str
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
    labels:
        description: Labels to attach to the schedule policy
        required: false
        type: dict
    schedule_policy:
        description: Configuration for schedule policies, defining intervals, retention, and scheduling details.
        required: false
        type: dict
        suboptions:
            interval:
                description: Interval-based scheduling configuration.
                type: dict
                suboptions:
                    minutes:
                        description: The interval in minutes for the schedule.
                        type: str
                    retain:
                        description: The number of schedules to retain.
                        type: str
                    incremental_count:
                        description: Configuration for incremental schedule count.
                        type: dict
                        suboptions:
                            count:
                                description: Number of incremental schedules to retain.
                                type: str
            daily:
                description: Daily scheduling configuration.
                type: dict
                suboptions:
                    time:
                        description: The time of day for the daily schedule (e.g., "HH:MM").
                        type: str
                    retain:
                        description: The number of daily schedules to retain.
                        type: str
                    incremental_count:
                        description: Configuration for incremental schedule count.
                        type: dict
                        suboptions:
                            count:
                                description: Number of incremental schedules to retain.
                                type: str
            weekly:
                description: Weekly scheduling configuration.
                type: dict
                suboptions:
                    day:
                        description: The day of the week for the schedule (e.g., "Monday").
                        type: str
                    time:
                        description: The time of day for the weekly schedule (e.g., "HH:MM").
                        type: str
                    retain:
                        description: The number of weekly schedules to retain.
                        type: str
                    incremental_count:
                        description: Configuration for incremental schedule count.
                        type: dict
                        suboptions:
                            count:
                                description: Number of incremental schedules to retain.
                                type: str
            monthly:
                description: Monthly scheduling configuration.
                type: dict
                suboptions:
                    date:
                        description: The date of the month for the schedule (e.g., "1" for the 1st day).
                        type: str
                    time:
                        description: The time of day for the monthly schedule (e.g., "HH:MM").
                        type: str
                    retain:
                        description: The number of monthly schedules to retain.
                        type: str
                    incremental_count:
                        description: Configuration for incremental schedule count.
                        type: dict
                        suboptions:
                            count:
                                description: Number of incremental schedules to retain.
                                type: str
            backup_schedule:
                description: A list of backup schedules as strings.
                type: list
                elements: str
            for_object_lock:
                description: Indicates whether the schedule is for object-locked backup
                type: bool
            auto_delete:
                description: Specifies whether the schedule should be auto-deleted when no longer needed.
                type: bool
    ownership:
        description: Ownership configuration for the schedule policy
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the schedule policy
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
'''

def create_schedule_policy(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new Schedule Policy"""
    try:
        params = dict(module.params)
        schedule_policy_request = schedule_policy_request_body(module)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/schedulepolicy',
            data=schedule_policy_request
        )
        
        # Return the schedule_policy from the response
        if isinstance(response, dict) and 'schedule_policy' in response:
            return response['schedule_policy'], True
            
        # If we get an unexpected response format, raise an error
        raise ValueError(f"Unexpected API response format: {response}")
        
    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to create schedule policy: {error_msg}")

def update_schedule_policy(module: AnsibleModule, client: PXBackupClient) -> tuple[Dict[str, Any], bool]:  # Using tuple instead of Tuple
    """Update an existing Schedule Policy"""
    try:    
        schedule_policy_request = schedule_policy_request_body(module)
        schedule_policy_request['metadata']['uid'] = module.params.get('uid', '')
        
        response = client.make_request('PUT', 'v1/schedulepolicy', schedule_policy_request)
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update Schedule Policy: {str(e)}")

def update_ownership(module, client):
    """Update ownership of a Schedule Policy"""
    ownership_request = {
        "org_id": module.params['org_id'],
        "name": module.params['name'],
        "ownership": module.params['ownership'],
        "uid": module.params.get('uid', '')
    }
    try:
        response = client.make_request('PUT', 'v1/schedulepolicy/updateownership', ownership_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update Schedule Policy ownership: {str(e)}")

def enumerate_schedule_policies(module, client):
    """List all Schedule Policies"""
    params = {
        'include_secrets': module.params.get('include_secrets', False)
    }
    try:
        response = client.make_request('GET', f"v1/schedulepolicy/{module.params['org_id']}", params=params)
        return response.get('schedule_policies', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate Schedule Policy: {str(e)}")

def inspect_schedule_policies(module, client):
    """Get details of a specific Schedule Policy"""
    params = {
        'include_secrets': module.params.get('include_secrets', False)
    }
    try:
        response = client.make_request(
            'GET',
            f"v1/schedulepolicy/{module.params['org_id']}/{module.params['name']}",
            params=params
        )
        return response['schedule_policy']
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect Schedule Policy: {str(e)}")

def delete_schedule_policies(module, client):
    """Delete a Schedule Policy"""
    try:
        response = client.make_request(
            'DELETE',
            f"v1/schedulepolicy/{module.params['org_id']}/{module.params['name']}"
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete Schedule Policy: {str(e)}")

def schedule_policy_request_body(module):
    """Build the Schedule Policy request object"""
    schedule_policy_request = {
        "metadata": {
            "name": module.params['name'],
            "org_id": module.params['org_id'],
            "owner": module.params['owner']
        },
        "schedule_policy": module.params['schedule_policy']
    }

    if module.params.get('labels'):
        schedule_policy_request['metadata']['labels'] = module.params['labels']
        
    if module.params.get('ownership'):
        schedule_policy_request['metadata']['ownership'] = module.params['ownership']

    if module.params.get('auto_delete'):
        schedule_policy_request['auto_delete'] = module.params['auto_delete']

    if module.params.get('for_object_lock'):
        schedule_policy_request['for_object_lock'] = module.params['for_object_lock']

    if module.params.get('backup_schedule'):
        schedule_policy_request['backup_schedule'] = module.params['backup_schedule']

    return schedule_policy_request

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

def run_module():
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(type='str', choices=['CREATE', 'UPDATE', 'DELETE','INSPECT_ALL','UPDATE_OWNERSHIP','INSPECT_ONE'], default='CREATE'),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        owner=dict(type='str', required=False),
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
        
        include_secrets=dict(type='bool', default=False),
        labels=dict(type='dict', required=False),
        schedule_policy=dict(
            type='dict',
            required=False,
            options=dict(
                interval=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        minutes=dict(type='int', required=False),
                        retain=dict(type='int', required=False),
                        incremental_count=dict(
                            type='dict',
                            required=False,
                            options=dict(
                                count=dict(type='int', required=False)
                            )
                        )
                    )
                ),
                daily=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        time=dict(type='str', required=False),
                        retain=dict(type='int', required=False),   
                        incremental_count=dict(
                            type='dict',
                            required=False,
                            options=dict(
                                count=dict(type='int', required=False)  
                            )
                        )
                    )
                ),
                weekly=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        day=dict(type='str', required=False),
                        time=dict(type='str', required=False),
                        retain=dict(type='int', required=False),   
                        incremental_count=dict(
                            type='dict',
                            required=False,
                            options=dict(
                                count=dict(type='int', required=False)  
                            )
                        )
                    )
                ),
                monthly=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        date=dict(type='int', required=False),     
                        time=dict(type='str', required=False),
                        retain=dict(type='int', required=False),   
                        incremental_count=dict(
                            type='dict',
                            required=False,
                            options=dict(
                                count=dict(type='int', required=False)  
                            )
                        )
                    )
                ),
                backup_schedule=dict(
                    type='list',
                    required=False,
                    elements='str'
                ),
                for_object_lock=dict(type='bool', required=False, default=False),
                auto_delete=dict(type='bool', required=False, default=False)
            )
        ),
         # metadata-related arguments
        ownership = dict(
            type='dict',
            required=False,
            options=dict(
                owner=dict(type='str'),
                groups=dict(
                    type='list',
                    required=False,
                    elements='dict',
                    options=dict(
                        id=dict(type='str', required=True),
                        access=dict(
                            type='str',
                            choices=['Read', 'Write', 'Admin'],
                            required=True
                        )
                    )
                ),
                collaborators=dict(
                    type='list',
                    required=False,
                    elements='dict',
                    options=dict(
                        id=dict(type='str', required=True),
                        access=dict(
                            type='str',
                            choices=['Read', 'Write', 'Admin'],
                            required=True
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
        )
    )

    result = dict(
        changed=False,
        schedule_policy={},
        schedule_policies=[],
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('operation', 'CREATE', ['name', 'schedule_policy']),
            ('operation', 'UPDATE', ['name','schedule_policy']),
            ('operation', 'DELETE', ['name']),
            ('operation', 'INSPECT_ONE', ['name']),
            ('operation', 'UPDATE_OWNERSHIP', ['name', 'ownership'])
        ]
    )

    try:
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

        client = PXBackupClient(
            api_url=module.params['api_url'],
            token=module.params['token'],
            validate_certs=ssl_config.get('validate_certs', True),
            ca_cert=ssl_config.get('ca_cert'),
            client_cert=ssl_config.get('client_cert'),
            client_key=ssl_config.get('client_key')
        )

        changed = False
        operation = module.params['operation']

        if operation == 'CREATE':
            schedule_policy, changed = create_schedule_policy(module, client)
            result['schedule_policy'] = schedule_policy
            result['message'] = "Schedule Policy created successfully"
            
        elif operation == 'UPDATE':
            schedule_policy, changed = update_schedule_policy(module, client)
            result['schedule_policy'] = schedule_policy
            result['message'] = "Schedule Policy updated successfully"
            
        elif operation == 'UPDATE_OWNERSHIP':
            schedule_policy, changed = update_ownership(module, client)
            result['schedule_policy'] = schedule_policy
            result['message'] = "Schedule Policy Ownership updated successfully"
            
        elif operation == 'INSPECT_ALL':
            schedule_policies = enumerate_schedule_policies(module, client)
            result['schedule_policies'] = schedule_policies
            result['message'] = f"Found {len(schedule_policies)} Schedule Policies"
            
        elif operation == 'INSPECT_ONE':
            schedule_policy = inspect_schedule_policies(module, client)
            result['schedule_policy'] = schedule_policy
            result['message'] = "Schedule Policy found successfully"
            
        elif operation == 'DELETE':
            schedule_policy, changed = delete_schedule_policies(module, client)
            result['message'] = "Schedule Policy deleted successfully"

        result['changed'] = changed

    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        
        module.fail_json(msg=error_msg)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()