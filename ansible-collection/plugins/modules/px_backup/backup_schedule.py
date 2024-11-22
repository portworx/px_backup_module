#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.px_backup.api import PXBackupClient
import requests
import json

DOCUMENTATION = r'''
---
module: backup_schedule

short_description: Manage backup Schedule in PX-Backup

version_added: "2.8.1"

description: 
    - Manage backup Schedule in PX-Backup
    - Supports create, update, delete, and list operations
    - Requires cloud credentials

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
            - 'CREATE' will create the backup schedule
            - 'DELETE' will remove the backup schedule
            - 'UPDATE' will update the backup schedule
        choices: ['CREATE', 'DELETE', 'UPDATE']
        default: CREATE
        type: str
    name:
        description: Name of the backup schedule
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    owner:
        description: Owner Name
        required: true
        type: str
    schedule_policy:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    reclaim_policy:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    backup_location:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    cluster:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    namespaces:
        description: Labels to attach to the backup location
        required: false
        type: dict
    label_selectors:
        description: Labels to attach to the backup location
        required: false
        type: dict
    pre_exec_rule:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    post_exec_rule:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    csi_snapshot_class_name:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    include_resources:
        description: Labels to attach to the backup location
        required: false
        type: dict
    resource_types:
        description: Labels to attach to the backup location
        required: false
        type: dict
    schedule_policy_ref:
        description: Labels to attach to the backup location
        required: false
        type: dict
    backup_location_ref:
        description: Labels to attach to the backup location
        required: false
        type: dict
    pre_exec_rule_ref:
        description: Labels to attach to the backup location
        required: false
        type: dict
    post_exec_rule_ref:
        description: Labels to attach to the backup location
        required: false
        type: dict
    cluster_ref:
        description: Labels to attach to the backup location
        required: false
        type: dict
    backup_type:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    ns_label_selectors:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    backup_object_type:
        description: Labels to attach to the backup location
        required: false
        type: dict
    volume_snapshot_class_mapping:
        description: Labels to attach to the backup location
        required: false
        type: dict
    skip_vm_auto_exec_rules:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    direct_kdmp:
        description: Unique identifier of the backup location (required for update/delete)
        required: false
        type: str
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    labels:
        description: Labels to attach to the backup location
        required: false
        type: dict
    ownership:
        description: Ownership configuration for the backup location
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the backup location
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

def create_backup_schedule(module, client):
    """Create a new backup schedule"""
    backup_schedule_request = backup_schedule_request_body(module)
    
    try:
        response = client.make_request('POST', 'v1/backupschedule', backup_schedule_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to create Backup Schedule: {str(e)}")

def update_backup_schedule(module, client):
    """Update an existing backup location"""
    backup_schedule_request = backup_schedule_request_body(module)
    backup_schedule_request['metadata']['uid'] = module.params['uid']
    
    try:    
        response = client.make_request('PUT', 'v1/backupschedule', backup_schedule_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update Backup Schedule: {str(e)}")

def enumerate_backup_schedules(module, client):
    """List all backup locations"""
    params={}
    if module.params.get('backup_location_ref'):
        backup_location_ref = module.params['backup_location_ref']
        params['backup_location_ref.name'] = backup_location_ref.get('name')
        params['backup_location_ref.uid'] = backup_location_ref.get('uid')

    if module.params.get('enumerate_options'):
        enumerate_options = module.params['enumerate_options']
        params['enumerate_options.max_objects']= enumerate_options.get('enumerate_options.max_objects')
        params['enumerate_options.name_filter']= enumerate_options.get('enumerate_options.name_filter')
        params['enumerate_options.cluster_name_filter']= enumerate_options.get('enumerate_options.cluster_name_filter')
        params['enumerate_options.object_index']= enumerate_options.get('enumerate_options.object_index')
        params['enumerate_options.include_detailed_resources']= enumerate_options.get('enumerate_options.include_detailed_resources')
        params['enumerate_options.cluster_uid_filter']= enumerate_options.get('enumerate_options.cluster_uid_filter')
        params['enumerate_options.owners']= enumerate_options.get('enumerate_options.owners')
        params['enumerate_options.backup_object_type']= enumerate_options.get('enumerate_options.backup_object_type')
        params['enumerate_options.status']= enumerate_options.get('enumerate_options.status')
        params['enumerate_options.time_range.start_time']= enumerate_options.get('enumerate_options.time_range.start_time')
        params['enumerate_options.time_range.end_time']= enumerate_options.get('enumerate_options.time_range.end_time')
    try:
        response = client.make_request('GET', f"v1/backupschedule/{module.params['org_id']}", params=params)
        # backup_schedules= response.get('backup_schedules')
        return response['backup_schedules']
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate Backup Schedule: {str(e)}")

def inspect_backup_schedules(module, client):
    """Get details of a specific backup location"""
    params = {
        'uid': module.params.get('uid')
    }
    try:
        response = client.make_request(
            'GET',
            f"v1/backupschedule/{module.params['org_id']}/{module.params['name']}",
            params=params
        )
        return response['backup_schedule']
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect Backup Schedule: {str(e)}")

def delete_backup_schedules(module, client):
    """Delete a backup location"""
    params = {
        'uid': module.params.get('uid')
    }
    try:
        response = client.make_request(
            'DELETE',
            f"v1/backupschedule/{module.params['org_id']}/{module.params['name']}"
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete Backup Schedule: {str(e)}")

def backup_schedule_request_body(module):
    """Build the Cloud Credential request object"""
    backup_schedule_request = {
        "metadata": {
            "name": module.params['name'],
            "org_id": module.params['org_id'],
            "owner": module.params['owner']
        },
        "schedule_policy": module.params['schedule_policy'],
        "reclaim_policy": module.params['reclaim_policy'],
        "backup_location": module.params['backup_location'],
        "cluster": module.params['cluster'],
        "namespaces":module.params['namespaces'],
        "include_resources": module.params['include_resources'], 
        "csi_snapshot_class_name": module.params['csi_snapshot_class_name'],
        "resource_types": module.params['resource_types'],
        "schedule_policy_ref": module.params['schedule_policy_ref'],
        "backup_location_ref": module.params['backup_location_ref'],
        "backup_type": module.params['backup_type'],
        "ns_label_selectors": module.params['ns_label_selectors'],
        "cluster_ref": module.params['cluster_ref'],
        "backup_object_type": module.params['backup_object_type'],
        "direct_kdmp": module.params['direct_kdmp'],

    }
    if module.params.get('pre_exec_rule_ref') and module.params.get('pre_exec_rule'):
        backup_schedule_request['pre_exec_rule_ref'] = module.params['pre_exec_rule_ref']
        backup_schedule_request['pre_exec_rule'] = module.params['pre_exec_rule']

    
    if module.params.get('post_exec_rule_ref') and module.params.get('post_exec_rule'):
        backup_schedule_request['post_exec_rule_ref'] = module.params['post_exec_rule_ref']
        backup_schedule_request['post_exec_rule'] = module.params['post_exec_rule']
    
    if module.params.get('backup_object_type') == 'VirtualMachine' and module.params.get('skip_vm_auto_exec_rules'):
        backup_schedule_request['backup_object_type'] = module.params['backup_object_type']
        backup_schedule_request['skip_vm_auto_exec_rules'] = module.params['skip_vm_auto_exec_rules']

    if module.params.get('suspend'):
        backup_schedule_request['suspend'] = module.params['suspend']

    if module.params.get('label_selectors'):
        backup_schedule_request['label_selectors'] = module.params['label_selectors']
        
    if module.params.get('volume_snapshot_class_mapping'):
        backup_schedule_request['volume_snapshot_class_mapping'] = module.params['volume_snapshot_class_mapping']

    return backup_schedule_request

def run_module():
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(type='str', choices=['CREATE', 'UPDATE', 'DELETE','INSPECT_ALL','INSPECT_ONE'], default='CREATE'),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        owner=dict(type='str', required=False),
        schedule_policy=dict(type='str', required=False),
        reclaim_policy=dict(type='str', required=False),
        backup_location=dict(type='str', required=False),
        cluster=dict(type='str', required=False),
        pre_exec_rule=dict(type='str', required=False),
        post_exec_rule=dict(type='str', required=False),
        csi_snapshot_class_name=dict(type='str', required=False),
        backup_type=dict(type='str', required=False),
        ns_label_selectors=dict(type='str', required=False),
        skip_vm_auto_exec_rules=dict(type='bool', required=False),
        suspend=dict(type='str', required=False),
        direct_kdmp=dict(type='bool', required=False),
        include_resources=dict(type='list', elements='dict', options=dict(
                name=dict(type='str'),
                namespace=dict(type='str'),
                group=dict(type='str'),
                kind=dict(type='str'),
                version=dict(type='str'),

            )),
        backup_object_type=dict(
            type='dict',
            options=dict(
                type=dict(type='str', required=False),
            ),
        ),
        cluster_ref=dict(
            type='dict',
            options=dict(
                name=dict(type='str', required=False),
                uid=dict(type='str', required=False),
            ),
        ),
        post_exec_rule_ref=dict(
            type='dict',
            options=dict(
                name=dict(type='str', required=False),
                uid=dict(type='str', required=False),
            ),
        ),
        pre_exec_rule_ref=dict(
            type='dict',
            options=dict(
                name=dict(type='str', required=False),
                uid=dict(type='str', required=False),
            ),
        ),
        backup_location_ref=dict(
            type='dict',
            options=dict(
                name=dict(type='str', required=False),
                uid=dict(type='str', required=False),
            ),
        ),
        schedule_policy_ref=dict(
            type='dict',
            options=dict(
                name=dict(type='str', required=False),
                uid=dict(type='str', required=False),
            ),
        ),
        resource_types=dict(type='list', elements='str', required=False),
        namespaces=dict(type='list', elements='str'),
        volume_snapshot_class_mapping=dict(type='dict', required=False, default={}),

        validate_certs=dict(type='bool', default=True),
        label_selectors=dict(type='dict', required=False),
        labels=dict(type='dict', required=False),
        ownership=dict(type='dict', required=False, options=dict(
            owner=dict(type='str'),
            groups=dict(type='list', elements='dict', options=dict(
                id=dict(type='str'),
                access=dict(type='str', choices=['Invalid', 'Read', 'Write', 'Admin'])
            )),
            collaborators=dict(type='list', elements='dict', options=dict(
                id=dict(type='str'),
                access=dict(type='str', choices=['Invalid', 'Read', 'Write', 'Admin'])
            )),
            public=dict(type='dict', options=dict(
                type=dict(type='str', choices=['Invalid', 'Read', 'Write', 'Admin'])
            ))
        )),
    )

    result = dict(
        changed=False,
        backup_schedule={},
        backup_schedules=[],
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        # required_if=[
        #     ('credential_type', 'AWS', ['aws_config'])
        # ],

    )

    if module.check_mode:
        module.exit_json(**result)

    client = PXBackupClient(
        module.params['api_url'],
        module.params['token'],
        module.params['validate_certs']
    )

    try:

        # Handle other states
        if module.params['operation'] == 'CREATE':
            backup_schedule, changed = create_backup_schedule(module, client)
            result['message'] = "Backup location created successfully"

        elif module.params['operation'] == 'UPDATE':
            # Update existing backup location
            backup_schedule, changed = update_backup_schedule(module, client)
            result['message'] = "Backup location updated successfully"

        elif module.params['operation'] == 'INSPECT_ALL':
            # Update existing backup location
            backup_schedules = enumerate_backup_schedules(module, client)
            message=f"Found {len(backup_schedules)} backup locations"
            result['message'] = message
            result['backup_schedules']= backup_schedules

        elif module.params['operation'] == 'INSPECT_ONE':
            # Update existing backup location
            backup_schedule = inspect_backup_schedules(module, client)
            result['message'] = "Backup location updated successfully"
            result['backup_schedule']= backup_schedule

        elif module.params['operation'] == 'DELETE':
            # Update existing backup location
            backup_schedule, changed = delete_backup_schedules(module, client)
            result['message'] = "Backup location updated successfully"




    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"Unexpected error: {error_detail}"
            except ValueError:
                error_msg = f"Unexpected error: {e.response.text}"
        else:
        # Generic error message for non-RequestException errors
            error_msg = f"An unexpected error occurred: {error_msg}"
        
        module.fail_json(msg=error_msg)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()