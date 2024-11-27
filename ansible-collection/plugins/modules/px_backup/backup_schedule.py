#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
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
            - 'CREATE'  create new backup Schedule
            - 'DELETE'  delete backup Schedule
            - 'UPDATE'  update backup Schedule
            - 'INSPECT_ALL' lists all backup Schedule
            - 'INSPECT_ONE' retrieves details of a specific backup Schedule
        choices: ['CREATE', 'DELETE', 'UPDATE','INSPECT_ALL','INSPECT_ONE']
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
        description: Unique identifier of the backup Schedule (required for update/delete)
        required: false
        type: str
    owner:
        description: Owner Name
        required: true
        type: str
    reclaim_policy:
        description: Reclaim policy of backup Schedule
        choices: ['Invalid', 'Delete', 'Retain']
        type: str
    namespaces:
        description: Namespaces which need to backup
        required: false
        type: dict
    label_selectors:
        description: Label Selector for backup
        required: false
        type: dict
    pre_exec_rule:
        description: Pre exec Rule name
        required: false
        type: str
    post_exec_rule:
        description: Post exec Rule name
        required: false
        type: str
    csi_snapshot_class_name:
        description: CSI Snapshot Class Name
        required: false
        type: str
    include_resources:
        description: Resources included for backup
        required: false
        type: dict
    resource_types:
        description: Type of Resources for backup
        required: false
        type: dict
    schedule_policy_ref:
        description: Schedule Policy Refs
        required: false
        type: dict
    backup_location_ref:
        description: Backup Location Ref
        required: false
        type: dict
    pre_exec_rule_ref:
        description: Pre Rule Ref
        required: false
        type: dict
    post_exec_rule_ref:
        description: Post Rule Ref
        required: false
        type: dict
    cluster_ref:
        description: Cluster Ref
        required: false
        type: dict
    backup_type:
        description: Type of Backup
        choices: ['Invalid', 'Generic', 'Normal'
        type: str
    ns_label_selectors:
        description: Namespace Label Selectors
        required: false
        type: str
    backup_object_type:
        description: Backup Object types
        choices: ['Invalid', 'All', 'VirtualMachine']
        type: dict
    volume_snapshot_class_mapping:
        description: Volume Snapshot Class Mapping
        required: false
        type: dict
    skip_vm_auto_exec_rules:
        description: Skip VM rules
        required: false
        type: bool
    direct_kdmp:
        description: KDMP enable
        required: false
        type: bool
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    labels:
        description: Labels to attach to the Backup Schedule
        required: false
        type: dict
    ownership:
        description: Ownership configuration for the Backup Schedule
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the Backup Schedule
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
    enumerate_options:
        description: Enumerate Options for the Backup Schedule
        required: false
        type: dict
        suboptions:
            max_objects:
                description: Max Object of the Backup Schedule
                type: str
            name_filter:
                description: Backup Schedule name Filter
                type: str
            cluster_name_filter:
                description: Cluster Name filter for the Backup Schedule
                type: str
            object_index:
                description: Object Index of the Backup Schedule
                type: str
            include_detailed_resources:
                description: Resources include for the Backup Schedule
                type: str
            cluster_uid_filter:
                description: Cluster Filter of the Backup Schedule
                type: str
            owners:
                description: Owner of the Backup Schedule
                type: str
            backup_object_type
                description: Backup type of the Backup Schedule
                choices: ['Invalid', 'Read', 'Write', 'Admin']
                type: str
            status
                description: Status of the Backup Schedule
                choices: ['Invalid', 'Read', 'Write', 'Admin']
                type: str
            time_range:
                description: Time Range fillter configurations
                type: list
                elements: dict
                suboptions:
                    start_time:
                        description: Start time of Backup Schedule
                        type: str
                    end_time:
                        description: End time of Backup Schedule
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
    """Update an existing backup schedule"""
    backup_schedule_request = backup_schedule_request_body(module)
    backup_schedule_request['metadata']['uid'] = module.params['uid']
    
    try:    
        response = client.make_request('PUT', 'v1/backupschedule', backup_schedule_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update Backup Schedule: {str(e)}")

def enumerate_backup_schedules(module, client):
    """List all backup schedule"""
    backup_location_ref = module.params.get('backup_location_ref', {})
    enumerate_options = module.params.get('enumerate_options', {})
    params ={}

    if backup_location_ref:
        params['backup_location_ref.name'] = backup_location_ref.get('name')
        params['backup_location_ref.uid'] = backup_location_ref.get('uid')

    if enumerate_options:
        time_range = enumerate_options.get("time_range", {})
        if time_range:
            params['enumerate_options.time_range.start_time']= time_range.get('start_time')
            params['enumerate_options.time_range.end_time']= time_range.get('end_time')

        params['enumerate_options.backup_object_type']= enumerate_options.get('backup_object_type')
        params['enumerate_options.max_objects']= enumerate_options.get('max_objects')
        params['enumerate_options.name_filter']= enumerate_options.get('name_filter')
        params['enumerate_options.cluster_name_filter']= enumerate_options.get('cluster_name_filter')
        params['enumerate_options.object_index']= enumerate_options.get('object_index')
        params['enumerate_options.include_detailed_resources']= enumerate_options.get('include_detailed_resources')
        params['enumerate_options.cluster_uid_filter']= enumerate_options.get('cluster_uid_filter')
        params['enumerate_options.owners']= enumerate_options.get('owners')
        params['enumerate_options.status']= enumerate_options.get('status')
        
    try:
        response = client.make_request('GET', f"v1/backupschedule/{module.params['org_id']}", params=params)

        return response['backup_schedules']
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate Backup Schedule: {str(e)}")

def inspect_backup_schedules(module, client):
    """Get details of a specific backup schedule"""
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
    """Delete a backup schedule"""
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
    """Build the backup schedule request object"""
    backup_schedule_request = {
        "metadata": {
            "name": module.params['name'],
            "org_id": module.params['org_id'],
            "owner": module.params['owner']
        },
        "reclaim_policy": module.params['reclaim_policy'],
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

    if module.params.get('operation') == "UPDATE":
        backup_schedule_request['cluster'] = module.params['cluster_ref'].get('name')
        backup_schedule_request['schedule_policy'] = module.params['schedule_policy_ref'].get('name')
        if module.params.get('pre_exec_rule_ref'):
            backup_schedule_request['pre_exec_rule_ref'] = module.params['pre_exec_rule_ref']
        if module.params.get('post_exec_rule_ref'):
            backup_schedule_request['post_exec_rule_ref'] = module.params['post_exec_rule_ref']
        

    if module.params.get('pre_exec_rule_ref') and module.params.get('pre_exec_rule'):
        backup_schedule_request['pre_exec_rule_ref'] = module.params['pre_exec_rule_ref']
        backup_schedule_request['pre_exec_rule'] = module.params['pre_exec_rule']

    
    if module.params.get('post_exec_rule_ref') and module.params.get('post_exec_rule'):
        backup_schedule_request['post_exec_rule_ref'] = module.params['post_exec_rule_ref']
        backup_schedule_request['post_exec_rule'] = module.params['post_exec_rule']
    
    if module.params.get('backup_object_type') == 'VirtualMachine' and module.params.get('skip_vm_auto_exec_rules'):
        backup_schedule_request['backup_object_type'] = module.params['backup_object_type']
        backup_schedule_request['skip_vm_auto_exec_rules'] = module.params['skip_vm_auto_exec_rules']

    if module.params.get('exclude_resource_types'):
        backup_schedule_request['exclude_resource_types'] = module.params['exclude_resource_types']
    
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
        operation=dict(type='str', choices=['CREATE', 'UPDATE', 'DELETE','INSPECT_ALL','INSPECT_ONE'], required=True),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        owner=dict(type='str', required=False),
        reclaim_policy=dict(type='str', choices=['Invalid', 'Delete', 'Retain']),
        pre_exec_rule=dict(type='str', required=False),
        post_exec_rule=dict(type='str', required=False),
        csi_snapshot_class_name=dict(type='str', required=False),
        backup_type=dict(type='str', choices=['Invalid', 'Generic', 'Normal']),
        ns_label_selectors=dict(type='str', required=False),
        skip_vm_auto_exec_rules=dict(type='bool', required=False),
        suspend=dict(type='bool', required=False, default=False),
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
                type=dict(type='str', choices=['Invalid', 'All', 'VirtualMachine']),
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
        exclude_resource_types=dict(type='list', elements='str', required=False),
        namespaces=dict(type='list', elements='str'),
        volume_snapshot_class_mapping=dict(type='dict', required=False),

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
        enumerate_options=dict(type='dict', required=False, options=dict(
            owners=dict(type='str'),
            max_objects=dict(type='str'),
            name_filter=dict(type='str'),
            cluster_name_filter=dict(type='str'),
            object_index=dict(type='str'),
            include_detailed_resources=dict(type='bool'),
            cluster_uid_filter=dict(type='str'),
            backup_object_type=dict(type='str',choices=['Invalid', 'All', 'VirtualMachine']),
            status=dict(type='str'),
            time_range=dict(type='dict', options=dict(
                start_time=dict(type='str'),
                end_time=dict(type='str')
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
            result['message'] = "Backup schedule created successfully"

        elif module.params['operation'] == 'UPDATE':
            # Update existing backup location
            backup_schedule, changed = update_backup_schedule(module, client)
            result['message'] = "Backup schedule updated successfully"

        elif module.params['operation'] == 'INSPECT_ALL':
            # Update existing backup location
            backup_schedules = enumerate_backup_schedules(module, client)
            message=f"Found {len(backup_schedules)} backup schedules"
            result['message'] = message
            result['backup_schedules']= backup_schedules

        elif module.params['operation'] == 'INSPECT_ONE':
            # Update existing backup location
            backup_schedule = inspect_backup_schedules(module, client)
            result['message'] = "Backup schedule Found successfully"
            result['backup_schedule']= backup_schedule

        elif module.params['operation'] == 'DELETE':
            # Update existing backup location
            backup_schedule, changed = delete_backup_schedules(module, client)
            result['message'] = "Backup schedule deleted successfully"




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