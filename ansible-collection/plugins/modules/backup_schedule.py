#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
import requests


DOCUMENTATION = r'''
---
module: backup_schedule

short_description: Manage backup Schedule in PX-Backup

version_added: "2.9.0"

description: 
    - Manage backup Schedule in PX-Backup
    - Supports create, update, delete, and list operations
    - Supports enhanced filtering and sorting in 2.9.0+
    - Provides VM-specific backup capabilities
    - Updated for API version 2.9.0+ with cluster scope support

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
            - "- CREATE:  create new backup Schedule"
            - "- DELETE:  delete backup Schedule"
            - "- UPDATE:  update backup Schedule"
            - "- INSPECT_ALL: lists all backup Schedule"
            - "- INSPECT_ALL_POST_REQUEST: lists all backup Schedule using POST request"
            - "- INSPECT_ONE: retrieves details of a specific backup Schedule"
        choices: ['CREATE', 'DELETE', 'UPDATE','INSPECT_ALL','INSPECT_ALL_POST_REQUEST','INSPECT_ONE']
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
        required: false
        type: str
    reclaim_policy:
        description: Reclaim policy of backup Schedule
        choices: ['Invalid', 'Delete', 'Retain']
        type: str
    namespaces:
        description: Namespaces which need to backup
        required: false
        type: list
        elements: str
    label_selectors:
        description: Label Selector for backup
        required: false
        type: dict
    pre_exec_rule:
        description: Pre exec Rule name (deprecated - use pre_exec_rule_ref instead)
        required: false
        type: str
    post_exec_rule:
        description: Post exec Rule name (deprecated - use post_exec_rule_ref instead)
        required: false
        type: str
    csi_snapshot_class_name:
        description: CSI Snapshot Class Name (deprecated)
        required: false
        type: str
    include_resources:
        description: Resources included for backup
        required: false
        type: list
        elements: dict
        suboptions:
            name:
                description: Resource name
                type: str
            namespace:
                description: Resource namespace
                type: str
            group:
                description: Resource group
                type: str
            kind:
                description: Resource kind
                type: str
            version:
                description: Resource version
                type: str
    resource_types:
        description: Type of Resources for backup
        required: false
        type: list
        elements: str
    schedule_policy_ref:
        description: Schedule Policy Refs
        required: false
        type: dict
        suboptions:
            name:
                description: Policy name
                type: str
            uid:
                description: Policy UID
                type: str
    backup_location_ref:
        description: Backup Location Ref
        required: false
        type: dict
        suboptions:
            name:
                description: Backup location name
                type: str
            uid:
                description: Backup location UID
                type: str
    pre_exec_rule_ref:
        description: Pre Rule Ref
        required: false
        type: dict
        suboptions:
            name:
                description: Pre exec rule name
                type: str
            uid:
                description: Pre exec rule UID
                type: str
    post_exec_rule_ref:
        description: Post Rule Ref
        required: false
        type: dict
        suboptions:
            name:
                description: Post exec rule name
                type: str
            uid:
                description: Post exec rule UID
                type: str
    cluster_ref:
        description: Cluster Ref
        required: false
        type: dict
        suboptions:
            name:
                description: Cluster name
                type: str
            uid:
                description: Cluster UID
                type: str
    backup_type:
        description: Type of Backup
        choices: ['Invalid', 'Generic', 'Normal']
        type: str
    ns_label_selectors:
        description: Namespace Label Selectors
        required: false
        type: str
    backup_object_type:
        description: Backup Object types
        type: dict
        suboptions:
            type:
                description: Type of backup object
                choices: ['Invalid', 'NS', 'VM', 'All']
                type: str
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
    suspend:
        description: Suspend the backup schedule
        required: false
        type: bool
        default: false
    enumerate_options:
        description: Enumerate Options for the Backup Schedule
        required: false
        type: dict
        suboptions:
            labels:
                description: Label selectors for filtering
                type: dict
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
                type: bool
            cluster_uid_filter:
                description: Cluster Filter of the Backup Schedule
                type: str
            owners:
                description: Owner of the Backup Schedule
                type: list
                elements: str
            backup_object_type:
                description: filter to use Backup Object Type on object
                type: str
            status:
                description: filter to use policy name and uid. Any object that contains the filter will be returned.
                type: list
                elements: str
            time_range:
                description: Time Range filter configurations
                type: dict
                suboptions:
                    start_time:
                        description: Start time of Backup Schedule
                        type: str
                    end_time:
                        description: End time of Backup Schedule
                        type: str
            schedule_policy_ref:
                description: Filter by schedule policy references
                type: list
                elements: dict
                suboptions:
                    name:
                        description: Policy name
                        type: str
                    uid:
                        description: Policy UID
                        type: str
            backup_schedule_ref:
                description: Filter by backup schedule references
                type: list
                elements: dict
                suboptions:
                    name:
                        description: Backup schedule name
                        type: str
                    uid:
                        description: Backup schedule UID
                        type: str
            sort_option:
                description: Sorting options for results
                type: dict
                suboptions:
                    sortBy:
                        description: Field to sort by
                        type: dict
                        suboptions:
                            type:
                                description: Sort field type
                                choices: ['Invalid', 'CreationTimestamp', 'Name', 'ClusterName', 'Size', 'RestoreBackupName']
                                type: str
                    sortOrder:
                        description: Sort order
                        type: dict
                        suboptions:
                            type:
                                description: Sort order type
                                choices: ['Invalid', 'Ascending', 'Descending']
                                type: str
    exclude_resource_types:
        description: List of resources to exclude during backup
        type: list
        elements: str
        required: false
    parallel_backup:
        description: option to enable parallel schedule backups
        required: false
        type: bool
    keep_cr_status:
        description: option to enable to keep the CR status of the resources in the backup schedule
        required: false
        type: bool
    advanced_resource_label_selector:
        description: Advanced label selector for resources (string format with operator support)
        required: false
        type: str
    # New in 2.9.0
    volume_resource_only_policy_ref:
        description: reference to Volume Resource Only policy ref
        required: false
        type: dict
        version_added: '2.9.0'
        suboptions:
            name:
                description: Volume Resource Only policy name
                type: str
            uid:
                description: Volume Resource Only policy UID
                type: str
    policy_ref:
        description: List of schedule policy references to filter by
        type: list
        elements: dict
        required: false
        version_added: '2.9.0'
        suboptions:
            name:
                description: Policy name
                type: str
                required: true
            uid:
                description: Policy UID
                type: str
                required: true
    include_objects:
        description: List of exact backup schedules to include (name + UID required)
        type: list
        elements: dict
        required: false
        version_added: '2.9.0'
        suboptions:
            name:
                description: Schedule name
                type: str
                required: true
            uid:
                description: Schedule UID
                type: str
                required: true
    exclude_objects:
        description: List of exact backup schedules to exclude (name + UID required)
        type: list
        elements: dict
        required: false
        version_added: '2.9.0'
        suboptions:
            name:
                description: Schedule name
                type: str
                required: true
            uid:
                description: Schedule UID
                type: str
                required: true
    include_filter:
        description: Substring or regex pattern to match backup schedules to include (e.g. "*" for All, "pxb-" or any valid regex)
        type: str
        required: false
        version_added: '2.9.0'
    exclude_filter:
        description: Substring or regex pattern to match backup schedules to exclude (e.g. "*" for All, "pxb-" or any valid regex)
        type: str
        required: false
        version_added: '2.9.0'
    cluster_scope:
        description: Cluster scope configuration for operations (new in 2.9.0)
        type: dict
        required: false
        version_added: '2.9.0'
        suboptions:
            cluster_refs:
                description: List of cluster references
                type: list
                elements: dict
                suboptions:
                    name:
                        description: Name of the cluster
                        type: str
                    uid:
                        description: Cluster UID
                        type: str
            all_clusters:
                description: Boolean flag to apply the operation to all clusters
                type: bool

requirements:
    - python >= 3.9
    - requests

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

def enumerate_backup_schedules(module, client, operation):
    """List all backup schedules with support for both GET and POST methods"""
    backup_location_ref = module.params.get('backup_location_ref', {})
    cluster_ref = module.params.get('cluster_ref', {}) 
    enumerate_options = module.params.get('enumerate_options', {})
    
    if operation == 'INSPECT_ALL_POST_REQUEST':
        try:
            # Build the request body for POST
            request_body = {}
            
            # Add enumerate_options if provided
            if enumerate_options:
                request_body["enumerate_options"] = {}
                
                # Add all enumerate options fields
                if enumerate_options.get('labels'):
                    request_body["enumerate_options"]["labels"] = enumerate_options.get('labels')
                if enumerate_options.get('max_objects'):
                    request_body["enumerate_options"]["max_objects"] = enumerate_options.get('max_objects')
                if enumerate_options.get('name_filter'):
                    request_body["enumerate_options"]["name_filter"] = enumerate_options.get('name_filter')
                if enumerate_options.get('cluster_name_filter'):
                    request_body["enumerate_options"]["cluster_name_filter"] = enumerate_options.get('cluster_name_filter')
                if enumerate_options.get('cluster_uid_filter'):
                    request_body["enumerate_options"]["cluster_uid_filter"] = enumerate_options.get('cluster_uid_filter')
                if enumerate_options.get('include_detailed_resources') is not None:
                    request_body["enumerate_options"]["include_detailed_resources"] = enumerate_options.get('include_detailed_resources')
                if enumerate_options.get('backup_object_type'):
                    request_body["enumerate_options"]["backup_object_type"] = enumerate_options.get('backup_object_type')
                if enumerate_options.get('owners'):
                    request_body["enumerate_options"]["owners"] = enumerate_options.get('owners')
                if enumerate_options.get('status'):
                    request_body["enumerate_options"]["status"] = enumerate_options.get('status')
                if enumerate_options.get('time_range'):
                    request_body["enumerate_options"]["time_range"] = enumerate_options.get('time_range')
                if enumerate_options.get('schedule_policy_ref'):
                    request_body["enumerate_options"]["schedule_policy_ref"] = enumerate_options.get('schedule_policy_ref')
                if enumerate_options.get('backup_schedule_ref'):
                    request_body["enumerate_options"]["backup_schedule_ref"] = enumerate_options.get('backup_schedule_ref')
                if enumerate_options.get('sort_option'):
                    request_body["enumerate_options"]["sort_option"] = enumerate_options.get('sort_option')
                if enumerate_options.get('object_index'):
                    request_body["enumerate_options"]["object_index"] = enumerate_options.get('object_index')
            
            # Add references if provided
            if backup_location_ref:
                request_body["backup_location_ref"] = backup_location_ref
            
            if cluster_ref:
                request_body["cluster_ref"] = cluster_ref
            
            # Add 2.9.0 fields if provided
            if module.params.get('volume_resource_only_policy_ref'):
                params['volume_resource_only_policy_ref.name'] = module.params.get('volume_resource_only_policy_ref').get('name')
                params['volume_resource_only_policy_ref.uid'] = module.params.get('volume_resource_only_policy_ref').get('uid')
                
            if module.params.get('policy_ref'):
                request_body["policy_ref"] = module.params.get('policy_ref')
                
            if module.params.get('include_objects'):
                request_body["include_objects"] = module.params.get('include_objects')
                
            if module.params.get('exclude_objects'):
                request_body["exclude_objects"] = module.params.get('exclude_objects')
                
            if module.params.get('include_filter'):
                request_body["include_filter"] = module.params.get('include_filter')
                
            if module.params.get('exclude_filter'):
                request_body["exclude_filter"] = module.params.get('exclude_filter')
            
            # Make POST request
            response = client.make_request(
                'POST',
                f"v1/backupschedule/{module.params['org_id']}/enumerate",
                data=request_body
            )
            
            return response.get('backup_schedules', [])
            
        except Exception as e:
            handle_request_exception(e, module, "enumerate backup schedules")
    else:
        # Use GET with query parameters for simpler queries
        params = {}

        if backup_location_ref:
            params['backup_location_ref.name'] = backup_location_ref.get('name')
            params['backup_location_ref.uid'] = backup_location_ref.get('uid')

        if cluster_ref:
            params['cluster_ref.name'] = cluster_ref.get('name')
            params['cluster_ref.uid'] = cluster_ref.get('uid')

        if module.params.get('volume_resource_only_policy_ref'):
            params['volume_resource_only_policy_ref.name'] = module.params.get('volume_resource_only_policy_ref').get('name')
            params['volume_resource_only_policy_ref.uid'] = module.params.get('volume_resource_only_policy_ref').get('uid')

        if enumerate_options:
            # Handle time_range
            time_range = enumerate_options.get("time_range", {})
            if time_range:
                params['enumerate_options.time_range.start_time'] = time_range.get('start_time')
                params['enumerate_options.time_range.end_time'] = time_range.get('end_time')

            # Handle other enumerate options
            if enumerate_options.get('backup_object_type'):
                params['enumerate_options.backup_object_type'] = enumerate_options.get('backup_object_type')
            if enumerate_options.get('max_objects'):
                params['enumerate_options.max_objects'] = enumerate_options.get('max_objects')
            if enumerate_options.get('name_filter'):
                params['enumerate_options.name_filter'] = enumerate_options.get('name_filter')
            if enumerate_options.get('cluster_name_filter'):
                params['enumerate_options.cluster_name_filter'] = enumerate_options.get('cluster_name_filter')
            if enumerate_options.get('object_index'):
                params['enumerate_options.object_index'] = enumerate_options.get('object_index')
            if enumerate_options.get('include_detailed_resources') is not None:
                params['enumerate_options.include_detailed_resources'] = enumerate_options.get('include_detailed_resources')
            if enumerate_options.get('cluster_uid_filter'):
                params['enumerate_options.cluster_uid_filter'] = enumerate_options.get('cluster_uid_filter')
            if enumerate_options.get('owners'):
                params['enumerate_options.owners'] = enumerate_options.get('owners')
            if enumerate_options.get('status'):
                params['enumerate_options.status'] = enumerate_options.get('status')
            
        try:
            response = client.make_request('GET', f"v1/backupschedule/{module.params['org_id']}", params=params)
            return response.get('backup_schedules', [])
        except Exception as e:
            handle_request_exception(e, module, "enumerate backup schedules")

def handle_request_exception(e, module, operation):
    """Handle exceptions from API requests with consistent error formatting"""
    error_msg = str(e)
    if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
        try:
            error_detail = e.response.json()
            error_msg = f"{error_msg}: {error_detail}"
        except ValueError:
            error_msg = f"{error_msg}: {e.response.text}"
    module.fail_json(msg=f"Failed to {operation}: {error_msg}")

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
    """Delete a backup schedule with support for 2.9.0 features"""
    # For simple delete operations - now uses the updated endpoint
    if not (module.params.get('policy_ref') or module.params.get('include_objects') or 
            module.params.get('exclude_objects') or module.params.get('include_filter') or 
            module.params.get('exclude_filter') or module.params.get('cluster_scope')):
        params = {
            'uid': module.params.get('uid')
        }
        try:
            response = client.make_request(
                'DELETE',
                f"v1/backupschedule/{module.params['org_id']}/{module.params['name']}",
                params=params
            )
            return response, True
        except Exception as e:
            handle_request_exception(e, module, "delete backup schedule")
    
    # For complex delete operations, use POST endpoint
    else:
        try:
            delete_request = {
                "org_id": module.params['org_id'],
                "name": module.params.get('name'),
                "uid": module.params.get('uid')
            }
            
            # Add deprecated delete_backups field if provided
            if module.params.get('delete_backups') is not None:
                delete_request["delete_backups"] = module.params['delete_backups']
            
            # Add 2.9.0 fields if provided
            if module.params.get('backup_object_type'):
                delete_request["backup_object_type"] = module.params['backup_object_type']
                
            if module.params.get('policy_ref'):
                delete_request["policy_ref"] = module.params['policy_ref']
                
            if module.params.get('include_objects'):
                delete_request["include_objects"] = module.params['include_objects']
                
            if module.params.get('exclude_objects'):
                delete_request["exclude_objects"] = module.params['exclude_objects']
                
            if module.params.get('include_filter'):
                delete_request["include_filter"] = module.params['include_filter']
                
            if module.params.get('exclude_filter'):
                delete_request["exclude_filter"] = module.params['exclude_filter']
                
            if module.params.get('cluster_ref'):
                delete_request["cluster_ref"] = module.params['cluster_ref']

            if module.params.get('volume_resource_only_policy_ref'):
                delete_request["volume_resource_only_policy_ref"] = module.params['volume_resource_only_policy_ref']
            
            # Add cluster_scope support (new in 2.9.0)
            if module.params.get('cluster_scope'):
                cluster_scope = module.params['cluster_scope']
                delete_request["cluster_scope"] = {}
                if cluster_scope.get('cluster_refs'):
                    delete_request["cluster_scope"]["cluster_refs"] = {"refs": cluster_scope['cluster_refs']}
                elif cluster_scope.get('all_clusters'):
                    delete_request["cluster_scope"]["all_clusters"] = cluster_scope['all_clusters']
            
            response = client.make_request(
                'POST',
                f"v1/backupschedule/{module.params['org_id']}/delete",
                data=delete_request
            )
            return response, True
        except Exception as e:
            handle_request_exception(e, module, "delete backup schedule")

def backup_schedule_request_body(module):
    """Build the backup schedule request object"""
    backup_schedule_request = {
        "metadata": {
            "name": module.params['name'],
            "org_id": module.params['org_id'],
            "owner": module.params['owner']
        },
        "reclaim_policy": module.params['reclaim_policy'],
        "namespaces": module.params['namespaces'],
        "include_resources": module.params['include_resources'], 
        "csi_snapshot_class_name": module.params['csi_snapshot_class_name'],
        "resource_types": module.params['resource_types'],
        "backup_location_ref": module.params['backup_location_ref'],
        "backup_type": module.params['backup_type'],
        "ns_label_selectors": module.params['ns_label_selectors'],
        "cluster_ref": module.params['cluster_ref'],
        "direct_kdmp": module.params['direct_kdmp'],
        "parallel_backup": module.params['parallel_backup'],
        "keep_cr_status": module.params['keep_cr_status'],
    }

    # Handle deprecated fields
    if module.params.get('schedule_policy'):
        backup_schedule_request['schedule_policy'] = module.params['schedule_policy']
    if module.params.get('backup_location'):
        backup_schedule_request['backup_location'] = module.params['backup_location']
    if module.params.get('cluster'):
        backup_schedule_request['cluster'] = module.params['cluster']

    if module.params['backup_object_type']:
        backup_schedule_request["backup_object_type"] = module.params['backup_object_type']


    if module.params.get('operation') == "UPDATE":
        # Add suspend field for update operation
        if module.params.get('suspend') is not None:
            backup_schedule_request['suspend'] = module.params['suspend']
        
        if module.params.get('schedule_policy_ref'):
            backup_schedule_request['schedule_policy_ref'] = module.params['schedule_policy_ref']
        
        if module.params.get('pre_exec_rule_ref'):
            backup_schedule_request['pre_exec_rule_ref'] = module.params['pre_exec_rule_ref']
        if module.params.get('post_exec_rule_ref'):
            backup_schedule_request['post_exec_rule_ref'] = module.params['post_exec_rule_ref']
        if module.params.get('policy_ref'):
            backup_schedule_request['policy_ref'] = module.params['policy_ref']
        
        if module.params.get('cluster_scope'):
            cluster_scope = module.params['cluster_scope']
            backup_schedule_request["cluster_scope"] = {}
            if cluster_scope.get('cluster_refs'):
                backup_schedule_request["cluster_scope"]["cluster_refs"] = {"refs": cluster_scope['cluster_refs']}
            elif cluster_scope.get('all_clusters'):
                backup_schedule_request["cluster_scope"]["all_clusters"] = cluster_scope['all_clusters']

    if module.params.get('volume_resource_only_policy_ref'):
        backup_schedule_request['volume_resource_only_policy_ref'] = module.params['volume_resource_only_policy_ref']

    if module.params.get('pre_exec_rule_ref') and module.params.get('pre_exec_rule'):
        backup_schedule_request['pre_exec_rule_ref'] = module.params['pre_exec_rule_ref']
        backup_schedule_request['pre_exec_rule'] = module.params['pre_exec_rule']

    if module.params.get('post_exec_rule_ref') and module.params.get('post_exec_rule'):
        backup_schedule_request['post_exec_rule_ref'] = module.params['post_exec_rule_ref']
        backup_schedule_request['post_exec_rule'] = module.params['post_exec_rule']
    
    if module.params.get('skip_vm_auto_exec_rules'):
        backup_schedule_request['skip_vm_auto_exec_rules'] = module.params['skip_vm_auto_exec_rules']

    if module.params.get('exclude_resource_types'):
        backup_schedule_request['exclude_resource_types'] = module.params['exclude_resource_types']
    
    if module.params.get('suspend') is not None and module.params.get('operation') != "UPDATE":
        backup_schedule_request['suspend'] = module.params['suspend']

    if module.params.get('label_selectors'):
        backup_schedule_request['label_selectors'] = module.params['label_selectors']
        
    if module.params.get('volume_snapshot_class_mapping'):
        backup_schedule_request['volume_snapshot_class_mapping'] = module.params['volume_snapshot_class_mapping']

    if module.params.get('labels'):
        backup_schedule_request['metadata']['labels'] = module.params['labels']

    if module.params.get('advanced_resource_label_selector'):
        backup_schedule_request['advanced_resource_label_selector'] = module.params['advanced_resource_label_selector']
        
    if module.params.get('include_objects'):
        backup_schedule_request['include_objects'] = module.params['include_objects']
        
    if module.params.get('exclude_objects'):
        backup_schedule_request['exclude_objects'] = module.params['exclude_objects']
        
    if module.params.get('include_filter'):
        backup_schedule_request['include_filter'] = module.params['include_filter']
        
    if module.params.get('exclude_filter'):
        backup_schedule_request['exclude_filter'] = module.params['exclude_filter']

    return backup_schedule_request

def run_module():
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(type='str', choices=['CREATE', 'UPDATE', 'DELETE','INSPECT_ALL','INSPECT_ALL_POST_REQUEST','INSPECT_ONE'], required=True),
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
                version=dict(type='str')
            )),
        backup_object_type=dict(
            required=False,
            type='dict',
            options=dict(
                type=dict(type='str', choices=['Invalid', 'NS', 'VM', 'All'], required=True),
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
        parallel_backup=dict(type='bool', required=False),
        keep_cr_status=dict(type='bool', required=False),
        advanced_resource_label_selector=dict(type='str', required=False),
        # Deprecated fields (keeping for backward compatibility)
        schedule_policy=dict(type='str', required=False),
        backup_location=dict(type='str', required=False),
        cluster=dict(type='str', required=False),
        cloud_credential=dict(type='str', required=False),
        delete_backups=dict(type='bool', required=False),

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
            labels=dict(type='dict'),
            owners=dict(type='list', elements='str'),
            max_objects=dict(type='str'),
            name_filter=dict(type='str'),
            cluster_name_filter=dict(type='str'),
            object_index=dict(type='str'),
            include_detailed_resources=dict(type='bool'),
            cluster_uid_filter=dict(type='str'),
            backup_object_type=dict(type='str'),
            status=dict(type='list', elements='str'),
            time_range=dict(type='dict', options=dict(
                start_time=dict(type='str'),
                end_time=dict(type='str')
            )),
            schedule_policy_ref=dict(type='list', elements='dict', options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )),
            backup_schedule_ref=dict(type='list', elements='dict', options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )),
            sort_option=dict(type='dict', options=dict(
                sortBy=dict(type='dict', options=dict(
                    type=dict(type='str', choices=['Invalid', 'CreationTimestamp', 'Name', 'ClusterName', 'Size', 'RestoreBackupName'])
                )),
                sortOrder=dict(type='dict', options=dict(
                    type=dict(type='str', choices=['Invalid', 'Ascending', 'Descending'])
                ))
            ))
        )),
        
        # New in 2.9.0 - Volume Resource Only Policy support
        volume_resource_only_policy_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        ),
        
        # Enhanced filtering and bulk operations (2.9.0)
        policy_ref=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        ),
        include_objects=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        ),
        exclude_objects=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        ),
        include_filter=dict(type='str', required=False),
        exclude_filter=dict(type='str', required=False),
        
        # New in 2.9.0 - Cluster Scope support
        cluster_scope=dict(
            type='dict',
            required=False,
            options=dict(
                cluster_refs=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        name=dict(type='str', required=True),
                        uid=dict(type='str', required=True)
                    )
                ),
                all_clusters=dict(type='bool')
            )
        ),
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
        # Mutual exclusion for cluster scope and filtering
        mutually_exclusive=[
            ['cluster_scope.cluster_refs', 'cluster_scope.all_clusters'],
            ['include_objects', 'include_filter'],
            ['exclude_objects', 'exclude_filter']
        ]
    )

    if module.check_mode:
        module.exit_json(**result)

    client = PXBackupClient(
        module.params['api_url'],
        module.params['token'],
        module.params['validate_certs']
    )

    try:
        # Handle operations
        if module.params['operation'] == 'CREATE':
            backup_schedule, changed = create_backup_schedule(module, client)
            result['backup_schedule'] = backup_schedule
            result['message'] = "Backup schedule created successfully"
            result['changed'] = changed

        elif module.params['operation'] == 'UPDATE':
            backup_schedule, changed = update_backup_schedule(module, client)
            result['backup_schedule'] = backup_schedule
            result['message'] = "Backup schedule updated successfully"
            result['changed'] = changed

        elif module.params['operation'] == 'INSPECT_ALL' or module.params['operation'] == 'INSPECT_ALL_POST_REQUEST':
            backup_schedules = enumerate_backup_schedules(module, client, module.params['operation'])
            result['backup_schedules'] = backup_schedules
            result['message'] = f"Found {len(backup_schedules)} backup schedules"
            result['changed'] = False

        elif module.params['operation'] == 'INSPECT_ONE':
            backup_schedule = inspect_backup_schedules(module, client)
            result['backup_schedule'] = backup_schedule
            result['message'] = "Backup schedule found successfully"
            result['changed'] = False

        elif module.params['operation'] == 'DELETE':
            backup_schedule, changed = delete_backup_schedules(module, client)
            result['backup_schedule'] = backup_schedule if backup_schedule else {}
            result['message'] = "Backup schedule deleted successfully"
            result['changed'] = changed

    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"API Error: {error_detail}"
            except ValueError:
                error_msg = f"API Error: {e.response.text}"
        else:
            # Generic error message for non-RequestException errors
            error_msg = f"An unexpected error occurred: {error_msg}"
        
        module.fail_json(msg=error_msg)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()