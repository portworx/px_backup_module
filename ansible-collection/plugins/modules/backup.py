#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Backup Management Module

This Ansible module manages backups in PX-Backup, providing operations for:
- Creating new backups
- Updating existing backups
- Deleting backups
- Inspecting backups (single or all)
- Managing backup sharing
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
module: backup

short_description: Manage backups in PX-Backup

version_added: "2.8.1"

description:
    - Manage backups in PX-Backup using different operations
    - Supports CRUD operations and backup sharing
    - Supports both Generic and Normal backup types
    - Provides both single backup and bulk inspection capabilities
    - Handles namespace and resource selection

options:
    operation:
        description:
            - "Operation to perform on the backup"
            - " - CREATE: creates a new backup"
            - " - UPDATE: modifies an existing backup"
            - " - DELETE: removes a backup"
            - " - INSPECT_ONE: retrieves details of a specific backup"
            - " - INSPECT_ALL: lists all backups"
            - " - UPDATE_BACKUP_SHARE: updates backup sharing settings"
        required: true
        type: str
        choices:
            - CREATE
            - UPDATE
            - DELETE
            - INSPECT_ONE
            - INSPECT_ALL
            - UPDATE_BACKUP_SHARE
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
            - Name of the backup
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description:
            - Unique identifier of the backup
            - Required for UPDATE, DELETE, INSPECT_ONE, and UPDATE_BACKUP_SHARE operations
        required: false
        type: str
    backup_location_ref:
        description: Reference to backup location
        type: dict
        required: false
        suboptions:
            name:
                description: Name of the backup location
                type: str
            uid:
                description: UID of the backup location
                type: str
    cluster_ref:
        description: Reference to cluster
        type: dict
        required: false
        suboptions:
            name:
                description: Name of the cluster
                type: str
            uid:
                description: UID of the cluster
                type: str
    pre_exec_rule_ref:
        description: Reference to pre exec rule
        type: dict
        required: false
        suboptions:
            name:
                description: Name of the pre exec rule
                type: str
            uid:
                description: UID of the pre exec rule
                type: str
    post_exec_rule_ref:
        description: Reference to post exec rule
        type: dict
        required: false
        suboptions:
            name:
                description: Name of the post exec rule
                type: str
            uid:
                description: UID of the post exec rule
                type: str
    exclude_resource_types:
        description: List of resources to exclude during backup
        type: list
        elements: str
        required: false
    namespaces:
        description: List of namespaces to backup
        type: list
        elements: str
        required: false
    label_selectors:
        description: Label selectors to choose resources
        type: dict
        required: false
    resource_types:
        description: List of resource types to backup
        type: list
        elements: str
        required: false
    include_resources:
        description: List of specific resources to include in backup
        type: list
        elements: dict
        required: false
        suboptions:
            name:
                description: Resource name
                type: str
            namespace:
                description: Resource namespace
                type: str
            group:
                description: Resource API group
                type: str
            kind:
                description: Resource kind
                type: str
            version:
                description: Resource version
                type: str
    backup_type:
        description: Type of backup
        type: str
        choices: ['Generic', 'Normal']
        default: 'Normal'
        required: false
    backup_object_type:
        description: Backup object type
        type: dict
        required: false
        suboptions:
            type:
                description: Type of backup object
                type: str
                choices: ['Invalid', 'All', 'VirtualMachine']
    ns_label_selectors:
        description: Label selectors for namespaces
        type: str
        required: false
    cluster:
        description: Name or UID of the cluster
        type: str
        required: false
    skip_vm_auto_exec_rules:
        description: Skip auto rules for VirtualMachine backup object type
        type: bool
        default: false
        required: false
    volume_snapshot_class_mapping:
        description: Volume snapshot class mapping for CSI based backup
        type: dict
        required: false
    direct_kdmp:
        description: Take backup as direct kdmp
        type: bool
        default: false
        required: false
    backup_share:
        description: Backup sharing configuration
        type: dict
        required: false
        suboptions:
            collaborators:
                description: List of users to share with
                type: list
                elements: str
            groups:
                description: List of groups to share with
                type: list
                elements: str
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true

requirements:
    - python >= 3.9
    - requests

'''

EXAMPLES = r'''
# Create a new backup
- name: Create backup
  backup:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-backup"
    org_id: "default"
    backup_location_ref:
      name: "s3-location"
      uid: "location-uid"
    cluster_ref:
      name: "prod-cluster"
      uid: "cluster-uid"
    namespaces:
      - "app1"
      - "app2"
    backup_type: "Normal"

# List all backups
- name: List all backups
  backup:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"

# Update backup sharing
- name: Update backup sharing
  backup:
    operation: UPDATE_BACKUP_SHARE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-backup"
    org_id: "default"
    uid: "backup-uid"
    backup_share:
      collaborators: ["user1", "user2"]
      groups: ["group1"]
      access_type: "Read"
'''

RETURN = r'''
backup:
    description: Details of the backup for single-item operations
    type: dict
    returned: success
    sample: {
        "metadata": {
            "name": "prod-backup",
            "org_id": "default",
            "uid": "123-456",
            "labels": {
                "environment": "production",
                "team": "platform",
                "application": "database"
            },
            "ownership": {
                "owner": "admin@company.com",
                "groups": [
                    {
                        "id": "platform-team",
                        "access": "Write"
                    },
                    {
                        "id": "devops",
                        "access": "Admin"
                    }
                ],
                "collaborators": [
                    {
                        "id": "john.doe@company.com",
                        "access": "Read"
                    },
                    {
                        "id": "jane.smith@company.com",
                        "access": "Write"
                    }
                ],
                "public": {
                    "type": "Read"
                }
            }
        },
        "backup_info": {
            "cluster": "prod-cluster",
            "namespaces": ["app1", "app2"],
            "backup_type": "Normal",
            "label_selectors": {
                "app": "mysql",
                "tier": "database"
            },
            "resources": [
                {
                    "name": "mysql-deployment",
                    "namespace": "app1",
                    "group": "apps",
                    "kind": "Deployment",
                    "version": "v1"
                }
            ],
            "status": {
                "status": "Success",
                "reason": "Backup completed successfully"
            },
            "backup_path": "/backups/prod-backup",
            "total_size": 1073741824,  # 1GB in bytes
            "resource_count": 15,
            "stork_version": "2.8.0",
            "backup_object_type": "All",
            "direct_kdmp": false,
            "completion_time_info": {
                "volumes_completion_time": "2024-11-19T10:00:00Z",
                "resources_completion_time": "2024-11-19T10:05:00Z",
                "total_completion_time": "2024-11-19T10:05:30Z"
            }
        }
    }
message:
    description: Operation result message
    type: str
    returned: always
changed:
    description: Whether the operation changed the backup
    type: bool
    returned: always
'''

# Configure logging
# logger = logging.getLogger('backup')
# logger.addHandler(logging.NullHandler())
# logging.basicConfig(
#     level=logging.DEBUG,  # Set the logging level to DEBUG
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#     handlers=[
#         logging.StreamHandler(),  # Logs to the console
#         logging.FileHandler("backup_module_debug.log", mode="w")  # Optional: Logs to a file
#     ]
# )
logger = logging.getLogger('backup')
logger.addHandler(logging.NullHandler())

# Custom exceptions


class BackupError(Exception):
    """Base exception for backup operations"""
    pass


class ValidationError(BackupError):
    """Raised when validation fails"""
    pass


class APIError(BackupError):
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
        raise ValidationError(
            f"Operation '{operation}' requires parameters: {', '.join(missing)}")


def build_backup_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build backup request object
    """
    # Create base metadata structure
    metadata = {
        "name": params.get('name'),
        "org_id": params.get('org_id'),
        "uid": params.get('uid')  # Include UID for updates
    }

    # Add labels if provided
    if params.get('labels'):
        metadata['labels'] = params['labels']

    # Add ownership if provided
    if params.get('ownership'):
        metadata['ownership'] = params['ownership']

    # Create request structure
    request = {
        "metadata": metadata
    }
    # For update operations, we just need basic metadata
    # and any specific fields being updated
    if params.get('operation') == 'UPDATE':
        # Add labels if provided
        if params.get('labels'):
            request['metadata']['labels'] = params['labels']

        # Add ownership if provided
        if params.get('ownership'):
            request['metadata']['ownership'] = params['ownership']

        return request

    # For other operations, include additional fields
    request.update({
        "backup_location_ref": params.get('backup_location_ref', {}),
        "cluster_ref": params.get('cluster_ref', {}),
        "namespaces": params.get('namespaces', []),
        "label_selectors": params.get('label_selectors', {}),
        "include_resources": params.get('include_resources', []),
        "resource_types": params.get('resource_types', [])
    })

    # Add backup type if provided
    if params.get('backup_type'):
        backup_type_map = {
            'Invalid': 0,
            'Generic': 1,
            'Normal': 2
        }
        request['backup_type'] = backup_type_map.get(params['backup_type'], 0)

    # Add optional fields if they exist
    optional_fields = [
        'cluster',
        'pre_exec_rule_ref',
        'post_exec_rule_ref',
        'ns_label_selectors',
        'skip_vm_auto_exec_rules',
        'volume_snapshot_class_mapping',
        'direct_kdmp',
        'exclude_resource_types'
    ]

    for field in optional_fields:
        if params.get(field) is not None:
            request[field] = params[field]

    return request

def process_backup_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process backup API response into standardized format
    
    Args:
        response: Raw API response dictionary
        
    Returns:
        Dict containing processed backup information with all available fields
    """
    result = {}
    
    # Process metadata if present
    if 'metadata' in response:
        result['metadata'] = {}
        metadata = response['metadata']
        # Process all fields in metadata
        for key, value in metadata.items():
            if value is not None:  # Only include non-None values
                # Handle different default types
                if isinstance(value, dict):
                    result['metadata'][key] = value or {}
                elif isinstance(value, list):
                    result['metadata'][key] = value or []
                else:
                    result['metadata'][key] = value

    # Process backup_info if present
    if 'backup_info' in response:
        result['backup_info'] = {}
        backup_info = response['backup_info']
        # Process all fields in backup_info
        for key, value in backup_info.items():
            if value is not None:  # Only include non-None values
                # Handle different default types
                if isinstance(value, dict):
                    result['backup_info'][key] = value or {}
                elif isinstance(value, list):
                    result['backup_info'][key] = value or []
                elif isinstance(value, bool):
                    result['backup_info'][key] = value
                else:
                    result['backup_info'][key] = value

    return result

def create_backup(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new backup"""
    try:
        params = dict(module.params)
        
        # Build request
        backup_request = build_backup_request(params)
        
        # Make API request
        response = client.make_request(
            method='POST',
            endpoint='v1/backup',
            data=backup_request
        )
        
        # Return the backup from the response
        if isinstance(response, dict) and 'backup' in response:
            return response['backup'], True

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
        module.fail_json(msg=f"Failed to create backup: {error_msg}")

def update_backup(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing backup"""
    try:
        params = dict(module.params)
        backup_request = build_backup_request(params)

        # Make update request
        response = client.make_request(
            method='PUT',
            endpoint='v1/backup', 
            data=backup_request
        )

        # Process response
        result = process_backup_response(response)
        return result, True

    except Exception as e:
        error_msg = str(e)
        if hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {getattr(e.response, 'text', 'No response text')}"
        module.fail_json(msg=f"Failed to update backup: {error_msg}")

def update_backup_share(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update backup sharing settings"""
    try:
        # Map access types to enum values based on protobuf definition
        access_type_map = {
            'Invalid': 0,
            'View': 1,
            'Restorable': 2,
            'FullAccess': 3
        }

        # Get backup share configuration from module params
        
        backupshare = module.params.get('backup_share', {})
        
        # Validate collaborators
        collaborators = []
        for collaborator in backupshare.get('collaborators', []):
            if not isinstance(collaborator, dict) or 'id' not in collaborator or 'access' not in collaborator:
                module.fail_json(
                    msg=f"Invalid collaborator entry: {collaborator}. Each collaborator must have 'id' and 'access'."
                )
            access_value = access_type_map.get(collaborator['access'])
            if access_value is None:
                module.fail_json(
                    msg=f"Invalid access_type '{collaborator['access']}' for collaborator '{collaborator['id']}'."
                )
            collaborators.append({"id": collaborator['id'], "access": access_value})

        # Validate groups
        groups = []
        for group in backupshare.get('groups', []):
            if not isinstance(group, dict) or 'id' not in group or 'access' not in group:
                module.fail_json(
                    msg=f"Invalid group entry: {group}. Each group must have 'id' and 'access'."
                )
            access_value = access_type_map.get(group['access'])
            if access_value is None:
                module.fail_json(
                    msg=f"Invalid access_type '{group['access']}' for group '{group['id']}'."
                )
            groups.append({"id": group['id'], "access": access_value})
        # Structure the backup share request according to protobuf
        backup_share_request = {
            "org_id": module.params['org_id'],
            "name": module.params['name'],
            "uid": module.params['uid'],
            "backupshare": {
                "collaborators": collaborators,
                "groups": groups
            }
        }

        # Debug the request being sent
        logger.debug(f"Backup Share Request: {backup_share_request}")

        # Make the API request to update the backup share
        response = client.make_request(
            method='PUT',
            endpoint='v1/backup/updatebackupshare',
            data=backup_share_request
        )

        # Return the response
        return response, True

    except Exception as e:
        error_msg = str(e)
        if hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {getattr(e.response, 'text', 'No response text')}"
        module.fail_json(msg=f"Failed to update backup share: {error_msg}")

def enumerate_backups(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all backups"""

    # Build query parameters
    params = {
        'enumerate_options.cluster_name_filter': module.params.get('cluster_name_filter'),
        'enumerate_options.cluster_uid_filter': module.params.get('cluster_uid_filter')
    }

    # Add other parameters if they exist
    if module.params.get('max_objects'):
        params['enumerate_options.max_objects'] = module.params['max_objects']

    if module.params.get('include_detailed_resources') is not None:
        params['enumerate_options.include_detailed_resources'] = module.params['include_detailed_resources']

    if module.params.get('name_filter'):
        params['enumerate_options.name_filter'] = module.params['name_filter']

    if module.params.get('labels'):
        # For dictionary types, we might need to handle this differently
        # depending on how the API expects labels
        params['enumerate_options.labels'] = module.params['labels']

    if module.params.get('owners'):
        params['enumerate_options.owners'] = module.params['owners']

    if module.params.get('backup_object_type'):
        params['enumerate_options.backup_object_type'] = module.params['backup_object_type']

    if module.params.get('status'):
        params['enumerate_options.status'] = module.params['status']

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    logger.debug(f"Making request with params: {params}")

    try:
        response = client.make_request(
            'GET',
            f"v1/backup/{module.params['org_id']}",
            params=params
        )

        return response.get('backups', [])
    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to enumerate backups: {error_msg}")


def inspect_backup(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific backup"""
    try:
        # Build request URL and params
        params = {}
        if module.params.get('uid'):
            params['uid'] = module.params['uid']

        response = client.make_request(
            'GET',
            f"v1/backup/{module.params['org_id']}/{module.params['name']}",
            params=params
        )
        
        # Log response for debugging
        module.debug(f"API Response: {response}")

        if not response:
            module.fail_json(msg=f"No backup found with name {module.params['name']} and uid {module.params['uid']}")

        # Return the processed response
        return {
            'backup': response.get('backup', {}),
            'message': "Successfully retrieved backup details",
            'changed': False
        }

    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
            if hasattr(e.response, 'status_code'):
                error_msg = f"API returned status code {e.response.status_code}: {error_msg}"
        module.fail_json(msg=f"Failed to inspect backup: {error_msg}")


def delete_backup(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a backup"""
    try:
        # Build delete request parameters
        params = {
            'uid': module.params['uid']
        }
        
        # Add cluster information
        if module.params.get('cluster_ref'):
            if module.params['cluster_ref'].get('name'):
                params['cluster'] = module.params['cluster_ref']['name']
            if module.params['cluster_ref'].get('uid'):
                params['cluster_uid'] = module.params['cluster_ref']['uid']
        
        response = client.make_request(
            'DELETE',
            f"v1/backup/{module.params['org_id']}/{module.params['name']}",
            params=params
        )
        return response, True
    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to delete backup: {error_msg}")


def needs_update(current: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """
    Compare current and desired state to determine if update is needed
    
    Args:
        current: Current backup state
        desired: Desired backup state
    
    Returns:
        bool: True if update is needed, False otherwise
    """
    def normalize_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize dictionary for comparison"""
        if not isinstance(d, dict):
            return d
            
        normalized = {}
        for k, v in d.items():
            if v is not None:
                if isinstance(v, dict):
                    normalized[k] = normalize_dict(v)
                elif isinstance(v, list):
                    normalized[k] = [normalize_dict(item) if isinstance(item, dict) else item 
                                   for item in v]
                else:
                    normalized[k] = v
        return normalized

    # Focus comparison on specific fields that can be updated
    fields_to_compare = [
        'metadata.labels',
        'metadata.ownership',
        'backup_info.label_selectors',
        'backup_info.namespaces',
        'backup_info.include_resources',
        'backup_info.resource_types'
    ]

    current_normalized = normalize_dict(current)
    desired_normalized = normalize_dict(desired)

    for field_path in fields_to_compare:
        parts = field_path.split('.')
        curr_value = current_normalized
        desired_value = desired_normalized
        
        for part in parts:
            curr_value = curr_value.get(part, {})
            desired_value = desired_value.get(part, {})
            
        if curr_value != desired_value:
            return True

    return False


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
    return f"Failed to {operation.lower()} backup: {error_msg}"


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
            backup, changed = create_backup(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'backup': backup},
                message="Backup created successfully"
            )

        elif operation == 'UPDATE':
            backup, changed = update_backup(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'backup': backup},
                message="Backup updated successfully"
            )

        elif operation == 'UPDATE_BACKUP_SHARE':
            backup, changed = update_backup_share(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'backup': backup},
                message="Backup share updated successfully"
            )

        elif operation == 'INSPECT_ALL':
            backups = enumerate_backups(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'backups': backups},
                message=f"Found {len(backups)} backups"
            )

        elif operation == 'INSPECT_ONE':
            result = inspect_backup(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data=result,
                message="Successfully retrieved backup details"
            )

        elif operation == 'DELETE':
            backup, changed = delete_backup(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'backup': backup},
                message="Backup deleted successfully"
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
                'UPDATE_BACKUP_SHARE'
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        cluster=dict(type='str', required=False),

         # metadata-related arguments
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

        # Backup location reference
        backup_location_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),

        # Pre exec rule reference
        pre_exec_rule_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),

        # Post exec rule reference
        post_exec_rule_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),

        # Cluster reference
        cluster_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),

        # Backup configuration
        namespaces=dict(type='list', elements='str', required=False),
        label_selectors=dict(type='dict', required=False),
        resource_types=dict(type='list', elements='str', required=False),

        exclude_resource_types=dict(type='list', elements='str', required=False),
        include_resources=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                namespace=dict(type='str', required=True),
                group=dict(type='str', required=True),
                kind=dict(type='str', required=True),
                version=dict(type='str', required=True)
            )
        ),
        backup_type=dict(
            type='str',
            required=False,
            choices=['Generic', 'Normal'],
            default='Normal'
        ),
        backup_object_type=dict(
            type='str',
            required=False,
            choices=['Invalid', 'All', 'VirtualMachine']
        ),
        ns_label_selectors=dict(type='str', required=False),
        skip_vm_auto_exec_rules=dict(
            type='bool', required=False, default=False),
        volume_snapshot_class_mapping=dict(type='dict', required=False),
        direct_kdmp=dict(type='bool', required=False, default=False),

        # Backup share configuration
        backup_share=dict(
            type='dict',
            required=False,
            options=dict(
                collaborators=dict(
                    type='list', 
                    elements='dict',
                    options=dict(
                        id=dict(type='str', required=True),
                        access=dict(type='str', choices=['Invalid', 'View', 'Restorable', 'FullAccess'], required=True)
                    )
                ),
                groups=dict(
                    type='list', 
                    elements='dict',
                    options=dict(
                        id=dict(type='str', required=True),
                        access=dict(type='str', choices=['Invalid', 'View', 'Restorable', 'FullAccess'], required=True)
                    )
                ),
            )
        ),

        # Enumerate options
        labels=dict(type='dict', required=False),
        max_objects=dict(type='int', required=False),
        name_filter=dict(type='str', required=False),
        cluster_name_filter=dict(type='str', required=False),
        include_detailed_resources=dict(
            type='bool', required=False, default=False),
        cluster_uid_filter=dict(type='str', required=False),
        owners=dict(type='list', elements='str', required=False),
        status=dict(type='list', elements='str', required=False),

        validate_certs=dict(type='bool', default=True)
    )

    result = dict(
        changed=False,
        backup={},
        backups=[],
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'backup_location_ref', 'cluster_ref'],

        'UPDATE': ['name', 'uid'],

        'DELETE': ['name', 'uid'],

        'INSPECT_ONE': ['name', 'uid'],

        'INSPECT_ALL': ['cluster_name_filter', 'cluster_uid_filter', 'org_id'],

        'UPDATE_BACKUP_SHARE': ['name', 'uid', 'backup_share']
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('operation', 'CREATE', [
             'name', 'backup_location_ref', 'cluster_ref']),

            ('operation', 'UPDATE', ['name', 'uid']),

            ('operation', 'DELETE', ['name', 'uid']),

            ('operation', 'INSPECT_ONE', ['name', 'uid']),
            
            ('operation', 'INSPECT_ALL', ['cluster_name_filter', 'cluster_uid_filter', 'org_id']),

            ('operation', 'UPDATE_BACKUP_SHARE',
             ['name', 'uid', 'backup_share'])
        ]
    )

    try:
        # Validate operation parameters
        operation = module.params['operation']
        validate_params(module.params, operation,
                        operation_requirements[operation])

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