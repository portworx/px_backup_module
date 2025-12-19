#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Volume Resource Only Policy Management Module

This Ansible module manages volume resource only policies in PX-Backup, providing operations for:
- Creating new volume resource only policies
- Updating existing volume resource only policies
- Deleting volume resource only policies
- Inspecting volume resource only policies (single or all)
- Managing volume resource only policy ownership
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

# Constants for enum mappings
VOLUME_TYPE_MAP = {
    'Invalid': 0,
    'Portworx': 1,
    'Csi': 2,
    'Nfs': 3
}

DOCUMENTATION = r'''
---
module: volume_resource_only_policy

short_description: Manage volume resource only policies in PX-Backup

version_added: "2.10.0"

description:
    - Manage volume resource only policies in PX-Backup using different operations
    - Supports CRUD operations and ownership management
    - Allows configuration of volume types, CSI drivers, and NFS servers
    - Provides both single policy and bulk inspection capabilities
    - Handles policy configurations for skipping volume data backup

options:
    operation:
        description:
            - "Operation to perform on the volume resource only policy"
            - "- CREATE: creates a new volume resource only policy"
            - "- UPDATE: modifies an existing volume resource only policy"
            - "- DELETE: removes a volume resource only policy"
            - "- INSPECT_ONE: retrieves details of a specific volume resource only policy"
            - "- INSPECT_ALL: lists all volume resource only policies"
            - "- UPDATE_OWNERSHIP: updates ownership settings of a volume resource only policy"
        required: true
        type: str
        choices:
            - CREATE
            - UPDATE
            - DELETE
            - INSPECT_ONE
            - INSPECT_ALL
            - UPDATE_OWNERSHIP
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
            - Name of the volume resource only policy
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description:
            - Unique identifier of the volume resource only policy
        required: false
        type: str
    volume_types:
        description: List of volume types to be skipped for backing up the volume data
        type: list
        elements: str
        required: false
        choices: ['Invalid', 'Portworx', 'Csi', 'Nfs']
    csi_drivers:
        description: List of CSI drivers that need to be used to skip the backing up of volume data
        type: list
        elements: str
        required: false
    nfs_servers:
        description: List of NFS servers that need to be used to skip the backing up of volume data in the case of NFS volumes
        type: list
        elements: str
        required: false
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
        description: Labels to attach to the volume resource only policy
        required: false
        type: dict
    enumerate_options:
        description:
            - Options for controlling enumeration behavior when listing volume resource only policies
            - Used with INSPECT_ALL operation to filter and limit results
            - All suboptions are optional and can be combined for advanced filtering
        type: dict
        required: false
        version_added: '2.9.0'
        suboptions:
            generic_enumerate_options:
                description: Common enumeration options for filtering and pagination
                type: dict
                required: false
                suboptions:
                    labels:
                        description: Labels to attach to the volume resource only policy
                        type: dict
                        required: false
                    max_objects:
                        description:
                            - Maximum number of policies to return in the response
                            - Useful for pagination and limiting large result sets
                            - Must be a positive integer
                        type: int
                        required: false
                    name_filter:
                        description: Filter policies by name using substring matching
                        type: str
                        required: false
                    object_index:
                        description:
                            - Starting index for pagination when retrieving policies
                            - Used with max_objects for pagination through large result sets
                            - Zero-based indexing (0 = first policy)
                        type: int
                        required: false
                    sort_option:
                        description: Sorting configuration for policy enumeration
                        type: dict
                        required: false
                        version_added: '2.11.0'
                        suboptions:
                            sortBy:
                                description: Field to sort by
                                type: str
                                choices: ['Invalid', 'CreationTimestamp', 'Name', 'ClusterName', 'Size', 'RestoreBackupName', 'LastUpdateTimestamp']
                                default: 'Invalid'
                            sortOrder:
                                description: Sort order
                                type: str
                                choices: ['Invalid', 'Ascending', 'Descending']
                                default: 'Invalid'
                    time_range:
                        description: Time range for filtering policies by creation/update time
                        type: dict
                        required: false
                        version_added: '2.11.0'
                        suboptions:
                            start_time:
                                description: Start time for the time range filter (RFC3339 format)
                                type: str
                                required: false
                            end_time:
                                description: End time for the time range filter (RFC3339 format)
                                type: str
                                required: false
            volume_types:
                description: Filter policies by volume types
                type: list
                elements: str
                required: false
                version_added: '2.11.0'
                choices: ['Invalid', 'Portworx', 'Csi', 'Nfs']
    ownership:
        description: Ownership configuration for the volume resource only policy
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the volume resource only policy
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
    - "CREATE: name, org_id"
    - "UPDATE: name, org_id"
    - "DELETE: name, org_id"
    - "INSPECT_ONE: name, org_id"
    - "INSPECT_ALL: org_id"
    - "UPDATE_OWNERSHIP: name, org_id, ownership"
'''

EXAMPLES = r'''
# Create a new volume resource only policy
- name: Create volume resource only policy
  volume_resource_only_policy:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-portworx-policy"
    org_id: "default"
    volume_types:
      - "Portworx"
      - "Csi"
    csi_drivers:
      - "ebs.csi.aws.com"
      - "disk.csi.azure.com"
    labels:
      environment: "production"
      team: platform

# List all volume resource only policies
- name: List all volume resource only policies
  volume_resource_only_policy:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"

# List policies with enhanced filtering and sorting
- name: List volume resource only policies with filtering
  volume_resource_only_policy:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    enumerate_options:
      generic_enumerate_options:
        max_objects: 50
        name_filter: "prod-"
        labels:
          environment: "production"
        sort_option:
          sortBy: "LastUpdateTimestamp"
          sortOrder: "Descending"
      volume_types:
        - "Portworx"
        - "Csi"

# Update ownership of a volume resource only policy
- name: Update volume resource only policy ownership
  volume_resource_only_policy:
    operation: UPDATE_OWNERSHIP
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-portworx-policy"
    org_id: "default"
    uid: "123"
    ownership:
      owner: "admin@example.com"
      groups:
        - id: "backup-admins"
          access: "Admin"
      collaborators:
        - id: "user@example.com"
          access: "Write"

# Delete a volume resource only policy
- name: Delete volume resource only policy
  volume_resource_only_policy:
    operation: DELETE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-portworx-policy"
    org_id: "default"
    uid: "123"
'''

RETURN = r'''
volume_resource_only_policy:
    description: Details of the volume resource only policy for single-item operations
    type: dict
    returned: success
    sample: {
        "metadata": {
            "name": "skip-portworx-policy",
            "org_id": "default",
            "uid": "123456",
            "labels": {
                "environment": "production",
                "team": "platform"
            },
            "ownership": {
                "owner": "admin@company.com",
                "groups": [
                    {
                        "id": "backup-admins",
                        "access": "Admin"
                    }
                ],
                "collaborators": [
                    {
                        "id": "user@company.com",
                        "access": "Write"
                    }
                ]
            }
        },
        "volume_resource_only_policy_info": {
            "volume_types": ["Portworx", "Csi"],
            "csi_drivers": ["ebs.csi.aws.com", "disk.csi.azure.com"],
            "nfs_servers": ["nfs.example.com"]
        }
    }
volume_resource_only_policies:
    description: List of volume resource only policies for INSPECT_ALL operation
    type: list
    returned: when operation is INSPECT_ALL
    sample: [
        {
            "metadata": {
                "name": "policy1",
                "org_id": "default"
            },
            "volume_resource_only_policy_info": {
                "volume_types": ["Portworx"],
                "csi_drivers": [],
                "nfs_servers": []
            }
        }
    ]
message:
    description: Operation result message
    type: str
    returned: always
changed:
    description: Whether the operation changed the volume resource only policy
    type: bool
    returned: always
'''

# Configure logging
logger = logging.getLogger('volume_resource_only_policy')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class VolumeResourceOnlyPolicyError(Exception):
    """Base exception for volume resource only policy operations"""
    pass

class ValidationError(VolumeResourceOnlyPolicyError):
    """Raised when validation fails"""
    pass

class APIError(VolumeResourceOnlyPolicyError):
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

def build_volume_resource_only_policy_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build volume resource only policy request object
    
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
        "volume_resource_only_policy": {}
    }

    # Add UID for update operations
    if params.get('uid'):
        request['metadata']['uid'] = params['uid']

    # Add optional metadata fields
    if params.get('labels'):
        request['metadata']['labels'] = params['labels']
        
    if params.get('ownership'):
        request['metadata']['ownership'] = params['ownership']

    # Build volume_resource_only_policy info
    policy_info = {}
    
    # Handle volume_types - convert string values to enum integers
    if params.get('volume_types'):
        volume_type_values = []
        for vol_type in params['volume_types']:
            if vol_type in VOLUME_TYPE_MAP:
                volume_type_values.append(VOLUME_TYPE_MAP[vol_type])
            else:
                raise ValidationError(f"Invalid volume_type: {vol_type}")
        policy_info['volume_types'] = volume_type_values
    
    # Handle csi_drivers
    if params.get('csi_drivers'):
        policy_info['csi_drivers'] = params['csi_drivers']
    
    # Handle nfs_servers
    if params.get('nfs_servers'):
        policy_info['nfs_servers'] = params['nfs_servers']

    request['volume_resource_only_policy'] = policy_info
    return request

def create_volume_resource_only_policy(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new volume resource only policy"""
    try:
        params = dict(module.params)
        policy_request = build_volume_resource_only_policy_request(params)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/volumeresourceonlypolicy',
            data=policy_request
        )
        
        # Return the policy from the response
        if isinstance(response, dict) and 'volume_resource_only_policy' in response:
            return response['volume_resource_only_policy'], True
            
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
        module.fail_json(msg=f"Failed to create volume resource only policy: {error_msg}")

def update_volume_resource_only_policy(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing volume resource only policy"""
    try:
        params = dict(module.params)
        policy_request = build_volume_resource_only_policy_request(params)
        
        # Get current state for comparison
        current = inspect_volume_resource_only_policy(module, client)
        if not needs_update(current, policy_request):
            return current, False
            
        # Make update request
        response = client.make_request(
            method='PUT',
            endpoint='v1/volumeresourceonlypolicy',
            data=policy_request
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update volume resource only policy: {str(e)}")

def update_ownership(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update ownership of a volume resource only policy"""
    ownership_request = {
        "org_id": module.params['org_id'],
        "name": module.params['name'],
        "ownership": module.params['ownership'],
        "uid": module.params.get('uid', '')
    }
    
    try:
        response = client.make_request(
            'PUT', 
            'v1/volumeresourceonlypolicy/updateownership', 
            ownership_request
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update volume resource only policy ownership: {str(e)}")

def enumerate_volume_resource_only_policies(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all volume resource only policies"""

    # Determine if we should use the new POST endpoint based on enhanced options
    enumerate_options = module.params.get('enumerate_options', {})
    request_body = {
        "org_id": module.params['org_id']
    }

    # Handle top-level labels
    if module.params.get('labels'):
        request_body["labels"] = module.params['labels']

    # Build enumerate_options for the request
    if enumerate_options:
        request_enumerate_options = {}

        # Handle generic enumerate options
        if enumerate_options.get('generic_enumerate_options'):
            generic_opts = enumerate_options['generic_enumerate_options']
            generic_enumerate_options = {}

            # Add simple fields
            for field in ['labels', 'max_objects', 'name_filter', 'object_index']:
                if field in generic_opts and generic_opts[field] is not None:
                    generic_enumerate_options[field] = generic_opts[field]

            # Handle sort_option (nested within generic_enumerate_options)
            if generic_opts.get('sort_option'):
                sort_option = generic_opts['sort_option']
                generic_enumerate_options["sort_option"] = {
                    "sortBy": {"type": sort_option.get('sortBy', 'Invalid')},
                    "sortOrder": {"type": sort_option.get('sortOrder', 'Invalid')}
                }

            # Handle time_range (nested within generic_enumerate_options)
            if generic_opts.get('time_range'):
                time_range = generic_opts['time_range']
                time_range_obj = {}
                if time_range.get('start_time'):
                    time_range_obj['start_time'] = time_range['start_time']
                if time_range.get('end_time'):
                    time_range_obj['end_time'] = time_range['end_time']
                if time_range_obj:
                    generic_enumerate_options['time_range'] = time_range_obj

            if generic_enumerate_options:
                request_enumerate_options['generic_enumerate_options'] = generic_enumerate_options

        # Handle volume types filtering (at top level of enumerate_options)
        if enumerate_options.get('volume_types'):
            request_enumerate_options["volume_types"] = enumerate_options['volume_types']

        if request_enumerate_options:
            request_body["enumerate_options"] = request_enumerate_options

    try:
        response = client.make_request(
            'POST',
            f"v1/volumeresourceonlypolicy/{module.params['org_id']}/enumerate",
            data=request_body
        )
        return response.get('volume_resource_only_policies', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate volume resource only policies (POST): {str(e)}")

def inspect_volume_resource_only_policy(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific volume resource only policy"""
    try:
        response = client.make_request(
            'GET',
            f"v1/volumeresourceonlypolicy/{module.params['org_id']}/{module.params['name']}"
        )
        return response
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect volume resource only policy: {str(e)}")

def delete_volume_resource_only_policy(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a volume resource only policy"""
    try:
        response = client.make_request(
            'DELETE',
            f"v1/volumeresourceonlypolicy/{module.params['org_id']}/{module.params['name']}"
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete volume resource only policy: {str(e)}")

def needs_update(current: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """
    Compare current and desired state to determine if update is needed
    
    Args:
        current: Current policy state
        desired: Desired policy state
    
    Returns:
        bool indicating whether update is needed
    """
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
    return f"Failed to {operation.lower()} volume resource only policy: {error_msg}"

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
            policy, changed = create_volume_resource_only_policy(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'volume_resource_only_policy': policy},
                message="Volume resource only policy created successfully"
            )
        
        elif operation == 'UPDATE':
            policy, changed = update_volume_resource_only_policy(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'volume_resource_only_policy': policy},
                message="Volume resource only policy updated successfully"
            )
        
        elif operation == 'INSPECT_ALL':
            policies = enumerate_volume_resource_only_policies(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'volume_resource_only_policies': policies},
                message=f"Found {len(policies)} volume resource only policies"
            )

        elif operation == 'INSPECT_ONE':
            policy = inspect_volume_resource_only_policy(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'volume_resource_only_policy': policy},
                message="Successfully retrieved volume resource only policy details"
            )

        elif operation == 'UPDATE_OWNERSHIP':
            policy, changed = update_ownership(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'volume_resource_only_policy': policy},
                message="Volume resource only policy ownership updated successfully"
            )
        
        elif operation == 'DELETE':
            policy, changed = delete_volume_resource_only_policy(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'volume_resource_only_policy': policy},
                message="Volume resource only policy deleted successfully"
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
        volume_types=dict(
            type='list',
            elements='str',
            required=False,
            choices=['Invalid', 'Portworx', 'Csi', 'Nfs']
        ),
        csi_drivers=dict(type='list', elements='str', required=False),
        nfs_servers=dict(type='list', elements='str', required=False),
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
        
        labels=dict(type='dict', required=False),
        enumerate_options=dict(
            type='dict',
            required=False,
            options=dict(
                generic_enumerate_options=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        labels=dict(type='dict', required=False),
                        max_objects=dict(type='int', required=False),
                        name_filter=dict(type='str', required=False),
                        object_index=dict(type='int', required=False),
                        sort_option=dict(
                            type='dict',
                            required=False,
                            options=dict(
                                sortBy=dict(
                                    type='str',
                                    choices=['Invalid', 'CreationTimestamp', 'Name', 'ClusterName', 'Size', 'RestoreBackupName', 'LastUpdateTimestamp'],
                                    default='Invalid'
                                ),
                                sortOrder=dict(
                                    type='str',
                                    choices=['Invalid', 'Ascending', 'Descending'],
                                    default='Invalid'
                                )
                            )
                        ),
                        time_range=dict(
                            type='dict',
                            required=False,
                            options=dict(
                                start_time=dict(type='str', required=False),
                                end_time=dict(type='str', required=False)
                            )
                        )
                    )
                ),
                volume_types=dict(
                    type='list',
                    elements='str',
                    required=False,
                    choices=['Invalid', 'Portworx', 'Csi', 'Nfs']
                )
            )
        ),
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
                            choices=['Invalid', 'Read', 'Write', 'Admin']
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
                            choices=['Invalid', 'Read', 'Write', 'Admin']
                        )
                    )
                ),
                public=dict(
                    type='dict',
                    options=dict(
                        type=dict(
                            type='str',
                            choices=['Invalid', 'Read', 'Write', 'Admin']
                        )
                    )
                )
            )
        )
    )

    result = dict(
        changed=False,
        volume_resource_only_policy={},
        volume_resource_only_policies=[],
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name'],
        'UPDATE': ['name'],
        'DELETE': ['name'],
        'INSPECT_ONE': ['name'],
        'INSPECT_ALL': ['org_id'],
        'UPDATE_OWNERSHIP': ['name', 'ownership']
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