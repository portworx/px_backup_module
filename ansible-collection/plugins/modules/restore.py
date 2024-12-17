#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Location Management Module

This Ansible module manages restores in PX-Backup, providing operations for:
- Creating restores
- Enumerating restores
- Inspecting restores
- Deleting restores

"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import typing
from typing import Dict, List, Tuple, Optional, Any, Union
import logging
from dataclasses import dataclass
import os
os.environ['PYTHONUNBUFFERED'] = '1'

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
import requests
import sys

DOCUMENTATION = r'''
---
module: restore

short_description: Manage restores in PX-Backup

version_added: "2.8.1"

description:
    - Manage restores in PX-Backup using different operations
    - Supports CRUD operations and replacing existing resources during restore
    - Supports both Default and Custom restores
    - Provides both single and bulk restore inspection capabilities
    - Handles resource selection during restore
    - Handles storageClass and namespace mapping during custom restore

options:
    operation:
        description:
            - Operation to perform on the restore
            - "- CREATE: creates a new restore"
            - "- DELETE: removes a restore"
            - "- INSPECT_ONE: retrieves details of a specific restore"
            - "- INSPECT_ALL: lists all restores"
        required: true
        type: str
        choices: ['CREATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL']
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
            - Name of the restore
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description:
            - Unique identifier of the restore
        required: false
        type: str
    backup_ref:
        description: Reference to backup
        type: dict
        required: false
        suboptions:
            name:
                description: Name of the backup
                type: str
            uid:
                description: UID of the backup
                type: str
    rancher_project_mapping:
        description: Rancher project mapping
        type: dict
        required: false
        suboptions:
            key:
                description: Source rancher project
                type: str
            value:
                description: Destination rancher project
                type: str
    rancher_project_name_mapping:
        description: Rancher project name mapping
        type: dict
        required: false
        suboptions:
            key:
                description: Source rancher project name
                type: str
            value:
                description: Destination rancher project name
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
    namespace_mapping:
        description: Mapping of source and destination namespaces during restore
        type: dict
        required: false
    storage_class_mapping:
        description: Mapping of source and destination storage classes during restore
        type: dict
        required: false
    cluster:
        description: Name or UID of the cluster
        type: str
        required: false
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true

requirements:
    - python >= 3.9
    - requests

notes:
    - "Operation-specific required parameters:"
    - "CREATE: name, backup_ref, cluster_ref"
    - "DELETE: name, org_id"
    - "INSPECT_ONE: name, org_id"
    - "INSPECT_ALL: org_id"
'''

# Configure logging
# Configure the logger
logging.basicConfig(
    level=logging.DEBUG,  # Ensure DEBUG level logs are captured
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()  # Stream to console
    ]
)
logger = logging.getLogger('restore')
logger.addHandler(logging.NullHandler())

# Avoid duplicate logs
logger.propagate = False

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

def enumerate_restores(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all restores"""
    # First, let's log the input parameters for debugging
    logger.debug(f"Enumerate parameters module: {module.params}")

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

    if module.params.get('owners'):
        params['enumerate_options.owners'] = module.params['owners']

    # Add backup_object_type if provided
    if module.params.get('backup_object_type'):
        params['enumerate_options.backup_object_type'] = module.params['backup_object_type']

    if module.params.get('status'):
        params['enumerate_options.status'] = module.params['status']
        
    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}
    
    logger.debug(f"Enumerate parameters logger: {module.params}")

    try:
        response = client.make_request(
            'GET',
            f"v1/restore/{module.params['org_id']}",
            params=params
        )

        # Log the response for debugging
        logger.debug(f"Received response: {response}")

        return response.get('restores', [])
    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to enumerate restores: {error_msg}")

def inspect_backup(module: AnsibleModule, client: PXBackupClient, backup: Any) -> Dict[str, Any]:
    """Get details of a specific backup"""
    try:
        # Validate input
        backup_name = backup.get('name')
        backup_uid = backup.get('uid')
        
        if not backup_name:
            module.fail_json(msg="Backup 'name' is required but not provided.")
        if not backup_uid:
            module.fail_json(msg="Backup 'uid' is required but not provided.")
        
        # Build request params
        params = {"uid": backup_uid}  # Include the UID in the request parameters

        # Make the API request
        response = client.make_request(
            'GET',
            f"v1/backup/{module.params['org_id']}/{backup_name}",
            params=params
        )
        
        # Log response for debugging
        module.debug(f"API Response: {response}")

        if not response:
            module.fail_json(msg=f"No backup found with name {backup_name} and uid {backup_uid}")

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

def build_restore_request(params: Dict[str, Any], module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """
    Build restore request object
    """
    # Create base metadata structure
    metadata = {
        "name": params.get('name'),
        "org_id": params.get('org_id'),
        "uid": params.get('uid')  # Include UID for updates
    }

    # Create request structure
    request = {
        "metadata": metadata
    }

    # For other operations, include additional fields
    request.update({
        "backup_ref": params.get('backup_ref', {}),
        "cluster_ref": params.get('cluster_ref', {}),
        "include_resources": params.get('include_resources', []),
        "storage_class_mapping": params.get('storage_class_mapping', {}),
        "rancher_project_mapping": params.get('rancher_project_mapping', {}),
        "rancher_project_name_mapping": params.get('rancher_project_name_mapping', {})
    })
    
    # Handle namespace mapping if not provided
    if not params.get('namespace_mapping'):
        if not params.get('backup_ref') or not params['backup_ref'].get('name'):
            module.fail_json(msg="Missing 'backup_ref' or 'backup_ref.name' for namespace mapping resolution.")

        backup = {
            "name": params['backup_ref']['name'],
            "uid": params['backup_ref']['uid'],
        }
        logger.debug(f"backup params are", backup)
        # Call inspect_backup to retrieve backup details
        try:
            backup_details = inspect_backup(module, client, backup)
        except Exception as e:
            module.fail_json(msg=f"Error inspecting backup for namespace mapping: {str(e)}")

        backup_info = backup_details.get('backup', {}).get('backup_info', {})
        # Get namespaces from the backup info
        source_namespaces = backup_info.get('namespaces', [])

        # Add namespace mapping only if exactly one namespace is found
        if len(source_namespaces) == 1:
            namespace_mapping = {
                source_namespaces[0]: source_namespaces[0]
            }
            request.update({"namespace_mapping": namespace_mapping})
        else:
            module.fail_json(msg=f"Unable to resolve namespace mapping: More than one source namespace found.{backup_details}")
    
    else:
        request.update({"namespace_mapping": params.get('namespace_mapping')})
    
    if params.get('backup_ref'):
        request['backup'] = params['backup_ref']['name']
    
    if params.get('cluster'):
        request['cluster'] = params['cluster']
    
    if params.get('replace_policy'):
        replace_policy_map = {
            'Invalid': 0,
            'Retain': 1,
            'Delete': 2
        }
        request['replace_policy'] = replace_policy_map.get(params['replace_policy'], 0)

    return request

def process_restore_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process restore API response into standardized format
    
    Args:
        response: Raw API response dictionary
        
    Returns:
        Dict containing processed restore information with all available fields
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

    # Process restore_info if present
    if 'restore_info' in response:
        result['restore_info'] = {}
        restore_info = response['restore_info']
        # Process all fields in restore_info
        for key, value in restore_info.items():
            if value is not None:  # Only include non-None values
                # Handle different default types
                if isinstance(value, dict):
                    result['restore_info'][key] = value or {}
                elif isinstance(value, list):
                    result['restore_info'][key] = value or []
                elif isinstance(value, bool):
                    result['restore_info'][key] = value
                else:
                    result['restore_info'][key] = value

    return result

def create_restore(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new restore"""
    try:
        params = dict(module.params)
        
        # Build request
        backup_request = build_restore_request(params, module, client)
        
        # Make API request
        response = client.make_request(
            method='POST',
            endpoint='v1/restore',
            data=backup_request
        )

        # Process response using the common handler
        result = process_restore_response(response)
        return result, True
        
    except Exception as e:
        error_msg = str(e)
        if hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {getattr(e.response, 'text', 'No response text')}"
        module.fail_json(msg=f"Failed to create restore: {error_msg}")

def delete_restore(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a restore"""
    try:
        # Build delete request parameters
        params = {}
        
        # Add cluster information
        if module.params.get('cluster_ref'):
            if module.params['cluster_ref'].get('name'):
                params['cluster'] = module.params['cluster_ref']['name']
            if module.params['cluster_ref'].get('uid'):
                params['cluster_uid'] = module.params['cluster_ref']['uid']
        
        response = client.make_request(
            'DELETE',
            f"v1/restore/{module.params['org_id']}/{module.params['name']}",
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
        module.fail_json(msg=f"Failed to delete restore: {error_msg}")

def inspect_restore(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific restore"""
    try:


        response = client.make_request(
            'GET',
            f"v1/restore/{module.params['org_id']}/{module.params['name']}",
        )
        
        # Log response for debugging
        module.debug(f"API Response: {response}")

        if not response:
            module.fail_json(msg=f"No restores found with name {module.params['name']}")

        # Return the processed response
        return {
            'restore': response.get('restore', {}),
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
            restore, changed = create_restore(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'restore': restore},
                message="Restore created successfully"
            )

        elif operation == 'INSPECT_ALL':
            restores = enumerate_restores(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'restores': restores},
                message=f"Found {len(restores)} restores"
            )

        elif operation == 'INSPECT_ONE':
            result = inspect_restore(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data=result,
                message="Successfully retrieved backup details"
            )

        elif operation == 'DELETE':
            restore, changed = delete_restore(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'restore': restore},
                message="Restore deleted successfully"
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
                'DELETE',
                'INSPECT_ONE',
                'INSPECT_ALL',
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        cluster=dict(type='str', required=False),
        
        # Backup reference
        backup_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        ),

        rancher_project_name_mapping=dict(
            type='dict',
            required=False,
            options=dict(
                key=dict(type='str', required=True),
                value=dict(type='str', required=True)
            )
        ),

        rancher_project_mapping=dict(
            type='dict',
            required=False,
            options=dict(
                key=dict(type='str', required=True),
                value=dict(type='str', required=True)
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

        # Restore configuration
        namespace_mapping=dict(
            type='dict',
            required=False,
        ),
        
        storage_class_mapping=dict(
            type='dict',
            required=False
        ),
        
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
        backup_object_type=dict(
            type='str',
            required=False,
            choices=['Invalid', 'All', 'VirtualMachine']
        ),
        replace_policy = dict(
            type='str',
            required=False,
            choices=['Invalid', 'Retain', 'Delete']
        ),

        # Enumerate options
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
        result={},
        results=[],
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'backup_ref', 'cluster_ref'],

        'DELETE': ['name', 'org_id'],

        'INSPECT_ONE': ['name', 'org_id'],

        'INSPECT_ALL': ['org_id'],
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('operation', 'CREATE', [
             'name', 'backup_ref', 'cluster_ref']),

            ('operation', 'DELETE', ['name', 'org_id']),

            ('operation', 'INSPECT_ONE', ['name', 'org_id']),

            ('operation', 'INSPECT_ALL', ['org_id']),
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