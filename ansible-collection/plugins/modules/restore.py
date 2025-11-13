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

version_added: "2.10.0"

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
        description: List of specific resources to include in restore
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
            gvk:
                description: Resource GVK in format 'group/version/kind' or 'version/kind' for core resources
                type: str
                required: true
    exclude_resources:
        description: List of specific resources to exclude from restore
        type: list
        elements: dict
        required: false
        version_added: '2.11.0'
        suboptions:
            name:
                description: Resource name
                type: str
            namespace:
                description: Resource namespace
                type: str
            gvk:
                description: Resource GVK in format 'group/version/kind' or 'version/kind' for core resources
                type: str
                required: true
    filter:
        description: Advanced filtering options for restore operations
        type: dict
        required: false
        version_added: '2.11.0'
        suboptions:
            namespace_filter:
                description: Namespace-based filtering options
                type: dict
                required: false
                suboptions:
                    namespace_name_pattern:
                        description: Pattern to match namespace names
                        type: str
                        required: false
                    include_namespaces:
                        description: List of namespaces to include
                        type: list
                        elements: str
                        required: false
                    exclude_namespaces:
                        description: List of namespaces to exclude
                        type: list
                        elements: str
                        required: false
                    include_resources:
                        description: List of specific resources to include
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
                            gvk:
                                description: Resource GVK in format 'group/version/kind' or 'version/kind' for core resources
                                type: str
                                required: true
                    exclude_resources:
                        description: List of specific resources to exclude
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
                            gvk:
                                description: Resource GVK in format 'group/version/kind' or 'version/kind' for core resources
                                type: str
                                required: true
                    gvks:
                        description: Group-Version-Kind specifications for filtering
                        type: list
                        elements: str
                        required: false
                    resource_name_pattern:
                        description: Pattern to match resource names
                        type: str
                        required: false
            virtual_machine_filter:
                description: Virtual machine specific filtering options
                type: dict
                required: false
                suboptions:
                    vm_name_pattern:
                        description: Pattern to match virtual machine names (e.g., "*" for all, "pxb-" or any valid regex)
                        type: str
                        required: false
                    os_name:
                        description: List of OS names to include for filtering
                        type: list
                        elements: str
                        required: false
                    include_vms:
                        description: List of specific VMs to include for filtering
                        type: list
                        elements: dict
                        required: false
                        suboptions:
                            name:
                                description: Virtual machine name
                                type: str
                                required: true
                            namespace:
                                description: Virtual machine namespace
                                type: str
                                required: false
                    exclude_vms:
                        description: List of specific VMs to exclude from filtering
                        type: list
                        elements: dict
                        required: false
                        suboptions:
                            name:
                                description: Virtual machine name
                                type: str
                                required: true
                            namespace:
                                description: Virtual machine namespace
                                type: str
                                required: false
    namespace_mapping:
        description:
            - Mapping of source and destination namespaces during restore
            - Set namespace_mapping equal if is_sfr is set to true
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
    is_sfr:
        description:
            - Set to true for VirtualMachine file level restore
            - Enables restoration of specific files/directories from VM backups
            - Requires file_level_restore_info when set to true
        required: false
        type: bool
        default: false
        version_added: "2.11.0"
    file_level_restore_info:
        description: File level restore configuration for VM backups
        type: dict
        required: false
        version_added: "2.11.0"
        suboptions:
            virtual_machine_name:
                description: Name of the VM to restore files to
                type: str
                required: true
            volume_name:
                description: Source PVC name to restore files from
                type: str
                required: true
            restore_files:
                description: List of files/directories to restore
                type: list
                elements: dict
                required: true
                suboptions:
                    source_path:
                        description: Relative path to file/dir in volume
                        type: str
                        required: true
                    destination_path:
                        description: Absolute destination path (optional, defaults to source path)
                        type: str
                        required: false
                    is_dir:
                        description: True if source path is directory
                        type: bool
                        default: false
                    partition_info:
                        description: Partition info if volume is partitioned (e.g., vda1, sda14)
                        type: str
                        required: false
    sort_option:
        description: Sorting configuration for restore enumeration
        type: dict
        required: false
        version_added: '2.11.0'
        suboptions:
            sort_by:
                description: Field to sort by
                type: str
                choices: ['CreationTimestamp', 'Name', 'ClusterName', 'Size', 'RestoreBackupName', 'LastUpdateTimestamp']
                default: 'CreationTimestamp'
            sort_order:
                description: Sort order
                type: str
                choices: ['Ascending', 'Descending']
                default: 'Descending'
    virtual_machine_restore_options:
        description: Virtual machine specific restore options
        type: dict
        required: false
        version_added: '2.11.0'
        suboptions:
            skip_mac_masking:
                description: Skip MAC address masking while restoring virtual machines
                type: bool
                default: false
            skip_vm_restart:
                description: Skip VM restart during virtual machine restore
                type: bool
                default: false
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

requirements:
    - python >= 3.9
    - requests

notes:
    - "Operation-specific required parameters:"
    - "CREATE: name, backup_ref, cluster_ref"
    - "CREATE (SFR): name, backup_ref, cluster_ref, is_sfr=true, file_level_restore_info"
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


def validate_sfr_params(params: Dict[str, Any]) -> None:
    """
    Validate SFR-specific parameters

    Args:
        params: Module parameters

    Raises:
        ValidationError: If SFR validation fails
    """
    if params.get('is_sfr'):
        if not params.get('file_level_restore_info'):
            raise ValidationError("file_level_restore_info is required when is_sfr=true")

        sfr_info = params['file_level_restore_info']
        required_fields = ['virtual_machine_name', 'volume_name', 'restore_files']
        for field in required_fields:
            if not sfr_info.get(field):
                raise ValidationError(f"file_level_restore_info.{field} is required for SFR")

        # Validate restore_files array
        restore_files = sfr_info.get('restore_files', [])
        if not isinstance(restore_files, list) or len(restore_files) == 0:
            raise ValidationError("file_level_restore_info.restore_files must be a non-empty list")

        for i, file_info in enumerate(restore_files):
            if not file_info.get('source_path'):
                raise ValidationError(f"restore_files[{i}].source_path is required")


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

    # Add sorting options if provided
    if module.params.get('sort_option'):
        sort_option = module.params['sort_option']
        params['enumerate_options.sort_option.sortBy.type'] = sort_option.get('sort_by', 'CreationTimestamp')
        params['enumerate_options.sort_option.sortOrder.type'] = sort_option.get('sort_order', 'Descending')

    # Add new filtration features
    if module.params.get('vm_volume_name'):
        params['enumerate_options.vm_volume_name'] = module.params['vm_volume_name']

    if module.params.get('exclude_failed_resource') is not None:
        params['enumerate_options.exclude_failed_resource'] = module.params['exclude_failed_resource']

    # Add resource_info filter
    if module.params.get('resource_info'):
        resource_info = module.params['resource_info']
        if resource_info.get('name'):
            params['enumerate_options.resource_info.name'] = resource_info['name']
        if resource_info.get('namespace'):
            params['enumerate_options.resource_info.namespace'] = resource_info['namespace']
        if resource_info.get('group'):
            params['enumerate_options.resource_info.group'] = resource_info['group']
        if resource_info.get('kind'):
            params['enumerate_options.resource_info.kind'] = resource_info['kind']
        if resource_info.get('version'):
            params['enumerate_options.resource_info.version'] = resource_info['version']

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
        
        if not backup_name:
            module.fail_json(msg="Backup 'name' is required but not provided.")
        
        # Build request params
        params = {"uid": backup.get('uid', '')}  # Include the UID in the request parameters

        # Make the API request
        response = client.make_request(
            'GET',
            f"v1/backup/{module.params['org_id']}/{backup_name}",
            params=params
        )
        
        # Log response for debugging
        module.debug(f"API Response: {response}")

        if not response:
            module.fail_json(msg=f"No backup found with name {backup_name}")

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
        "uid": params.get('uid', '')  # Include UID for updates
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

    # Add enhanced parameters for target namespace selection
    if params.get('target_namespace_prefix'):
        request["target_namespace_prefix"] = params['target_namespace_prefix']

    if params.get('use_source_as_target_namespace'):
        request["use_source_as_target_namespace"] = params['use_source_as_target_namespace']
    
    # Add enhanced parameters for resource type selection
    if params.get('include_optional_resource_types'):
        request["include_optional_resource_types"] = params['include_optional_resource_types']

    if params.get('backup_object_type'):
        request["backup_object_type"] = params['backup_object_type']

    # Add new exclude_resources parameter
    if params.get('exclude_resources'):
        request["exclude_resources"] = params['exclude_resources']

    # Add filter parameter with enhanced VM filtering
    filter_obj = {}

    # Add namespace filter if provided
    if params.get('namespace_filter'):
        filter_obj["namespace_filter"] = params['namespace_filter']

    # Add enhanced virtual machine filter if provided
    if params.get('virtual_machine_filter'):
        vm_filter = {}
        vm_filter_params = params['virtual_machine_filter']

        if vm_filter_params.get('vm_name_pattern'):
            vm_filter["vm_name_pattern"] = vm_filter_params['vm_name_pattern']

        if vm_filter_params.get('os_name'):
            vm_filter["os_name"] = vm_filter_params['os_name']

        if vm_filter_params.get('include_vms'):
            vm_filter["include_vms"] = vm_filter_params['include_vms']

        if vm_filter_params.get('exclude_vms'):
            vm_filter["exclude_vms"] = vm_filter_params['exclude_vms']

        if vm_filter:
            filter_obj["virtual_machine_filter"] = vm_filter

    # Add legacy filter parameter for backward compatibility
    if params.get('filter'):
        filter_obj.update(params['filter'])

    if filter_obj:
        request["filter"] = filter_obj

    # Add virtual machine restore options
    if params.get('virtual_machine_restore_options'):
        request["virtual_machine_restore_options"] = params['virtual_machine_restore_options']

    if params.get('namespace_mapping'):
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

    # Add SFR support
    if params.get('is_sfr'):
        request['is_sfr'] = params['is_sfr']
        if params.get('file_level_restore_info'):
            request['file_level_restore_info'] = params['file_level_restore_info']

    # Add backup_object_type if provided
    if params.get('backup_object_type'):
        backup_object_type_map = {
            'Invalid': 0,
            'All': 1,
            'VirtualMachine': 2
        }
        request['backup_object_type'] = backup_object_type_map.get(params['backup_object_type'], 0)

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
    
    # Check if response is wrapped in 'restore' key
    if 'restore' in response:
        restore_data = response['restore']
    else:
        restore_data = response
    
    # Process metadata if present
    if 'metadata' in restore_data:
        result['metadata'] = {}
        metadata = restore_data['metadata']
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
    if 'restore_info' in restore_data:
        result['restore_info'] = {}
        restore_info = restore_data['restore_info']
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
                elif key == 'is_sfr':
                    result['restore_info'][key] = value
                elif key == 'file_level_restore_info':
                    result['restore_info'][key] = value or {}
                else:
                    result['restore_info'][key] = value

    return result

def create_restore(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new restore"""
    try:
        params = dict(module.params)
        validate_sfr_params(params)
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
            'message': "Successfully retrieved restore details",
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
        module.fail_json(msg=f"Failed to inspect restore: {error_msg}")

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
                uid=dict(type='str', required=False)
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

        # Namespace target options (mutually exclusive)
        target_namespace_prefix=dict(
            type='str',
            required=False
        ),

        use_source_as_target_namespace=dict(
            type='bool',
            required=False
        ),

        storage_class_mapping=dict(
            type='dict',
            required=False
        ),

        # Optional resource types
        include_optional_resource_types=dict(
            type='list',
            elements='str',
            required=False
        ),
        
        include_resources=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                namespace=dict(type='str', required=False),
                gvk=dict(type='str', required=True)
            )
        ),
        exclude_resources=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                namespace=dict(type='str', required=False),
                gvk=dict(type='str', required=True)
            )
        ),
        filter=dict(
            type='dict',
            required=False,
            options=dict(
                namespace_filter=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        namespace_name_pattern=dict(type='str', required=False),
                        include_namespaces=dict(type='list', elements='str', required=False),
                        exclude_namespaces=dict(type='list', elements='str', required=False),
                        include_resources=dict(
                            type='list',
                            elements='dict',
                            required=False,
                            options=dict(
                                name=dict(type='str', required=True),
                                namespace=dict(type='str', required=False),
                                gvk=dict(type='str', required=True)
                            )
                        ),
                        exclude_resources=dict(
                            type='list',
                            elements='dict',
                            required=False,
                            options=dict(
                                name=dict(type='str', required=True),
                                namespace=dict(type='str', required=False),
                                gvk=dict(type='str', required=True)
                            )
                        ),
                        gvks=dict(
                            type='list',
                            elements='str',
                            required=False,
                            description='List of GVK strings in format "group/version/kind" (e.g., "apps/v1/Deployment")'
                        ),
                        resource_name_pattern=dict(type='str', required=False)
                    )
                ),
                virtual_machine_filter=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        vm_name_pattern=dict(type='str', required=False),
                        os_name=dict(type='list', elements='str', required=False),
                        include_vms=dict(
                            type='list',
                            elements='dict',
                            required=False,
                            options=dict(
                                name=dict(type='str', required=True),
                                namespace=dict(type='str', required=False),
                                os_name=dict(type='str', required=False)
                            )
                        ),
                        exclude_vms=dict(
                            type='list',
                            elements='dict',
                            required=False,
                            options=dict(
                                name=dict(type='str', required=True),
                                namespace=dict(type='str', required=False),
                                os_name=dict(type='str', required=False)
                            )
                        )
                    )
                )
            )
        ),
        backup_object_type=dict(
            type='dict',
            required=False,
            options=dict(
                type=dict(
                    type='str',
                    required=True,
                    choices=['Invalid', 'All', 'VirtualMachine']
                )
            )
        ),
        replace_policy = dict(
            type='str',
            required=False,
            choices=['Invalid', 'Retain', 'Delete']
        ),

        # Single File Restore (SFR) support
        is_sfr=dict(type='bool', required=False, default=False),
        file_level_restore_info=dict(
            type='dict',
            required=False,
            options=dict(
                virtual_machine_name=dict(type='str', required=True),
                volume_name=dict(type='str', required=True),
                restore_files=dict(
                    type='list',
                    elements='dict',
                    required=True,
                    options=dict(
                        source_path=dict(type='str', required=True),
                        destination_path=dict(type='str', required=False),
                        is_dir=dict(type='bool', required=False, default=False),
                        partition_info=dict(type='str', required=False)
                    )
                )
            )
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

        # Sorting options
        sort_option=dict(type='dict', required=False, options=dict(
            sort_by=dict(
                type='str',
                choices=['CreationTimestamp', 'Name', 'ClusterName', 'Size', 'RestoreBackupName', 'LastUpdateTimestamp'],
                default='CreationTimestamp'
            ),
            sort_order=dict(
                type='str',
                choices=['Ascending', 'Descending'],
                default='Descending'
            )
        )),

        # Virtual machine restore options
        virtual_machine_restore_options=dict(
            type='dict',
            required=False,
            options=dict(
                skip_mac_masking=dict(type='bool', default=False),
                skip_vm_restart=dict(type='bool', default=False)
            )
        ),

        # New filtration features
        vm_volume_name=dict(
            type='str',
            required=False,
            description='Filter VM that matches the resource_info and has volume vm_volume_name attached to it'
        ),
        exclude_failed_resource=dict(
            type='bool',
            required=False,
            default=False,
            description='Filter to exclude failed resources while enumerating objects'
        ),
        resource_info=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=False),
                namespace=dict(type='str', required=False),
                group=dict(type='str', required=False),
                kind=dict(type='str', required=False),
                version=dict(type='str', required=False)
            ),
            description='Filter to use resource name and namespace. Any restore that contains the resource will be returned'
        ),

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
        )
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

            ('is_sfr', True, ['file_level_restore_info']),
        ]
    )

    try:
        # Validate operation parameters
        operation = module.params['operation']
        validate_params(module.params, operation,
                        operation_requirements[operation])



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