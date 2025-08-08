#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Location Management Module

This Ansible module manages backup locations in PX-Backup, providing operations for:
- Creating backup locations (S3, Azure, Google, NFS)
- Updating existing backup locations
- Deleting backup locations
- Validating backup locations
- Inspecting backup locations (single or all)
- Managing backup location ownership

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
module: backup_location

short_description: Manage backup locations in PX-Backup

version_added: "2.8.4"

description: 
    - Manage backup locations in PX-Backup using different operations
    - Supports CRUD operations, validation, and ownership management
    - Supports S3, Azure, Google and NFS backup locations
    - Provides both single location and bulk inspection capabilities
    - Requires cloud credentials

options:
    operation:
        description:
            - Operation to perform on the backup location
            - " - CREATE: creates a new backup location"
            - " - UPDATE: modifies an existing backup location"
            - " - DELETE: removes a backup location"
            - " - VALIDATE: validates a backup location configuration"
            - " - INSPECT_ONE: retrieves details of a specific backup location"
            - " - INSPECT_ALL: lists all backup locations"
            - " - UPDATE_OWNERSHIP: updates ownership settings of a backup location"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'VALIDATE', 'INSPECT_ONE', 'INSPECT_ALL', 'UPDATE_OWNERSHIP']
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
            - Name of the backup location
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description: 
            - Unique identifier of the backup location
            - Required for UPDATE, DELETE, VALIDATE, INSPECT_ONE, and UPDATE_OWNERSHIP operations
        required: false
        type: str
    location_type:
        description: 
            - Type of backup location
            - Required for CREATE and UPDATE operations
        required: false
        choices: ['S3', 'Azure', 'Google', 'NFS']
        type: str
    path:
        description: 
            - Path/bucket name for the backup location
            - Required for CREATE and UPDATE operations
        required: false
        type: str
    encryption_key:
        description: Encryption key for backup data
        required: false
        type: str
    cloud_credential_name:
        description: Name of cloud credential to use
        required: false
        type: str
    cloud_credential_uid:
        description: UID of cloud credential to use
        required: false
        type: str
    validate_cloud_credential:
        description: Whether to validate cloud credentials
        required: false
        type: bool
        default: true
    object_lock_enabled:
        description: Enable object lock for S3 backup locations
        required: false
        type: bool
        default: false
    s3_config:
        description: Configuration for S3 backup locations
        required: false
        type: dict
        suboptions:
            endpoint:
                description: S3 endpoint URL
                type: str
            region:
                description: S3 region
                type: str
            disable_ssl:
                description: Disable SSL verification
                type: bool
            disable_path_style:
                description: Disable path style access
                type: bool
            storage_class:
                description: S3 storage class
                type: str
            sse_type:
                description: Server-side encryption type
                choices: ['Invalid', 'SSE_S3', 'SSE_KMS']
                type: str
            azure_environment:
                description: Azure environment configuration
                type: dict
                suboptions:
                    type:
                        description: Azure environment type
                        choices: ['Invalid', 'AZURE_GLOBAL', 'AZURE_CHINA']
                        type: str
            azure_resource_group_name:
                description: Azure resource group name
                type: str
    nfs_config:
        description: Configuration for NFS backup locations
        required: false
        type: dict
        suboptions:
            server_addr:
                description: NFS server address
                type: str
            sub_path:
                description: Sub path on NFS share
                type: str
            mount_option:
                description: NFS mount options
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
        description: 
            - Ownership configuration for the backup location
            - Required for UPDATE_OWNERSHIP operation
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
    include_secrets:
        description: Include sensitive information in response
        type: bool
        default: false

requirements:
    - python >= 3.9
    - requests

'''

EXAMPLES = r'''
# Create an S3 backup location
- name: Create S3 backup location
  backup_location:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-s3-backup"
    org_id: "default"
    location_type: "S3"
    path: "my-bucket"
    s3_config:
      endpoint: "s3.amazonaws.com"
      region: "us-east-1"
      disable_ssl: false
      disable_path_style: false

# List all backup locations
- name: List all backup locations
  backup_location:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"

# Delete a backup location
- name: Delete backup location
  backup_location:
    operation: DELETE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-s3-backup"
    org_id: "default"
    uid: "backup-location-uid"
'''

RETURN = r'''
backup_location:
    description: Details of the backup location for single-item operations
    type: dict
    returned: success
    sample: {
        "metadata": {
            "name": "prod-s3-backup",
            "org_id": "default",
            "uid": "123-456"
        },
        "backup_location": {
            "type": "S3",
            "path": "my-bucket"
        }
    }
backup_locations:
    description: List of backup locations for INSPECT_ALL operation
    type: list
    returned: when operation is INSPECT_ALL
    sample: [
        {
            "metadata": {
                "name": "backup1",
                "org_id": "default"
            }
        },
        {
            "metadata": {
                "name": "backup2",
                "org_id": "default"
            }
        }
    ]
message:
    description: Operation result message
    type: str
    returned: always
changed:
    description: Whether the operation changed the backup location
    type: bool
    returned: always
'''

# Configure logging
logger = logging.getLogger('backup_location')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class BackupLocationError(Exception):
    """Base exception for backup location operations"""
    pass

class ValidationError(BackupLocationError):
    """Raised when validation fails"""
    pass

class APIError(BackupLocationError):
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
    

def create_backup_location(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new backup location"""
    try:
        # Get module parameters directly
        params = dict(module.params)
        backup_location_request = build_backup_location_request(params)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/backuplocation',
            data=backup_location_request
        )
        
        # Return the response
        return response, True
            
        
    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to create backup location: {error_msg}")

def update_backup_location(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing backup location"""
    try:
        # Build request using module.params
        params = dict(module.params)
        backup_location_request = build_backup_location_request(params)
        backup_location_request['metadata']['uid'] = params['uid']
        
        # Get current state for comparison
        current = inspect_backup_location(module, client)
        if not needs_update(current, backup_location_request):
            return current, False
            
        # Make update request
        response = client.make_request(
            method='PUT',
            endpoint='v1/backuplocation',
            data=backup_location_request
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update backup location: {str(e)}")

def update_ownership(module, client):
    """Update ownership of a backup location"""
    ownership_request = {
        "org_id": module.params['org_id'],
        "name": module.params['name'],
        "ownership": module.params['ownership'],
        "uid": module.params['uid']
    }
    
    try:
        response = client.make_request('PUT', 'v1/backuplocation/updateownership', ownership_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update backup location ownership: {str(e)}")

def validate_backup_location(module, client):
    """Validate a backup location"""
    validate_request = {
        "org_id": module.params['org_id'],
        "name": module.params['name'],
        "uid": module.params['uid']
    }
    
    try:
        response = client.make_request('POST', 'v1/backuplocation/validate', validate_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to validate backup location: {str(e)}")

def enumerate_backup_locations(module, client):
    """List all backup locations"""
    params = {
        'labels': module.params.get('labels', {}),
        'include_secrets': module.params.get('include_secrets', False),
        'include_validation_state': True
    }
    
    if module.params.get('cloud_credential_name') and module.params.get('cloud_credential_uid'):
        params['cloud_credential_ref'] = {
            'name': module.params['cloud_credential_name'],
            'uid': module.params['cloud_credential_uid']
        }
    
    try:
        response = client.make_request('GET', f"v1/backuplocation/{module.params['org_id']}", params=params)
        return response.get('backup_locations', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate backup locations: {str(e)}")

def inspect_backup_location(module, client):
    """Get details of a specific backup location"""
    params = {
        'include_secrets': module.params.get('include_secrets', False)
    }
    
    try:
        response = client.make_request(
            'GET',
            f"v1/backuplocation/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}",
            params=params
        )
        return response
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect backup location: {str(e)}")

def delete_backup_location(module, client):
    """Delete a backup location"""
    try:
        response = client.make_request(
            'DELETE',
            f"v1/backuplocation/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}",
            params={}
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete backup location: {str(e)}")


def build_backup_location_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build backup location request object
    
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
        "backup_location": {
            "type": params.get('location_type'),
            "path": params.get('path'),
            "encryption_key": params.get('encryption_key', ''),
            "validate_cloud_credential": params.get('validate_cloud_credential', True),
            "object_lock_enabled": params.get('object_lock_enabled', False)
        }
    }

    # Add optional configurations safely
    if params.get('labels'):
        request['metadata']['labels'] = params['labels']
        
    if params.get('ownership'):
        request['metadata']['ownership'] = params['ownership']

    # Construct cloud_credential_ref dynamically if the keys are provided
    if params.get('cloud_credential_ref'):
        request['backup_location']['cloud_credential_ref'] = {
            "name": params['cloud_credential_ref']['cloud_credential_name'],
            "uid": params['cloud_credential_ref']['cloud_credential_uid']
    }

    # Add location-specific configuration based on type
    location_type = params.get('location_type')
    
    if location_type == 'S3' and params.get('s3_config'):
        s3_config = {}
        s3_fields = [
            'endpoint', 'region', 'disable_ssl', 'disable_path_style', 
            'storage_class', 'sse_type', 'azure_environment',
            'azure_resource_group_name'
        ]
        for key in s3_fields:
            if params['s3_config'].get(key) is not None:
                s3_config[key] = params['s3_config'][key]
        if s3_config:
            request['backup_location']['s3_config'] = s3_config
            
    elif location_type == 'Azure' and params.get('azure_config'):
        azure_config = params.get('azure_config', {})
        azure_environment = azure_config.get('azure_environment', 'AZURE_GLOBAL')  # Use default if key is missing

        # Include azure_environment in the request payload
        request['backup_location']['s3_config'] = {
            "azure_environment": {
                "type": azure_environment
            }
        }


    elif location_type == 'NFS' and params.get('nfs_config'):
        nfs_config = {}
        nfs_fields = ['server_addr', 'sub_path', 'mount_option']
        for key in nfs_fields:
            if params['nfs_config'].get(key) is not None:
                nfs_config[key] = params['nfs_config'][key]
        if nfs_config:
            request['backup_location']['nfs_config'] = nfs_config

    return request

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
    return f"Failed to {operation.lower()} backup location: {error_msg}"

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
            backup_location, changed = create_backup_location(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'backup_location': backup_location},
                message="Backup location created successfully"
            )
        
        elif operation == 'VALIDATE':
            backup_location, changed = validate_backup_location(module, client)
            return OperationResult(
            success=True,
            changed=changed,
            data={'backup_location': backup_location},
            message="Backup location validated successfully"
            )
        
        elif operation == 'INSPECT_ALL':
            backup_locations = enumerate_backup_locations(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'backup_locations': backup_locations},
                message=f"Found {len(backup_locations)} backup locations"
            )

        elif operation == 'INSPECT_ONE':
            backup_location = inspect_backup_location(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'backup_location': backup_location},
                message="Successfully retrieved backup location details"
            )

        elif operation == 'UPDATE':
            backup_location, changed = update_backup_location(module, client)
            return OperationResult(
            success=True,
            changed=changed,
            data={'backup_location': backup_location},
            message="Backup location updated successfully"
            )

        elif operation == 'UPDATE_OWNERSHIP':
            backup_location, changed = update_ownership(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'backup_location': backup_location},
                message="Backup location ownership updated successfully"
            )
        
        elif operation == 'DELETE':
            backup_location, changed = delete_backup_location(module, client)
            return OperationResult(
            success=True,
            changed=changed,
            data={'backup_location': backup_location},
            message="Backup location deleted successfully"
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
                'VALIDATE',
                'INSPECT_ONE',
                'INSPECT_ALL',
                'UPDATE_OWNERSHIP'
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        location_type=dict(type='str', required=False, choices=['S3', 'Azure', 'Google', 'NFS']),
        path=dict(type='str', required=False),
        encryption_key=dict(type='str', required=False, no_log=True),
        validate_cloud_credential=dict(type='bool', required=False, default=True),
        object_lock_enabled=dict(type='bool', required=False, default=False),
        cloud_credential_ref=dict(
            type='dict',
            required=False,
            options=dict(
                cloud_credential_name=dict(type='str', required=True),
                cloud_credential_uid=dict(type='str', required=True)
            )
        ),
        
        # S3 Configuration
        s3_config=dict(
            type='dict',
            required=False,
            options=dict(
                endpoint=dict(type='str'),
                region=dict(type='str'),
                disable_ssl=dict(type='bool'),
                disable_path_style=dict(type='bool'),
                storage_class=dict(type='str'),
                sse_type=dict(type='str', choices=['Invalid', 'SSE_S3', 'SSE_KMS']),
                azure_environment=dict(
                    type='dict',
                    options=dict(
                        type=dict(type='str', choices=['Invalid', 'AZURE_GLOBAL', 'AZURE_CHINA'])
                    )
                ),
                azure_resource_group_name=dict(type='str')
            )
        ),
        
        # Azure Configuration
        azure_config=dict(
            type='dict',
            required=False,
            options=dict(
                account_name=dict(type='str'),
                account_key=dict(type='str', no_log=True),
                client_secret=dict(type='str', no_log=True),
                client_id=dict(type='str', no_log=True),
                tenant_id=dict(type='str', no_log=True),
                subscription_id=dict(type='str', no_log=True),
                azure_environment=dict(type='str', no_log=True)
            )
        ),
        
        # Google Configuration
        google_config=dict(
            type='dict',
            required=False,
            options=dict(
                project_id=dict(type='str'),
                json_key=dict(type='str', no_log=True)
            )
        ),
        
        # NFS Configuration
        nfs_config=dict(
            type='dict',
            required=False,
            options=dict(
                server_addr=dict(type='str'),
                sub_path=dict(type='str'),
                mount_option=dict(type='str')
            )
        ),
        
        validate_certs=dict(type='bool', default=True),
        labels=dict(type='dict', required=False),
        ownership=dict(type='dict', required=False),
        include_secrets=dict(type='bool', default=False)
    )

    result = dict(
        changed=False,
        backup_location={},
        backup_locations=[],
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'location_type', 'path'],
        'UPDATE': ['name', 'uid', 'location_type', 'path'],
        'DELETE': ['name', 'uid'],
        'VALIDATE': ['name', 'uid'],
        'INSPECT_ONE': ['name', 'uid'],
        'INSPECT_ALL': ['org_id'],
        'UPDATE_OWNERSHIP': ['name', 'uid', 'ownership']
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('location_type', 'S3', ['s3_config']),
            ('location_type', 'Azure', ['azure_config']),
            ('location_type', 'NFS', ['nfs_config'])
        ]
    )

    try:
        # Validate operation parameters
        operation = module.params['operation']
        validate_params(module.params, operation, operation_requirements[operation])

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