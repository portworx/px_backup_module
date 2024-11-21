#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Cluster Management Module

This Ansible module manages clusters in PX-Backup, providing operations for:
- Creating clusters
- Updating existing clusters
- Deleting clusters
- Inspecting clusters (single or all)
- Managing cluster sharing and backup sharing
- Managing cluster ownership
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import typing
from typing import Dict, List, Tuple, Optional, Any, Union
import logging
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.px_backup.api import PXBackupClient
import requests
import base64

DOCUMENTATION = r'''
---
module: cluster

short_description: Manage clusters in PX-Backup

version_added: "2.8.1"

description: 
    - Manage clusters in PX-Backup using different operations
    - Supports CRUD operations, sharing, and backup management
    - Supports various cloud providers (AWS, Azure, Google, IBM, Rancher)
    - Provides both single cluster and bulk inspection capabilities
    - Handles cluster credentials and configurations securely

options:
    operation:
        description:
            - Operation to perform on the cluster
            - 'CREATE' creates a new cluster
            - 'UPDATE' modifies an existing cluster
            - 'DELETE' removes a cluster
            - 'INSPECT_ONE' retrieves details of a specific cluster
            - 'INSPECT_ALL' lists all clusters
            - 'UPDATE_BACKUP_SHARE' updates backup sharing settings
            - 'SHARE_CLUSTER' shares cluster access with users/groups
            - 'UNSHARE_CLUSTER' removes shared access
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL', 
                 'UPDATE_BACKUP_SHARE', 'SHARE_CLUSTER', 'UNSHARE_CLUSTER']
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
            - Name of the cluster
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description: 
            - Unique identifier of the cluster
            - Required for UPDATE, DELETE, INSPECT_ONE operations
        required: false
        type: str
    px_config:
        description: Portworx configuration
        required: false
        type: dict
        suboptions:
            access_token:
                description: Access token for Portworx
                type: str
    kubeconfig:
        description: Kubernetes configuration
        required: false
        type: str
    cloud_type:
        description: Cloud provider type
        required: false
        choices: ['OTHERS', 'AWS', 'AZURE', 'GOOGLE', 'IBM']
        type: str
    cloud_credential_ref:
        description: Reference to cloud credentials
        required: false
        type: dict
        suboptions:
            name:
                description: Name of cloud credential
                type: str
            uid:
                description: UID of cloud credential
                type: str
    platform_credential_ref:
        description: Reference to platform credentials
        required: false
        type: dict
        suboptions:
            name:
                description: Name of platform credential
                type: str
            uid:
                description: UID of platform credential
                type: str
    service_token:
        description: Service token for authentication
        required: false
        type: str
    delete_restores:
        description: Whether to delete restores when cluster is deleted
        required: false
        type: bool
        default: false
    delete_all_cluster_backups:
        description: Whether to delete all cluster backups (super admin only)
        required: false
        type: bool
        default: false
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    labels:
        description: Labels to attach to the cluster
        required: false
        type: dict
    backup_share:
        description: Backup sharing configuration
        required: false
        type: dict
    cluster_share:
        description: Cluster sharing configuration
        required: false
        type: dict
        suboptions:
            users:
                description: List of users to share with
                type: list
                elements: str
            groups:
                description: List of groups to share with
                type: list
                elements: str
            share_cluster_backups:
                description: Whether to share existing backups
                type: bool
                default: false

requirements:
    - python >= 3.6
    - requests

notes:
    - "Operation-specific required parameters:"
    - "CREATE: name, org_id, (kubeconfig or teleport configuration)"
    - "UPDATE: name, uid, org_id"
    - "DELETE: name, org_id"
    - "INSPECT_ONE: name, uid, org_id"
    - "INSPECT_ALL: org_id"
    - "UPDATE_BACKUP_SHARE: name, uid, org_id, backup_share"
    - "SHARE_CLUSTER: name, uid, org_id, cluster_share"
    - "UNSHARE_CLUSTER: name, uid, org_id, cluster_share"
'''

# TODO: Add examples

# Configure logging
logger = logging.getLogger('cluster')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class ClusterError(Exception):
    """Base exception for cluster operations"""
    pass

class ValidationError(ClusterError):
    """Raised when validation fails"""
    pass

class APIError(ClusterError):
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

def encode_kubeconfig(kubeconfig: str) -> str:
    """
    Encode a kubeconfig string to Base64.

    Args:
        kubeconfig (str): The kubeconfig string to encode.

    Returns:
        str: The Base64-encoded kubeconfig string.
    """
    encoded_kubeconfig = base64.b64encode(kubeconfig.encode('utf-8')).decode('utf-8')
    return encoded_kubeconfig

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

def create_cluster(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new cluster"""
    try:
        params = dict(module.params)
        cluster_request = build_cluster_request(params)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/cluster',
            data=cluster_request
        )
        
        # Return the cluster from the response
        if isinstance(response, dict) and 'cluster' in response:
            return response['cluster'], True
            
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
        module.fail_json(msg=f"Failed to create cluster: {error_msg}")

def update_cluster(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing cluster"""
    try:
        params = dict(module.params)
        cluster_request = build_cluster_request(params)
        cluster_request['metadata']['uid'] = params['uid']
        
        current = inspect_cluster(module, client)
        if not needs_update(current, cluster_request):
            return current, False
            
        response = client.make_request(
            method='PUT',
            endpoint='v1/cluster',
            data=cluster_request
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update cluster: {str(e)}")

def update_backup_share(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update backup sharing settings"""
    try:
        request = {
            "org_id": module.params['org_id'],
            "name": module.params['name'],
            "uid": module.params['uid'],
            "add_backup_share": module.params.get('backup_share', {}).get('add', {}),
            "del_backup_share": module.params.get('backup_share', {}).get('delete', {})
        }
        
        response = client.make_request(
            method='PUT',
            endpoint='v1/cluster/updatebackupshare',
            data=request
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update backup share: {str(e)}")

def share_cluster(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Share cluster with users/groups"""
    try:
        share_config = module.params.get('cluster_share', {})
        request = {
            "org_id": module.params['org_id'],
            "cluster_ref": {
                "name": module.params['name'],
                "uid": module.params['uid']
            },
            "users": share_config.get('users', []),
            "groups": share_config.get('groups', []),
            "share_cluster_backups": share_config.get('share_cluster_backups', False)
        }
        
        response = client.make_request(
            method='PATCH',
            endpoint='v1/sharecluster',
            data=request
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to share cluster: {str(e)}")

def unshare_cluster(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Remove cluster sharing"""
    try:
        share_config = module.params.get('cluster_share', {})
        request = {
            "org_id": module.params['org_id'],
            "cluster_ref": {
                "name": module.params['name'],
                "uid": module.params['uid']
            },
            "users": share_config.get('users', []),
            "groups": share_config.get('groups', [])
        }
        
        response = client.make_request(
            method='PATCH',
            endpoint='v1/unsharecluster',
            data=request
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to unshare cluster: {str(e)}")

def enumerate_clusters(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all clusters"""
    try:
        params = {
            'labels': module.params.get('labels', {}),
            'include_secrets': module.params.get('include_secrets', False),
            'only_backup_share': module.params.get('only_backup_share', False),
            'cloud_credential_ref': module.params.get('cloud_credential_ref', {}),
        }
            
        response = client.make_request(
            method='GET',
            endpoint=f"v1/cluster/{module.params['org_id']}",
            params=params
        )
        return response['clusters']
        
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate clusters: {str(e)}")

def inspect_cluster(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific cluster"""
    try:
        params = {
            'include_secrets': module.params.get('include_secrets', False)
        }
        
        response = client.make_request(
            method='GET',
            endpoint=f"v1/cluster/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}",
            params=params
        )
        return response
        
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect cluster: {str(e)}")

def delete_cluster(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a cluster"""
    try:
        params = {
            'delete_restores': module.params['delete_restores'],
            'uid': module.params['uid'],
            'delete_all_cluster_backups': module.params['delete_all_cluster_backups']
        }
        
        response = client.make_request(
            method='DELETE',
            endpoint=f"v1/cluster/{module.params['org_id']}/{module.params['name']}",
            params=params
        )
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to delete cluster: {str(e)}")

def build_cluster_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build cluster request object
    
    Args:
        params: Module parameters
    
    Returns:
        Dict containing the request object
    """
    request = {
        "metadata": {
            "name": params.get('name'),
            "org_id": params.get('org_id')
        }
    }

    # Add cluster info
    cluster_info = {}
    
    # Add PX config if provided
    if params.get('px_config'):
        cluster_info['px_config'] = {
            'access_token': params['px_config'].get('access_token')
        }
    
    # Add kubeconfig if provided
    if params.get('kubeconfig'):
        request['kubeconfig'] = encode_kubeconfig(params['kubeconfig'])
    
    # Add cloud type if specified
    cloud_type = params.get('cloud_type')
    if cloud_type:
        request['cloud_type'] = cloud_type
    
        # Add credential references for cloud clusters
        if cloud_type in ['AWS', 'AZURE', 'GOOGLE', 'IBM'] and params.get('cloud_credential_ref'):
            request['cloud_credential_ref'] = {
                    'name': params['cloud_credential_ref'].get('name'),
                    'uid': params['cloud_credential_ref'].get('uid')
                }
    
    if params.get('platform_credential_ref'):
        request['platform_credential_ref'] = {   
            'name': params['platform_credential_ref'].get('name'),
            'uid': params['platform_credential_ref'].get('uid')
        }
    
    if params.get('service_token'):
        cluster_info['service_token'] = params['service_token']

    # Add optional fields
    if params.get('labels'):
        request['metadata']['labels'] = params['labels']

    if params.get('ownership'):
        request['metadata']['ownership'] = params['ownership']
    
    # Add cluster info to request if not empty
    if cluster_info:
        request['clusterinfo'] = cluster_info

    return request

def needs_update(current: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """
    Compare current and desired state to determine if update is needed
    
    Args:
        current: Current cluster state
        desired: Desired cluster state
    
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
    return f"Failed to {operation.lower()} cluster: {error_msg}"

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
            cluster, changed = create_cluster(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster': cluster},
                message="Cluster created successfully"
            )
        
        elif operation == 'UPDATE':
            cluster, changed = update_cluster(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster': cluster},
                message="Cluster updated successfully"
            )
        
        elif operation == 'INSPECT_ALL':
            clusters = enumerate_clusters(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'clusters': clusters},
                message=f"Found {len(clusters)} clusters"
            )
            
        elif operation == 'INSPECT_ONE':
            cluster = inspect_cluster(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'cluster': cluster},
                message="Successfully retrieved cluster details"
            )
            
        elif operation == 'DELETE':
            cluster, changed = delete_cluster(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster': cluster},
                message="Cluster deleted successfully"
            )
            
        elif operation == 'UPDATE_BACKUP_SHARE':
            cluster, changed = update_backup_share(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster': cluster},
                message="Cluster backup share updated successfully"
            )
            
        elif operation == 'SHARE_CLUSTER':
            cluster, changed = share_cluster(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster': cluster},
                message="Cluster shared successfully"
            )
            
        elif operation == 'UNSHARE_CLUSTER':
            cluster, changed = unshare_cluster(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster': cluster},
                message="Cluster unshared successfully"
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
                'UPDATE_BACKUP_SHARE',
                'SHARE_CLUSTER',
                'UNSHARE_CLUSTER'
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        px_config=dict(
            type='dict',
            required=False,
            options=dict(
                access_token=dict(type='str', no_log=True)
            )
        ),
        kubeconfig=dict(type='str', required=False, no_log=True),
        cloud_type=dict(
            type='str',
            required=False,
            choices=['OTHERS', 'AWS', 'AZURE', 'GOOGLE', 'IBM']
        ),
        cloud_credential_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        ),
        platform_credential_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        ),
        service_token=dict(type='str', required=False, no_log=True),
        delete_restores=dict(type='bool', required=False, default=False),
        delete_all_cluster_backups=dict(type='bool', required=False, default=False),
        validate_certs=dict(type='bool', default=True),
        labels=dict(type='dict', required=False),
        backup_share=dict(
            type='dict',
            required=False,
            options=dict(
                add=dict(type='dict'),
                delete=dict(type='dict')
            )
        ),
        cluster_share=dict(
            type='dict',
            required=False,
            options=dict(
                users=dict(type='list', elements='str'),
                groups=dict(type='list', elements='str'),
                share_cluster_backups=dict(type='bool', default=False)
            )
        ),
        include_secrets=dict(type='bool', default=False)
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'org_id'],
        'UPDATE': ['name', 'uid', 'org_id'],
        'DELETE': ['name', 'org_id'],
        'INSPECT_ONE': ['name', 'uid', 'org_id'],
        'INSPECT_ALL': ['org_id'],
        'UPDATE_BACKUP_SHARE': ['name', 'uid', 'org_id', 'backup_share'],
        'SHARE_CLUSTER': ['name', 'uid', 'org_id', 'cluster_share'],
        'UNSHARE_CLUSTER': ['name', 'uid', 'org_id', 'cluster_share']
    }

    result = dict(
        changed=False,
        cluster={},
        clusters=[],
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
        #required_one_of=[['kubeconfig', 'teleport_cluster_id']]
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