#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Cluster Management Module

This Ansible module ensures a cluster is present or absent in PX-Backup.
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
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.cluster import inspect_cluster as inspect_cluster_util, find_cluster_by_name
import requests
import base64

DOCUMENTATION = r'''
---
module: cluster

short_description: Ensure a cluster is present or absent in PX-Backup

version_added: "2.9.0"

description: 
    - Ensures a cluster is present (created or updated) or absent (deleted) in PX-Backup.
    - This module is idempotent and will only make changes if the desired state is not met.

options:
    state:
        description:
            - "Whether the cluster should be `present` or `absent`."
            - "`present` will create a new cluster or update an existing one."
            - "`absent` will delete a cluster."
        required: true
        type: str
        choices: ['present', 'absent']
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
            - Name of the cluster.
        required: true
        type: str
    org_id:
        description: Organization ID
        required: true
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

    ownership:
        description: Cluster ownership and access control configuration
        type: dict
        required: false
        suboptions:
            owner:
                description:
                - Owner of the cluster
                type: str
                required: false
            groups:
                description:
                - List of group access configurations
                type: list
                elements: dict
                required: false
                suboptions:
                    id:
                        description:
                        - Group identifier
                        type: str
                        required: true
                    access:
                        description:
                        - Access level for the group
                        type: str
                        required: true
                        choices: ['Read', 'Write', 'Admin']
            collaborators:
                description: List of collaborator access configurations
                type: list
                elements: dict
                required: false
                suboptions:
                    id:
                        description:
                        - Collaborator identifier
                        type: str
                        required: true
                    access:
                        description:
                        - Access level for the collaborator
                        type: str
                        required: true
                        choices: ['Read', 'Write', 'Admin']
            public:
                description:
                - Public access configuration
                type: dict
                required: false
                suboptions:
                    type:
                        description:
                        - Public access level
                        type: str
                        required: false
                        choices: ['Read', 'Write', 'Admin']

requirements:
    - python >= 3.9
    - requests

notes:
    - "When `state` is `present`, either `kubeconfig` or `px_config` must be provided if the cluster does not exist."
    - "This module is idempotent. It will check the current state before making any changes."
    - "For read-only operations, use the `cluster_info` module."
    - "For managing cluster sharing, use the `cluster_share` module."
'''

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
        
        current = inspect_cluster_util(
            client,
            params['org_id'],
            params['name'],
            params['uid']
        )
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

def run_module():
    """Main module execution"""
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        state=dict(
            type='str',
            required=True,
            choices=['present', 'absent']
        ),
        name=dict(type='str', required=True),
        org_id=dict(type='str', required=True),
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
        include_secrets=dict(type='bool', default=False),
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
        )
    )

    result = dict(
        changed=False,
        cluster={},
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_one_of=[['kubeconfig', 'px_config']]
    )

    try:
        if module.check_mode:
            module.exit_json(**result)

        client = PXBackupClient(
            module.params['api_url'],
            module.params['token'],
            module.params['validate_certs']
        )

        state = module.params['state']
        name = module.params['name']
        org_id = module.params['org_id']

        existing_cluster = find_cluster_by_name(client, org_id, name)

        if state == 'present':
            if existing_cluster:
                # Cluster exists, check for update
                module.params['uid'] = existing_cluster['metadata']['uid']
                cluster, changed = update_cluster(module, client)
                result['cluster'] = cluster
                result['changed'] = changed
                if changed:
                    result['message'] = "Cluster updated successfully."
                else:
                    result['message'] = "Cluster is already in the desired state."
            else:
                # Cluster does not exist, create it
                if not module.params.get('kubeconfig') and not module.params.get('px_config'):
                    module.fail_json(msg="Either 'kubeconfig' or 'px_config' is required to create a new cluster.")
                cluster, changed = create_cluster(module, client)
                result['cluster'] = cluster
                result['changed'] = changed
                result['message'] = "Cluster created successfully."

        elif state == 'absent':
            if existing_cluster:
                # Cluster exists, delete it
                module.params['uid'] = existing_cluster['metadata']['uid']
                _, changed = delete_cluster(module, client)
                result['changed'] = changed
                result['message'] = "Cluster deleted successfully."
            else:
                # Cluster does not exist, already absent
                result['changed'] = False
                result['message'] = "Cluster is already absent."

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