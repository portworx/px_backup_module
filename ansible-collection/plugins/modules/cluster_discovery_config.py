#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Cluster Discovery Configuration Management Module

This Ansible module manages cluster discovery configurations in PX-Backup,
providing operations for:
- Creating cluster discovery configs (for Gardener Shoot clusters)
- Updating existing cluster discovery configs
- Deleting cluster discovery configs
- Inspecting cluster discovery configs (single or all)
- Discovering clusters from Gardener
- Managing cluster discovery config ownership
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
CLUSTER_DISCOVERY_CONFIG_TYPE_MAP = {
    'Invalid': 0,
    'Shoot': 1
}

DOCUMENTATION = r'''
---
module: cluster_discovery_config

short_description: Manage cluster discovery configurations in PX-Backup

version_added: "2.11.0"

description:
    - Manage cluster discovery configurations in PX-Backup using different operations
    - Supports CRUD operations and cluster discovery from Gardener
    - Enables automatic discovery of Gardener Shoot clusters
    - Provides both single config and bulk inspection capabilities
    - Handles Gardener credentials and configurations securely

options:
    operation:
        description:
            - Operation to perform on the cluster discovery config
            - "- CREATE: creates a new cluster discovery config"
            - "- UPDATE: modifies an existing cluster discovery config"
            - "- DELETE: removes a cluster discovery config"
            - "- INSPECT_ONE: retrieves details of a specific cluster discovery config"
            - "- INSPECT_ALL: lists all cluster discovery configs"
            - "- UPDATE_OWNERSHIP: updates ownership settings"
            - "- DISCOVER_CLUSTERS: triggers cluster discovery from Gardener"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL', 'UPDATE_OWNERSHIP', 'DISCOVER_CLUSTERS']
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
            - Name of the cluster discovery config
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description:
            - Unique identifier of the cluster discovery config
        required: false
        type: str
    config_type:
        description:
            - Type of cluster discovery configuration
            - Currently only Shoot (Gardener) is supported
        required: false
        choices: ['Invalid', 'Shoot']
        type: str
        default: 'Shoot'
    shoot_discovery_config:
        description:
            - Configuration for Gardener Shoot cluster discovery
            - Required for CREATE and UPDATE operations when config_type is Shoot
        required: false
        type: dict
        suboptions:
            gardener_kubeconfig:
                description: Kubeconfig for accessing Gardener API server
                type: str
                required: true
            project_name:
                description: Gardener project name to discover Shoot clusters from
                type: str
                required: true
            label_selector:
                description: Label selector to filter Shoot clusters during discovery
                type: dict
                required: false
    cluster_discovery_settings:
        description:
            - Settings for automatic cluster discovery
        required: false
        type: dict
        suboptions:
            auto_discover:
                description: Enable automatic periodic cluster discovery
                type: bool
                default: false
            frequency:
                description: Frequency for automatic discovery
                type: dict
                suboptions:
                    hours:
                        description: Hours component of frequency
                        type: int
                    minutes:
                        description: Minutes component of frequency
                        type: int
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
                type: path
            client_cert:
                description:
                    - Path to client certificate file for mutual TLS authentication
                type: path
            client_key:
                description:
                    - Path to client private key file for mutual TLS authentication
                type: path
        version_added: "2.11.0"
    labels:
        description: Labels to attach to the cluster discovery config
        required: false
        type: dict
    ownership:
        description:
            - Ownership configuration for the cluster discovery config
            - Required for UPDATE_OWNERSHIP operation
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the cluster discovery config
                type: str
            groups:
                description: List of group access configurations
                type: list
                elements: dict
                suboptions:
                    id:
                        description: Group identifier
                        type: str
                    access:
                        description: Access level for the group
                        type: str
                        choices: ['Read', 'Write', 'Admin']
            collaborators:
                description: List of collaborator access configurations
                type: list
                elements: dict
                suboptions:
                    id:
                        description: Collaborator identifier
                        type: str
                    access:
                        description: Access level for the collaborator
                        type: str
                        choices: ['Read', 'Write', 'Admin']
            public:
                description: Public access configuration
                type: dict
                suboptions:
                    type:
                        description: Public access level
                        type: str
                        choices: ['Read', 'Write', 'Admin']

requirements:
    - python >= 3.9
    - requests

notes:
    - "Operation-specific required parameters:"
    - "CREATE: name, org_id, config_type, shoot_discovery_config (for Shoot type)"
    - "UPDATE: name, org_id"
    - "DELETE: name, org_id"
    - "INSPECT_ONE: name, org_id"
    - "INSPECT_ALL: org_id"
    - "UPDATE_OWNERSHIP: name, org_id, ownership"
    - "DISCOVER_CLUSTERS: name, org_id"
'''

EXAMPLES = r'''
# Create a Gardener Shoot cluster discovery config
- name: Create Gardener cluster discovery config
  cluster_discovery_config:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "gardener-discovery"
    org_id: "default"
    config_type: "Shoot"
    shoot_discovery_config:
      gardener_kubeconfig: "{{ lookup('file', '/path/to/gardener-kubeconfig') }}"
      project_name: "my-gardener-project"
      label_selector:
        environment: "production"
    cluster_discovery_settings:
      auto_discover: true
      frequency:
        hours: 1
        minutes: 0

# List all cluster discovery configs
- name: List all cluster discovery configs
  cluster_discovery_config:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"

# Trigger cluster discovery manually
- name: Discover clusters from Gardener
  cluster_discovery_config:
    operation: DISCOVER_CLUSTERS
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "gardener-discovery"
    org_id: "default"

# Delete a cluster discovery config
- name: Delete cluster discovery config
  cluster_discovery_config:
    operation: DELETE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "gardener-discovery"
    org_id: "default"
'''

RETURN = r'''
cluster_discovery_config:
    description: Details of the cluster discovery config for single-item operations
    type: dict
    returned: success
    sample: {
        "metadata": {
            "name": "gardener-discovery",
            "org_id": "default",
            "uid": "123-456"
        },
        "cluster_discovery_config_info": {
            "type": "Shoot",
            "shoot_discovery_config": {
                "project_name": "my-gardener-project"
            },
            "cluster_discovery_settings": {
                "auto_discover": true,
                "frequency": {
                    "hours": 1
                }
            }
        }
    }
cluster_discovery_configs:
    description: List of cluster discovery configs for INSPECT_ALL operation
    type: list
    returned: when operation is INSPECT_ALL
    sample: [
        {
            "metadata": {
                "name": "config1",
                "org_id": "default"
            }
        }
    ]
discovered_clusters:
    description: List of discovered clusters for DISCOVER_CLUSTERS operation
    type: list
    returned: when operation is DISCOVER_CLUSTERS
    sample: [
        {
            "name": "shoot-cluster-1",
            "project_name": "my-gardener-project"
        }
    ]
message:
    description: Operation result message
    type: str
    returned: always
changed:
    description: Whether the operation changed the cluster discovery config
    type: bool
    returned: always
'''

# Configure logging
logger = logging.getLogger('cluster_discovery_config')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class ClusterDiscoveryConfigError(Exception):
    """Base exception for cluster discovery config operations"""
    pass

class ValidationError(ClusterDiscoveryConfigError):
    """Raised when validation fails"""
    pass

class APIError(ClusterDiscoveryConfigError):
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


def build_cluster_discovery_config_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build cluster discovery config request object

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
        "cluster_discovery_config_info": {}
    }

    # Add UID for update operations
    if params.get('uid'):
        request['metadata']['uid'] = params['uid']

    # Add optional metadata fields
    if params.get('labels'):
        request['metadata']['labels'] = params['labels']

    if params.get('ownership'):
        request['metadata']['ownership'] = params['ownership']

    # Build cluster_discovery_config_info
    config_info = {}

    # Add config type
    config_type = params.get('config_type', 'Shoot')
    if config_type in CLUSTER_DISCOVERY_CONFIG_TYPE_MAP:
        config_info['type'] = CLUSTER_DISCOVERY_CONFIG_TYPE_MAP[config_type]

    # Handle shoot_discovery_config
    if params.get('shoot_discovery_config'):
        shoot_config = params['shoot_discovery_config']
        shoot_discovery_config = {}

        if shoot_config.get('gardener_kubeconfig'):
            shoot_discovery_config['gardener_kubeconfig'] = shoot_config['gardener_kubeconfig']

        if shoot_config.get('project_name'):
            shoot_discovery_config['project_name'] = shoot_config['project_name']

        if shoot_config.get('label_selector'):
            shoot_discovery_config['label_selector'] = shoot_config['label_selector']

        if shoot_discovery_config:
            config_info['shoot_discovery_config'] = shoot_discovery_config

    # Handle cluster_discovery_settings
    if params.get('cluster_discovery_settings'):
        settings = params['cluster_discovery_settings']
        discovery_settings = {}

        if settings.get('auto_discover') is not None:
            discovery_settings['auto_discover'] = settings['auto_discover']

        if settings.get('frequency'):
            frequency = {}
            if settings['frequency'].get('hours') is not None:
                frequency['hours'] = settings['frequency']['hours']
            if settings['frequency'].get('minutes') is not None:
                frequency['minutes'] = settings['frequency']['minutes']
            if frequency:
                discovery_settings['frequency'] = frequency

        if discovery_settings:
            config_info['cluster_discovery_settings'] = discovery_settings

    request['cluster_discovery_config_info'] = config_info
    return request


def create_cluster_discovery_config(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new cluster discovery config"""
    try:
        params = dict(module.params)
        config_request = build_cluster_discovery_config_request(params)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/clusterdiscoveryconfig',
            data=config_request
        )

        # Return the config from the response
        if isinstance(response, dict):
            return response, True

        raise ValueError(f"Unexpected API response format: {response}")

    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to create cluster discovery config: {error_msg}")


def update_cluster_discovery_config(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing cluster discovery config"""
    try:
        params = dict(module.params)
        config_request = build_cluster_discovery_config_request(params)

        # Get current state for comparison
        current = inspect_cluster_discovery_config(module, client)
        if not needs_update(current, config_request):
            return current, False

        # Make update request
        response = client.make_request(
            method='PUT',
            endpoint='v1/clusterdiscoveryconfig',
            data=config_request
        )
        return response, True

    except Exception as e:
        module.fail_json(msg=f"Failed to update cluster discovery config: {str(e)}")


def update_ownership(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update ownership of a cluster discovery config"""
    ownership_request = {
        "org_id": module.params['org_id'],
        "name": module.params['name'],
        "ownership": module.params['ownership'],
        "uid": module.params.get('uid', '')
    }

    try:
        response = client.make_request(
            'PUT',
            'v1/clusterdiscoveryconfig/updateownership',
            ownership_request
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update cluster discovery config ownership: {str(e)}")


def enumerate_cluster_discovery_configs(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all cluster discovery configs"""
    try:
        response = client.make_request(
            'GET',
            f"v1/clusterdiscoveryconfig/{module.params['org_id']}"
        )
        return response.get('cluster_discovery_configs', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate cluster discovery configs: {str(e)}")


def inspect_cluster_discovery_config(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific cluster discovery config"""
    try:
        response = client.make_request(
            'GET',
            f"v1/clusterdiscoveryconfig/{module.params['org_id']}/{module.params['name']}"
        )
        return response
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect cluster discovery config: {str(e)}")


def delete_cluster_discovery_config(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a cluster discovery config"""
    try:
        response = client.make_request(
            'DELETE',
            f"v1/clusterdiscoveryconfig/{module.params['org_id']}/{module.params['name']}"
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete cluster discovery config: {str(e)}")


def discover_clusters(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Trigger cluster discovery from Gardener"""
    try:
        request_body = {
            "org_id": module.params['org_id'],
            "name": module.params['name']
        }
        if module.params.get('uid'):
            request_body['uid'] = module.params['uid']

        response = client.make_request(
            'POST',
            f"v1/clusterdiscoveryconfig/{module.params['org_id']}/{module.params['name']}/discover",
            data=request_body
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to discover clusters: {str(e)}")


def needs_update(current: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """
    Compare current and desired state to determine if update is needed

    Args:
        current: Current config state
        desired: Desired config state

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
    return f"Failed to {operation} cluster discovery config: {error_msg}"


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
                'UPDATE_OWNERSHIP',
                'DISCOVER_CLUSTERS'
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        config_type=dict(
            type='str',
            required=False,
            default='Shoot',
            choices=['Invalid', 'Shoot']
        ),
        shoot_discovery_config=dict(
            type='dict',
            required=False,
            options=dict(
                gardener_kubeconfig=dict(type='str', no_log=True),
                project_name=dict(type='str'),
                label_selector=dict(type='dict')
            )
        ),
        cluster_discovery_settings=dict(
            type='dict',
            required=False,
            options=dict(
                auto_discover=dict(type='bool', default=False),
                frequency=dict(
                    type='dict',
                    options=dict(
                        hours=dict(type='int'),
                        minutes=dict(type='int')
                    )
                )
            )
        ),
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

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'org_id'],
        'UPDATE': ['name', 'org_id'],
        'DELETE': ['name', 'org_id'],
        'INSPECT_ONE': ['name', 'org_id'],
        'INSPECT_ALL': ['org_id'],
        'UPDATE_OWNERSHIP': ['name', 'org_id', 'ownership'],
        'DISCOVER_CLUSTERS': ['name', 'org_id']
    }

    result = dict(
        changed=False,
        cluster_discovery_config={},
        cluster_discovery_configs=[],
        discovered_clusters=[],
        message=''
    )

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

        # Create API client with SSL configuration
        client = PXBackupClient(
            api_url=module.params['api_url'],
            token=module.params['token'],
            validate_certs=ssl_config.get('validate_certs', True),
            ca_cert=ssl_config.get('ca_cert'),
            client_cert=ssl_config.get('client_cert'),
            client_key=ssl_config.get('client_key')
        )

        # Execute operation
        if operation == 'CREATE':
            config, changed = create_cluster_discovery_config(module, client)
            result['cluster_discovery_config'] = config
            result['changed'] = changed
            result['message'] = f"Cluster discovery config '{module.params['name']}' created successfully"

        elif operation == 'UPDATE':
            config, changed = update_cluster_discovery_config(module, client)
            result['cluster_discovery_config'] = config
            result['changed'] = changed
            result['message'] = f"Cluster discovery config '{module.params['name']}' {'updated' if changed else 'unchanged'}"

        elif operation == 'DELETE':
            _, changed = delete_cluster_discovery_config(module, client)
            result['changed'] = changed
            result['message'] = f"Cluster discovery config '{module.params['name']}' deleted successfully"

        elif operation == 'INSPECT_ONE':
            config = inspect_cluster_discovery_config(module, client)
            result['cluster_discovery_config'] = config
            result['message'] = f"Cluster discovery config '{module.params['name']}' retrieved successfully"

        elif operation == 'INSPECT_ALL':
            configs = enumerate_cluster_discovery_configs(module, client)
            result['cluster_discovery_configs'] = configs
            result['message'] = f"Retrieved {len(configs)} cluster discovery config(s)"

        elif operation == 'UPDATE_OWNERSHIP':
            config, changed = update_ownership(module, client)
            result['cluster_discovery_config'] = config
            result['changed'] = changed
            result['message'] = f"Ownership for cluster discovery config '{module.params['name']}' updated successfully"

        elif operation == 'DISCOVER_CLUSTERS':
            response, changed = discover_clusters(module, client)
            result['discovered_clusters'] = response.get('clusters', [])
            result['changed'] = changed
            result['message'] = f"Cluster discovery completed for config '{module.params['name']}'"

        module.exit_json(**result)

    except ValidationError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {str(e)}")


def main():
    run_module()


if __name__ == '__main__':
    main()
