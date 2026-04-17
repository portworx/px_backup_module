#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup ClusterDiscoveryConfig Management Module

This Ansible module manages cluster discovery configurations in PX-Backup,
providing operations for:
- Creating discovery configurations (e.g., Gardener Shoot discovery)
- Updating existing configurations
- Deleting configurations
- Inspecting configurations (single or all)
- Triggering manual cluster discovery
- Triggering manual credential refresh for discovered clusters
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
import requests

DOCUMENTATION = r'''
---
module: cluster_discovery_config

short_description: Manage cluster discovery configurations in PX-Backup

version_added: "3.0.0"

description:
    - Manage cluster discovery configurations in PX-Backup using different operations
    - Supports CRUD operations for discovery configurations
    - Supports manual cluster discovery and credential refresh triggers
    - Currently supports Gardener Shoot cluster discovery
    - Provides both single config and bulk inspection capabilities

options:
    operation:
        description:
            - Operation to perform on the cluster discovery config
            - "- CREATE: creates a new cluster discovery configuration"
            - "- UPDATE: modifies an existing cluster discovery configuration"
            - "- DELETE: removes a cluster discovery configuration"
            - "- INSPECT_ONE: retrieves details of a specific configuration"
            - "- INSPECT_ALL: lists all cluster discovery configurations"
            - "- DISCOVER_CLUSTERS: manually triggers cluster discovery"
            - "- REFRESH_CLUSTERS: manually triggers credential refresh for discovered clusters"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ONE', 'INSPECT_ALL',
                 'DISCOVER_CLUSTERS', 'REFRESH_CLUSTERS']
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
            - Name of the cluster discovery configuration
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description:
            - Unique identifier of the cluster discovery configuration
            - Optional but recommended for exact match in update/delete/discover/refresh
        required: false
        type: str
    config_type:
        description:
            - Type of discovery configuration
            - Currently only Shoot (Gardener) is supported
        required: false
        type: str
        choices: ['Shoot', 'All']
    shoot_config:
        description:
            - Gardener Shoot discovery configuration
            - Required when config_type is Shoot during CREATE
        required: false
        type: dict
        suboptions:
            gardener_kubeconfig:
                description:
                    - Gardener API server kubeconfig for authentication
                    - Must be base64-encoded
                type: str
                required: true
            project_name:
                description: Gardener project name to discover Shoot clusters from
                type: str
                required: true
            label_selector:
                description:
                    - Label selector string to filter Shoot clusters during discovery
                    - 'Supports Kubernetes label selector syntax, e.g.:'
                    - '"environment in (production, staging),team=platform,!deprecated"'
                type: str
                required: false
    settings:
        description: Common discovery settings (polling frequency, auto-discover toggle)
        required: false
        type: dict
        suboptions:
            auto_discover:
                description: Enable or disable automatic discovery
                type: bool
            auto_discover_frequency:
                description:
                    - Frequency of automatic discovery when auto_discover is enabled
                    - Minimum allowed total interval is 15 minutes
                type: dict
                suboptions:
                    days:
                        description: Number of days between discovery runs (0-365)
                        type: int
                        default: 0
                    hours:
                        description: Number of hours between discovery runs (0-23)
                        type: int
                        default: 0
                    minutes:
                        description: Number of minutes between discovery runs (0-59)
                        type: int
                        default: 0
    labels:
        description: Labels to attach to the cluster discovery configuration
        required: false
        type: dict
    include_secrets:
        description: Include sensitive fields like kubeconfigs in the response
        required: false
        type: bool
        default: false
    confirm_update:
        description:
            - Confirmation flag required for update operations
            - Must be set to true explicitly; otherwise the update will be rejected
        required: false
        type: bool
        default: false
    gardener_kubeconfig:
        description:
            - Updated Gardener kubeconfig for UPDATE operations
            - Must be base64-encoded
            - In UPDATE, this is a top-level field (not inside shoot_config)
        required: false
        type: str
    ssl_config:
        description:
            - SSL configuration dictionary containing certificate settings
            - Contains validate_certs, ca_cert, client_cert, and client_key options
        required: false
        type: dict
        default: {}
        options:
            validate_certs:
                description: Verify SSL certificates
                type: bool
                default: true
            ca_cert:
                description: Path to CA certificate file for SSL verification
                type: path
            client_cert:
                description: Path to client certificate file for mutual TLS authentication
                type: path
            client_key:
                description: Path to client private key file for mutual TLS authentication
                type: path

requirements:
    - python >= 3.9
    - requests

notes:
    - "Operation-specific required parameters:"
    - "CREATE: name, org_id, config_type, shoot_config (for Shoot type)"
    - "UPDATE: name, org_id, confirm_update=true"
    - "DELETE: name, org_id"
    - "INSPECT_ONE: name, org_id"
    - "INSPECT_ALL: org_id"
    - "DISCOVER_CLUSTERS: name, org_id"
    - "REFRESH_CLUSTERS: name, org_id"
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

# --- Config type mapping ---

CONFIG_TYPE_MAP = {
    'Shoot': 2,
    'All': 1,
}

CONFIG_TYPE_REVERSE_MAP = {v: k for k, v in CONFIG_TYPE_MAP.items()}


def validate_params(params: Dict[str, Any], operation: str, required_params: List[str]) -> None:
    """
    Validate parameters for the given operation.

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


# --- API operation functions ---

def create_cluster_discovery_config(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new cluster discovery configuration."""
    try:
        params = module.params
        request = build_create_request(params)

        response = client.make_request(
            method='POST',
            endpoint='v1/clusterdiscoveryconfig',
            data=request
        )

        if isinstance(response, dict) and 'cluster_discovery_config' in response:
            return response['cluster_discovery_config'], True

        # Return full response if structure is different
        return response, True

    except Exception as e:
        module.fail_json(msg=f"Failed to create cluster discovery config: {_format_error(e)}")


def update_cluster_discovery_config(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing cluster discovery configuration."""
    try:
        params = module.params

        # Inspect current state to check if update is actually needed
        current = inspect_cluster_discovery_config(module, client)
        if not _needs_update(current, params):
            return current, False

        request = build_update_request(params)

        response = client.make_request(
            method='PATCH',
            endpoint='v1/clusterdiscoveryconfig',
            data=request
        )
        return response, True

    except Exception as e:
        module.fail_json(msg=f"Failed to update cluster discovery config: {_format_error(e)}")


def enumerate_cluster_discovery_configs(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all cluster discovery configurations."""
    try:
        query_params = {}

        if module.params.get('config_type'):
            query_params['type'] = CONFIG_TYPE_MAP.get(module.params['config_type'], 0)

        query_params['include_secrets'] = module.params.get('include_secrets', False)

        response = client.make_request(
            method='GET',
            endpoint=f"v1/clusterdiscoveryconfig/{module.params['org_id']}",
            params=query_params
        )
        return response.get('cluster_discovery_configs', [])

    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate cluster discovery configs: {_format_error(e)}")


def inspect_cluster_discovery_config(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific cluster discovery configuration."""
    try:
        query_params = {
            'include_secrets': module.params.get('include_secrets', False),
        }
        if module.params.get('uid'):
            query_params['uid'] = module.params['uid']

        response = client.make_request(
            method='GET',
            endpoint=f"v1/clusterdiscoveryconfig/{module.params['org_id']}/{module.params['name']}",
            params=query_params
        )
        # Unwrap if the API returns {"cluster_discovery_config": {...}}
        if isinstance(response, dict) and 'cluster_discovery_config' in response:
            return response['cluster_discovery_config']
        return response

    except Exception as e:
        module.fail_json(msg=f"Failed to inspect cluster discovery config: {_format_error(e)}")


def delete_cluster_discovery_config(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a cluster discovery configuration."""
    try:
        query_params = {}
        if module.params.get('uid'):
            query_params['uid'] = module.params['uid']

        response = client.make_request(
            method='DELETE',
            endpoint=f"v1/clusterdiscoveryconfig/{module.params['org_id']}/{module.params['name']}",
            params=query_params
        )
        return response, True

    except Exception as e:
        module.fail_json(msg=f"Failed to delete cluster discovery config: {_format_error(e)}")


def discover_clusters(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Manually trigger cluster discovery for a specific configuration.

    Note: This is an async trigger operation — changed=True indicates the
    discovery was initiated, not that it completed. Use INSPECT_ONE to poll status.
    """
    try:
        request = {
            'org_id': module.params['org_id'],
            'name': module.params['name'],
        }
        if module.params.get('uid'):
            request['uid'] = module.params['uid']

        response = client.make_request(
            method='POST',
            endpoint=f"v1/clusterdiscoveryconfig/{module.params['org_id']}/{module.params['name']}/discover",
            data=request
        )
        return response, True

    except Exception as e:
        module.fail_json(msg=f"Failed to trigger cluster discovery: {_format_error(e)}")


def refresh_clusters(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Manually trigger credential refresh for all clusters of a discovery config.

    Note: This is an async trigger operation — changed=True indicates the
    refresh was initiated, not that it completed. Use INSPECT_ONE to poll status.
    """
    try:
        request = {
            'org_id': module.params['org_id'],
            'name': module.params['name'],
        }
        if module.params.get('uid'):
            request['uid'] = module.params['uid']

        response = client.make_request(
            method='POST',
            endpoint=f"v1/clusterdiscoveryconfig/{module.params['org_id']}/{module.params['name']}/refresh",
            data=request
        )
        return response, True

    except Exception as e:
        module.fail_json(msg=f"Failed to trigger cluster refresh: {_format_error(e)}")


# --- Request builder functions ---

def build_create_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the create request payload for ClusterDiscoveryConfigCreateRequest.

    Args:
        params: Module parameters

    Returns:
        Dict containing the request payload
    """
    request = {
        'metadata': {
            'name': params['name'],
            'org_id': params['org_id'],
        },
        'cluster_discovery_config_info': {}
    }

    # Add labels to metadata
    if params.get('labels'):
        request['metadata']['labels'] = params['labels']

    config_info = request['cluster_discovery_config_info']

    # Set config type
    if params.get('config_type'):
        config_info['type'] = CONFIG_TYPE_MAP.get(params['config_type'], 0)

    # Set shoot config
    if params.get('shoot_config'):
        shoot = params['shoot_config']
        shoot_config = {}
        if shoot.get('gardener_kubeconfig'):
            shoot_config['gardener_kubeconfig'] = shoot['gardener_kubeconfig']
        if shoot.get('project_name'):
            shoot_config['project_name'] = shoot['project_name']
        if shoot.get('label_selector'):
            shoot_config['label_selector'] = shoot['label_selector']
        config_info['shoot_config'] = shoot_config

    # Set discovery settings
    if params.get('settings'):
        settings = params['settings']
        settings_payload = {}

        if settings.get('auto_discover') is not None:
            settings_payload['auto_discover'] = settings['auto_discover']

        if settings.get('auto_discover_frequency'):
            freq = settings['auto_discover_frequency']
            settings_payload['auto_discover_frequency'] = {
                'days': freq.get('days', 0),
                'hours': freq.get('hours', 0),
                'minutes': freq.get('minutes', 0),
            }

        config_info['settings'] = settings_payload

    return request


def build_update_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the update request payload for ClusterDiscoveryConfigUpdateRequest.

    The update request has a different structure than create:
    - org_id is top-level
    - config_ref identifies the config to update
    - gardener_kubeconfig is top-level (not nested in shoot_config)
    - confirm_update must be true

    Args:
        params: Module parameters

    Returns:
        Dict containing the request payload
    """
    request = {
        'org_id': params['org_id'],
        'config_ref': {
            'name': params['name'],
        },
        'confirm_update': params.get('confirm_update', False),
    }

    if params.get('uid'):
        request['config_ref']['uid'] = params['uid']

    # Gardener kubeconfig (top-level in update, not inside shoot_config)
    if params.get('gardener_kubeconfig'):
        request['gardener_kubeconfig'] = params['gardener_kubeconfig']

    # Auto-discover toggle
    if params.get('settings') and params['settings'].get('auto_discover') is not None:
        request['auto_discover'] = params['settings']['auto_discover']

    # Auto-discover frequency
    if params.get('settings') and params['settings'].get('auto_discover_frequency'):
        freq = params['settings']['auto_discover_frequency']
        request['auto_discover_frequency'] = {
            'days': freq.get('days', 0),
            'hours': freq.get('hours', 0),
            'minutes': freq.get('minutes', 0),
        }

    # Metadata labels
    if params.get('labels'):
        request['metadata_labels'] = params['labels']

    return request


# --- Helper functions ---

def _needs_update(current: Dict[str, Any], params: Dict[str, Any]) -> bool:
    """
    Check if any of the fields being updated differ from the current state.

    Args:
        current: Current config returned by inspect
        params: Module parameters (desired state)

    Returns:
        True if an update is needed, False otherwise
    """
    config_info = current.get('cluster_discovery_config_info', {})
    current_settings = config_info.get('settings', {})
    current_labels = current.get('metadata', {}).get('labels', {})

    # Labels changed
    if params.get('labels') and params['labels'] != current_labels:
        return True

    # Settings changed
    if params.get('settings'):
        settings = params['settings']
        if settings.get('auto_discover') is not None:
            if settings['auto_discover'] != current_settings.get('auto_discover'):
                return True
        if settings.get('auto_discover_frequency'):
            current_freq = current_settings.get('auto_discover_frequency', {})
            new_freq = settings['auto_discover_frequency']
            if (new_freq.get('days', 0) != current_freq.get('days', 0) or
                    new_freq.get('hours', 0) != current_freq.get('hours', 0) or
                    new_freq.get('minutes', 0) != current_freq.get('minutes', 0)):
                return True

    # Gardener kubeconfig provided — always treat as changed since we cannot
    # safely compare secrets (inspect may not return it without include_secrets)
    if params.get('gardener_kubeconfig'):
        return True

    return False


def _format_error(e: Exception) -> str:
    """Format exception into a detailed error message."""
    error_msg = str(e)
    if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
        try:
            error_detail = e.response.json()
            error_msg = f"{error_msg}: {error_detail}"
        except ValueError:
            error_msg = f"{error_msg}: {e.response.text}"
    return error_msg


def handle_api_error(e: Exception, operation: str) -> str:
    """Handle API errors and format error message."""
    return f"Failed to {operation.lower()} cluster discovery config: {_format_error(e)}"


# --- Operation dispatcher ---

def perform_operation(module: AnsibleModule, client: PXBackupClient, operation: str) -> OperationResult:
    """
    Perform the requested operation.

    Args:
        module: Ansible module instance
        client: PX-Backup API client
        operation: Operation to perform

    Returns:
        OperationResult containing operation outcome
    """
    try:
        if operation == 'CREATE':
            config, changed = create_cluster_discovery_config(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster_discovery_config': config},
                message="Cluster discovery config created successfully"
            )

        elif operation == 'UPDATE':
            config, changed = update_cluster_discovery_config(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster_discovery_config': config},
                message="Cluster discovery config updated successfully"
            )

        elif operation == 'INSPECT_ALL':
            configs = enumerate_cluster_discovery_configs(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'cluster_discovery_configs': configs},
                message=f"Found {len(configs)} cluster discovery configs"
            )

        elif operation == 'INSPECT_ONE':
            config = inspect_cluster_discovery_config(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'cluster_discovery_config': config},
                message="Successfully retrieved cluster discovery config details"
            )

        elif operation == 'DELETE':
            config, changed = delete_cluster_discovery_config(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data={'cluster_discovery_config': config},
                message="Cluster discovery config deleted successfully"
            )

        elif operation == 'DISCOVER_CLUSTERS':
            result, changed = discover_clusters(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data=result,
                message="Cluster discovery triggered successfully"
            )

        elif operation == 'REFRESH_CLUSTERS':
            result, changed = refresh_clusters(module, client)
            return OperationResult(
                success=True,
                changed=changed,
                data=result,
                message="Cluster credential refresh triggered successfully"
            )

    except Exception as e:
        logger.exception(f"Operation {operation} failed")
        return OperationResult(
            success=False,
            changed=False,
            error=handle_api_error(e, operation)
        )


# --- Module entry point ---

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
                'DISCOVER_CLUSTERS',
                'REFRESH_CLUSTERS',
            ]
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        config_type=dict(
            type='str',
            required=False,
            choices=['Shoot', 'All']
        ),
        shoot_config=dict(
            type='dict',
            required=False,
            no_log=False,
            options=dict(
                gardener_kubeconfig=dict(type='str', required=True, no_log=True),
                project_name=dict(type='str', required=True),
                label_selector=dict(type='str', required=False),
            )
        ),
        settings=dict(
            type='dict',
            required=False,
            options=dict(
                auto_discover=dict(type='bool', required=False),
                auto_discover_frequency=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        days=dict(type='int', default=0),
                        hours=dict(type='int', default=0),
                        minutes=dict(type='int', default=0),
                    )
                )
            )
        ),
        labels=dict(type='dict', required=False),
        include_secrets=dict(type='bool', required=False, default=False),
        confirm_update=dict(type='bool', required=False, default=False),
        gardener_kubeconfig=dict(type='str', required=False, no_log=True),
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
    )

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'org_id', 'config_type'],
        'UPDATE': ['name', 'org_id'],
        'DELETE': ['name', 'org_id'],
        'INSPECT_ONE': ['name', 'org_id'],
        'INSPECT_ALL': ['org_id'],
        'DISCOVER_CLUSTERS': ['name', 'org_id'],
        'REFRESH_CLUSTERS': ['name', 'org_id'],
    }

    result = dict(
        changed=False,
        cluster_discovery_config={},
        cluster_discovery_configs=[],
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

        # Validate certificate files exist if provided
        # Only validate ca_cert when validate_certs is true (it's ignored otherwise)
        certs_to_check = ['client_cert', 'client_key']
        if ssl_config.get('validate_certs', True):
            certs_to_check.append('ca_cert')
        for cert_param in certs_to_check:
            cert_path = ssl_config.get(cert_param)
            if cert_path:
                if not os.path.exists(cert_path):
                    module.fail_json(msg=f"ssl_config.{cert_param} file not found: {cert_path}")
                if not os.access(cert_path, os.R_OK):
                    module.fail_json(msg=f"ssl_config.{cert_param} file not readable: {cert_path}")

        # Validate mutual TLS cert/key pairing
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