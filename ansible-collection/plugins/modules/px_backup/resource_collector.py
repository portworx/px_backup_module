#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Resource Collector Module

This Ansible module interfaces with the ResourceCollector service in PX-Backup to:
- List supported resource types for backup operations
- Query available Kubernetes resources on clusters
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import typing
from typing import Dict, List, Tuple, Optional, Any, Union
import logging
from dataclasses import dataclass
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
import requests

DOCUMENTATION = r'''
---
module: resource_collector

short_description: Get supported resource types in PX-Backup

version_added: "2.8.1"

description:
    - Query supported Kubernetes resource types for backup operations
    - List available resources on connected clusters
    - Part of the PX-Backup resource management system

options:
    api_url:
        description: PX-Backup API URL
        required: true
        type: str
    token:
        description: Authentication token
        required: true
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    cluster_ref:
        description: Reference to the target cluster
        required: true
        type: dict
        suboptions:
            name:
                description: Name of the cluster
                type: str
            uid: 
                description: UID of the cluster
                type: str

requirements:
    - python >= 3.9
    - requests
'''

EXAMPLES = r'''
# List supported resource types
- name: Get supported resource types
  resource_collector:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    cluster_ref:
      name: "prod-cluster"
      uid: "cluster-123"
'''

RETURN = r'''
resource_types:
    description: List of supported resource types
    type: list
    returned: success
    sample: ["pods", "deployments", "services", "configmaps", "secrets"]
message:
    description: Operation result message
    type: str
    returned: always
changed:
    description: Whether the operation changed anything
    type: bool
    returned: always
'''

# Configure logging
logger = logging.getLogger('resource_collector')
logger.addHandler(logging.NullHandler())

# Custom exceptions
class ResourceCollectorError(Exception):
    """Base exception for resource collector operations"""
    pass

class ValidationError(ResourceCollectorError):
    """Raised when validation fails"""
    pass

class APIError(ResourceCollectorError):
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

def validate_params(params: Dict[str, Any]) -> None:
    """
    Validate required parameters
    
    Args:
        params: Module parameters
        
    Raises:
        ValidationError: If validation fails
    """
    required_params = ['org_id', 'cluster_ref']
    missing = [param for param in required_params if not params.get(param)]
    if missing:
        raise ValidationError(f"Missing required parameters: {', '.join(missing)}")
        
    if params.get('cluster_ref'):
        if not params['cluster_ref'].get('name') or not params['cluster_ref'].get('uid'):
            raise ValidationError("cluster_ref requires both name and uid")

def get_resource_types(module: AnsibleModule, client: PXBackupClient) -> Tuple[List[str], bool]:
    """
    Get supported resource types from PX-Backup
    """
    try:
        # Build query parameters
        params = {
            'cluster_ref.name': module.params['cluster_ref']['name'],
            'cluster_ref.uid': module.params['cluster_ref']['uid']
        }

        # Make API request
        response = client.make_request(
            method='GET',
            endpoint=f"v1/resourceType/{module.params['org_id']}", 
            params=params
        )
        
        # Extract resource types from response
        resource_types = response.get('resource_types', [])
        return resource_types, False
        
    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to get resource types: {error_msg}")

def handle_api_error(e: Exception) -> str:
    """
    Handle API errors and format error message
    
    Args:
        e: Exception object
    
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
    return f"API request failed: {error_msg}"

def run_module():
    """Main module execution"""
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        org_id=dict(type='str', required=True),
        cluster_ref=dict(
            type='dict',
            required=True,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        )
    )

    result = dict(
        changed=False,
        resource_types=[],
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    try:
        # Validate parameters
        validate_params(module.params)

        # Initialize client
        client = PXBackupClient(
            module.params['api_url'],
            module.params['token'],
        )

        # Get resource types
        resource_types, changed = get_resource_types(module, client)
        
        # Update result
        result.update(
            changed=changed,
            resource_types=resource_types,
            message=f"Found {len(resource_types)} supported resource types"
        )

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