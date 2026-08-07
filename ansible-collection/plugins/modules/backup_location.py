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
- Triggering backup sync from object store (federated mode)

"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import time
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

version_added: "2.10.0"

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
            - " - VALIDATE: validates a backup location configuration (supports per-cluster validation in federated mode)"
            - " - INSPECT_ONE: retrieves details of a specific backup location"
            - " - INSPECT_ALL: lists all backup locations"
            - " - UPDATE_OWNERSHIP: updates ownership settings of a backup location"
            - " - SYNC: triggers backup sync from object store (federated mode only)"
        required: true
        type: str
        choices: ['CREATE', 'UPDATE', 'DELETE', 'VALIDATE', 'INSPECT_ONE', 'INSPECT_ALL', 'UPDATE_OWNERSHIP', 'SYNC']
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
    federated:
        description:
            - Enable Federated Identity (Workload Identity/OIDC) authentication
            - When true, authentication uses workload identity instead of cloud credentials
            - When true, cloud_credential_ref should be empty
            - "Supported for S3 (AWS IRSA / EKS Pod Identity), Azure (Workload Identity) and Google (Workload Identity)"
            - "Cloud-specific config should be in s3_config (azure_account_name, azure_subscription_id for Azure; google_project_id for Google)"
        required: false
        type: bool
        default: false
    cluster_refs:
        description:
            - List of clusters associated with this BackupLocation
            - Each item should have 'name' and optionally 'uid'
            - Required for CREATE and UPDATE when federated is true
            - CREATE and UPDATE automatically trigger validation on all clusters in cluster_refs
            - On UPDATE, the entire cluster_status map is replaced and ALL associated clusters
              are re-validated, not just newly added ones
            - For VALIDATE, when set, only the listed clusters are re-validated (must be a subset
              of the BackupLocation's existing cluster_refs); when omitted, all clusters are re-validated
        required: false
        type: list
        elements: dict
        suboptions:
            name:
                description: Name of the cluster
                type: str
            uid:
                description: UID of the cluster
                type: str
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
            azure_account_name:
                description:
                    - Azure storage account name
                    - Required for Federated Identity when using Azure
                    - When using federated identity, provide account name here instead of in cloud credential
                type: str
            azure_subscription_id:
                description:
                    - Azure subscription ID
                    - Required for Federated Identity when using Azure
                    - When using federated identity, provide subscription ID here instead of in cloud credential
                type: str
            google_project_id:
                description:
                    - Google Cloud project ID
                    - Required for Federated Identity (Workload Identity) when using Google, since no cloud credential is referenced
                    - Not required in non-federated mode, where it is derived from the cloud credential's JSON key
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
    ssl_config:
        description:
            - SSL configuration dictionary containing certificate settings
            - Contains validate_certs, ca_cert, client_cert, and client_key options
            - If not provided, defaults to standard SSL verification
        required: false
        type: dict
        default: {}
        suboptions:
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
    sync:
        description:
            - Trigger backup sync from the object store
            - Only valid in federated deployment mode
            - Can be used with CREATE or UPDATE operations, or via the SYNC operation
            - The sync is on-demand (not automatic or periodic)
            - Parallel sync triggers while another sync is in progress are not allowed
        required: false
        type: bool
        default: false
    sync_timeout:
        description:
            - Maximum time in seconds to wait for backup sync to complete
            - Only used with SYNC operation when wait_for_completion is true
        required: false
        type: int
        default: 600
    sync_poll_interval:
        description:
            - Interval in seconds between sync status polls
            - Only used with SYNC operation when wait_for_completion is true
        required: false
        type: int
        default: 10
    wait_for_completion:
        description:
            - Whether to wait for the sync operation to complete
            - Only used with SYNC operation
            - When true, the module will poll sync_info status until completion or timeout
        required: false
        type: bool
        default: false
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

# Create an Azure backup location with Federated Identity (Workload Identity)
- name: Create Azure backup location with federated identity
  backup_location:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-azure-federated"
    org_id: "default"
    location_type: "S3"
    path: "my-azure-container"
    federated: true
    s3_config:
      azure_account_name: "mystorageaccount"
      azure_subscription_id: "12345678-1234-1234-1234-123456789012"
      azure_environment:
        type: "AZURE_GLOBAL"
    cluster_refs:
      - name: "cluster-1"
        uid: "cluster-1-uid"
      - name: "cluster-2"

# Create an AWS S3 backup location with Federated Identity (AWS IRSA / EKS Pod Identity)
# No cloud credential is referenced. endpoint/disable_ssl are ignored in WLI mode and
# region is optional (falls back to AWS_REGION on the Stork pod if omitted).
- name: Create AWS S3 backup location with federated identity
  backup_location:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-aws-federated"
    org_id: "default"
    location_type: "S3"
    path: "my-bucket/backups"
    federated: true
    s3_config:
      region: "us-west-2"
    cluster_refs:
      - name: "cluster-1"
        uid: "cluster-1-uid"

# Create a Google backup location with Federated Identity (Workload Identity)
# google_project_id is required in federated mode since no cloud credential is referenced.
- name: Create Google backup location with federated identity
  backup_location:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-gcs-federated"
    org_id: "default"
    location_type: "Google"
    path: "my-bucket/backups"
    federated: true
    s3_config:
      google_project_id: "my-gcp-project"
    cluster_refs:
      - name: "cluster-1"
        uid: "cluster-1-uid"

# Validate only a subset of associated clusters (federated mode)
- name: Validate federated backup location (subset of clusters)
  backup_location:
    operation: VALIDATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "prod-azure-federated"
    uid: "backup-location-uid"
    cluster_refs:
      - name: "cluster-1"
        uid: "cluster-1-uid"

# Trigger backup sync on a federated backup location
- name: Trigger backup sync
  backup_location:
    operation: SYNC
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-azure-federated"
    org_id: "default"
    uid: "backup-location-uid"

# Trigger backup sync and wait for completion
- name: Trigger backup sync and wait
  backup_location:
    operation: SYNC
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "prod-azure-federated"
    org_id: "default"
    uid: "backup-location-uid"
    wait_for_completion: true
    sync_timeout: 900
    sync_poll_interval: 15
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
sync_info:
    description: Sync operation status details (returned for SYNC operation)
    type: dict
    returned: when operation is SYNC
    sample: {
        "status": "Completed",
        "reason": "Backup sync completed successfully",
        "cluster_ref": {"name": "cluster-1", "uid": "cluster-uid"},
        "sync_stats": {
            "start_time": "2026-05-04T10:00:00Z",
            "end_time": "2026-05-04T10:05:00Z"
        }
    }
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


def validate_google_backup_location_params(params: Dict[str, Any]) -> None:
    """Validate Google-specific backup location parameters.

    The GCP project ID is required only in federated (Workload Identity) mode, where no
    cloud credential is referenced and the project ID must be supplied directly in the
    backup location. In non-federated mode it is derived from the cloud credential's JSON
    key, so it is not required here.
    """
    if (params.get('location_type') == 'Google'
            and params.get('federated')
            and not (params.get('s3_config') or {}).get('google_project_id')):
        raise ValidationError(
            "s3_config.google_project_id is required for Google backup locations "
            "when federated is true"
        )


def validate_s3_backup_location_params(params: Dict[str, Any]) -> None:
    """Validate S3-specific backup location parameters.

    s3_config is required for S3 backup locations in non-federated mode, where it
    carries region/endpoint and related settings. In federated (Workload Identity)
    mode it is optional: region falls back to AWS_REGION on the Stork pod, matching
    the CLI which allows an S3 workload-identity backup location with no region.
    """
    if (params.get('location_type') == 'S3'
            and not params.get('federated')
            and not params.get('s3_config')):
        raise ValidationError(
            "s3_config is required for S3 backup locations when federated is false"
        )


def create_backup_location(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new backup location"""
    try:
        # Get module parameters directly
        params = dict(module.params)
        validate_s3_backup_location_params(params)
        validate_google_backup_location_params(params)
        backup_location_request = build_backup_location_request(params)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/backuplocation',
            data=backup_location_request
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
        module.fail_json(msg=f"Failed to create backup location: {error_msg}")

def update_backup_location(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing backup location"""
    try:
        # Build request using module.params
        params = dict(module.params)
        validate_s3_backup_location_params(params)
        backup_location_request = build_backup_location_request(params)

        if params.get('uid'):
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
        "uid": module.params.get('uid', '')
    }
    
    try:
        response = client.make_request('PUT', 'v1/backuplocation/updateownership', ownership_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update backup location ownership: {str(e)}")

def validate_backup_location(module, client):
    """Validate a backup location.

    For federated (workload-identity) backup locations, validation is asynchronous:
    the server triggers per-cluster validation via Stork on each associated cluster.
    An optional cluster_refs list can scope validation to a subset of the
    BackupLocation's existing clusters. Use INSPECT_ONE to check validation status.
    """
    params = module.params
    validate_request = {
        "org_id": params['org_id'],
        "name": params['name'],
        "uid": params.get('uid', '')
    }

    cluster_refs = _build_cluster_refs(params.get('cluster_refs'))
    if cluster_refs:
        validate_request['cluster_refs'] = cluster_refs

    try:
        response = client.make_request('POST', 'v1/backuplocation/validate', validate_request)
        return response, False
    except Exception as e:
        module.fail_json(msg=f"Failed to validate backup location: {str(e)}")


def _build_cluster_refs(refs):
    """Normalize cluster_refs into the API's [{name, uid}] shape, dropping empties."""
    if not refs:
        return []
    out = []
    for ref in refs:
        if not ref:
            continue
        item = {}
        if ref.get('name'):
            item['name'] = ref['name']
        if ref.get('uid'):
            item['uid'] = ref['uid']
        if item:
            out.append(item)
    return out


def sync_backup_location(module, client):
    """Trigger backup sync from object store for a federated backup location.

    This triggers an on-demand backup sync by sending a minimal PUT /v1/backuplocation
    request with only sync=true set in the backup_location payload.

    The PX-Backup server recognizes this as a "sync-only update" when:
      - sync=true
      - type is not set (defaults to Invalid/0 in protobuf)
      - cloud_credential_ref.name is empty
    This bypasses provider-specific validation (e.g., Azure environment type checks)
    and cloud credential requirements. The server hydrates all required fields
    (type, path, s3_config, cluster_refs, etc.) from the existing backup location
    object stored in MongoDB.

    In federated mode, PX-Backup will then create a sync BackupLocation CR on an
    application cluster, and Stork will read the object store bucket and create
    ApplicationBackup CRs for any backups not yet synced to PX-Backup.

    Optionally waits for the sync to complete by polling the sync_info status.
    """
    try:
        params = dict(module.params)

        # First inspect the current backup location to get its UID
        inspect_params = {
            'include_secrets': False,
            'uid': params.get('uid', '')
        }
        url = f"v1/backuplocation/{params['org_id']}/{params['name']}"
        current_bl = client.make_request(
            method='GET',
            endpoint=url,
            params=inspect_params
        ).get('backup_location', {})

        if not current_bl:
            module.fail_json(msg=f"Backup location '{params['name']}' not found")

        bl_uid = params.get('uid') or current_bl.get('metadata', {}).get('uid', '')

        # Build a minimal sync-only update request.
        # IMPORTANT: Send a minimal request with only sync=true.
        # Do NOT send type, path, s3_config, cloud_credential_ref, or other fields.
        # The server treats this as a "sync-only update" (isSyncOnlyUpdate=true)
        # when type==Invalid (not set) and cloud_credential_ref is empty, which
        # skips all provider-specific validation (Azure env type, S3 endpoint, etc.).
        # The server hydrates all required fields from the existing object via
        # hydrateWLIAzureConfigFromExisting() and other preservation logic.
        #
        # However, use_workload_identity MUST match the existing value because
        # validateBlNonUpdatableParam() checks it BEFORE the server's hydration
        # logic runs. If the existing BL has use_workload_identity=true and we
        # omit it (defaults to false), the server rejects the request.
        bl_info = current_bl.get('backup_location_info', current_bl.get('backup_location', {}))

        update_request = {
            "metadata": {
                "name": params['name'],
                "org_id": params['org_id'],
                "uid": bl_uid,
            },
            "backup_location": {
                "sync": True,
                "use_workload_identity": bl_info.get('use_workload_identity', False),
            }
        }

        # For federated/WLI locations the server does not preserve cluster_refs on
        # sync-only updates — it diffs the payload and wipes any refs not included.
        # Pass them through so the sync goroutine has a cluster to run against.
        cluster_refs = _build_cluster_refs(params.get('cluster_refs'))
        if cluster_refs:
            update_request["backup_location"]["cluster_refs"] = cluster_refs

        # Trigger sync via update
        response = client.make_request(
            method='PUT',
            endpoint='v1/backuplocation',
            data=update_request
        )

        # If wait_for_completion is requested, poll for sync status
        if params.get('wait_for_completion', False):
            sync_timeout = params.get('sync_timeout', 600)
            poll_interval = params.get('sync_poll_interval', 10)

            sync_result = _wait_for_sync_completion(
                module, client, params['org_id'], params['name'],
                bl_uid, sync_timeout, poll_interval
            )
            return sync_result, True

        return response, True

    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to trigger backup sync: {error_msg}")


def _wait_for_sync_completion(module, client, org_id, name, uid, timeout, poll_interval):
    """Poll sync_info status until completion, failure, or timeout.

    Returns the final backup location state with sync_info.

    Sync status transitions: Invalid -> Pending -> InProgress -> Completed/Failed
    """
    start_time = time.time()
    terminal_statuses = {'Completed', 'Failed', '3', '4'}  # proto enum values or string names

    while True:
        elapsed = time.time() - start_time
        if elapsed >= timeout:
            module.fail_json(
                msg=f"Backup sync timed out after {timeout}s. "
                    f"The sync may still be in progress on the server. "
                    f"Use INSPECT_ONE to check sync_info status."
            )

        # Inspect the backup location to get current sync status
        inspect_params = {
            'include_secrets': False,
            'uid': uid
        }
        try:
            url = f"v1/backuplocation/{org_id}/{name}"
            bl_response = client.make_request(
                method='GET',
                endpoint=url,
                params=inspect_params
            )
        except Exception as e:
            logger.warning(f"Error polling sync status: {e}, will retry")
            time.sleep(poll_interval)
            continue

        bl = bl_response.get('backup_location', {})
        bl_info = bl.get('backup_location_info', bl.get('backup_location', {}))
        sync_info = bl_info.get('sync_info', {})
        sync_status = str(sync_info.get('status', ''))

        logger.info(f"Sync status: {sync_status}, reason: {sync_info.get('reason', '')}")

        # Check for terminal states
        if sync_status in terminal_statuses or sync_status.lower() in {'completed', 'failed'}:
            if sync_status in {'Failed', '4'} or sync_status.lower() == 'failed':
                module.fail_json(
                    msg=f"Backup sync failed: {sync_info.get('reason', 'unknown reason')}",
                    backup_location=bl,
                    sync_info=sync_info
                )
            # Completed successfully
            return bl

        time.sleep(poll_interval)


def enumerate_backup_locations(module, client):
    """List all backup locations"""
    params = {
        'labels': module.params.get('labels', {}),
        'include_secrets': module.params.get('include_secrets', False),
        'include_validation_state': True
    }
    
    if module.params.get('cloud_credential_ref'):
        cloud_cred_ref = {}
        if module.params['cloud_credential_ref'].get('cloud_credential_name'):
            cloud_cred_ref['name'] = module.params['cloud_credential_ref']['cloud_credential_name']
        if module.params['cloud_credential_ref'].get('cloud_credential_uid'):
            cloud_cred_ref['uid'] = module.params['cloud_credential_ref']['cloud_credential_uid']

        if cloud_cred_ref:
            params['cloud_credential_ref'] = cloud_cred_ref
    
    try:
        response = client.make_request('GET', f"v1/backuplocation/{module.params['org_id']}", params=params)
        return response.get('backup_locations', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate backup locations: {str(e)}")

def inspect_backup_location(module, client):
    """Get details of a specific backup location"""
    params = {
        'include_secrets': module.params.get('include_secrets', False),
        'uid': module.params.get('uid', '')
    }

    
    try:
        url = f"v1/backuplocation/{module.params['org_id']}/{module.params['name']}"
        
        response = client.make_request(
            method='GET',
            endpoint=url,
            params=params  # uid passed as query parameter if provided
        )
        return response.get('backup_location', {})
        
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect backup location: {str(e)}")

def delete_backup_location(module, client):
    """Delete a backup location"""
    params = {
        'uid': module.params.get('uid', '')
    }

    try:
        url = f"v1/backuplocation/{module.params['org_id']}/{module.params['name']}"
        
        response = client.make_request(
            method='DELETE',
            endpoint=url,
            params=params  # uid passed as query parameter if provided
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
    federated = params.get('federated', False)

    # In federated (Workload Identity) mode there is no cloud credential to validate,
    # so cloud-credential validation is forced off regardless of the requested value.
    # This matches the CLI (validateAndSetCloudCredentialsForCreate in
    # pkg/pxb/backuplocation.go), which sets ValidateCloudCredential=false in WLI mode;
    # otherwise the server may attempt to validate against a non-existent credential.
    validate_cloud_credential = (
        False if federated else params.get('validate_cloud_credential', True)
    )

    request = {
        "metadata": {
            "name": params.get('name'),
            "org_id": params.get('org_id')
        },
        "backup_location": {
            "type": params.get('location_type'),
            "path": params.get('path'),
            "encryption_key": params.get('encryption_key', ''),
            "validate_cloud_credential": validate_cloud_credential,
            "object_lock_enabled": params.get('object_lock_enabled', False),
            # 'federated' is the user-facing param name only; BackupLocationInfo in the
            # px-backup-api proto has no 'federated' field (use_workload_identity = 10),
            # so the server ignores it. Emit only use_workload_identity to match the
            # wire payload produced by the CLI and the proto.
            "use_workload_identity": federated
        }
    }

    # Add sync flag if enabled (for federated mode backup sync)
    if params.get('sync'):
        request['backup_location']['sync'] = True

    # Add optional configurations safely
    if params.get('labels'):
        request['metadata']['labels'] = params['labels']

    if params.get('ownership'):
        request['metadata']['ownership'] = params['ownership']

    # Handle cluster_refs for federated backup locations
    cluster_refs = _build_cluster_refs(params.get('cluster_refs'))
    if cluster_refs:
        request['backup_location']['cluster_refs'] = cluster_refs

    # Handle cloud credential reference (not required for federated identity)
    if params.get('cloud_credential_ref'):
        cloud_cred_ref = {}
        if params['cloud_credential_ref'].get('cloud_credential_name'):
            cloud_cred_ref['name'] = params['cloud_credential_ref']['cloud_credential_name']
        if params['cloud_credential_ref'].get('cloud_credential_uid'):
            cloud_cred_ref['uid'] = params['cloud_credential_ref']['cloud_credential_uid']

        if cloud_cred_ref:
            request['backup_location']['cloud_credential_ref'] = cloud_cred_ref

    # Add location-specific configuration based on type
    location_type = params.get('location_type')

    if location_type == 'S3' and params.get('s3_config'):
        s3_config = {}
        s3_fields = [
            'endpoint', 'region', 'disable_ssl', 'disable_path_style',
            'storage_class', 'sse_type', 'azure_environment',
            'azure_resource_group_name', 'azure_account_name', 'azure_subscription_id'
        ]
        for key in s3_fields:
            if params['s3_config'].get(key) is not None:
                s3_config[key] = params['s3_config'][key]
        if s3_config:
            request['backup_location']['s3_config'] = s3_config
            
    elif location_type == 'Azure':
        # Azure backup locations carry their config under s3_config on the wire
        # (server proto reuses S3Config for Azure-specific fields). Two input shapes:
        #   - Non-federated: azure_config has azure_environment as a string + creds
        #     elsewhere via cloud_credential_ref.
        #   - Federated (use_workload_identity=true): s3_config has azure_environment
        #     as a dict plus azure_resource_group_name / azure_account_name /
        #     azure_subscription_id. No cloud_credential_ref.
        s3_config = {}

        if params.get('azure_config'):
            azure_env_str = params['azure_config'].get('azure_environment')
            if azure_env_str:
                s3_config['azure_environment'] = {'type': azure_env_str}

        if params.get('s3_config'):
            for key in ['azure_environment', 'azure_resource_group_name',
                        'azure_account_name', 'azure_subscription_id']:
                val = params['s3_config'].get(key)
                if val is not None:
                    s3_config[key] = val

        if s3_config:
            request['backup_location']['s3_config'] = s3_config

    elif location_type == 'Google':
        # Google backup locations carry their WLI config under s3_config on the wire
        # (server proto reuses S3Config). In federated (use_workload_identity=true) mode
        # the GCP project ID must be supplied directly here since no cloud credential is
        # referenced; in non-federated mode it is derived from the cloud credential's JSON
        # key. The project ID is immutable, so it is only sent on CREATE and is preserved
        # by the server on UPDATE.
        google_project_id = (params.get('s3_config') or {}).get('google_project_id')
        if google_project_id is not None and params.get('operation') == 'CREATE':
            request['backup_location']['s3_config'] = {
                'google_project_id': google_project_id
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

        elif operation == 'SYNC':
            backup_location, changed = sync_backup_location(module, client)
            # Extract sync_info from the response for convenience
            bl_info = backup_location.get('backup_location_info', backup_location.get('backup_location', {}))
            sync_info = bl_info.get('sync_info', {})
            sync_status = sync_info.get('status', 'Unknown')
            message = f"Backup sync triggered successfully"
            if module.params.get('wait_for_completion'):
                message = f"Backup sync completed with status: {sync_status}"
            return OperationResult(
                success=True,
                changed=changed,
                data={'backup_location': backup_location, 'sync_info': sync_info},
                message=message
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
                'UPDATE_OWNERSHIP',
                'SYNC'
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
        federated=dict(type='bool', required=False, default=False),
        sync=dict(type='bool', required=False, default=False),
        sync_timeout=dict(type='int', required=False, default=600),
        sync_poll_interval=dict(type='int', required=False, default=10),
        wait_for_completion=dict(type='bool', required=False, default=False),
        cluster_refs=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),
        cloud_credential_ref=dict(
            type='dict',
            required=False,
            options=dict(
                cloud_credential_name=dict(type='str', required=True),
                cloud_credential_uid=dict(type='str', required=False)
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
                azure_resource_group_name=dict(type='str'),
                azure_account_name=dict(type='str', no_log=True),
                azure_subscription_id=dict(type='str', no_log=True),
                google_project_id=dict(type='str')
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
        ownership=dict(type='dict', required=False),
        include_secrets=dict(type='bool', default=False)
    )

    result = {
        'changed': False,
        'backup_location': {},
        'backup_locations': [],
        'sync_info': {},
        'message': ''
    }

    # Define required parameters for each operation
    operation_requirements = {
        'CREATE': ['name', 'location_type', 'path'],
        'UPDATE': ['name', 'location_type', 'path'],
        'DELETE': ['name'],
        'VALIDATE': ['name'],
        'INSPECT_ONE': ['name'],
        'INSPECT_ALL': ['org_id'],
        'UPDATE_OWNERSHIP': ['name', 'ownership'],
        'SYNC': ['name'],
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            # S3 is intentionally omitted here: s3_config is required only in
            # non-federated mode (enforced in validate_s3_backup_location_params).
            # In federated (Workload Identity) mode s3_config is optional - region
            # falls back to AWS_REGION on the Stork pod - matching the CLI, which
            # allows an S3 workload-identity backup location with no region.
            ('location_type', 'NFS', ['nfs_config'])
        ]
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
        # ca_cert is only used when server cert verification is enabled
        if ssl_config.get('validate_certs', True):
            cert_path = ssl_config.get('ca_cert')
            if cert_path:
                if not os.path.exists(cert_path):
                    module.fail_json(msg=f"ssl_config.ca_cert file not found: {cert_path}")
                if not os.access(cert_path, os.R_OK):
                    module.fail_json(msg=f"ssl_config.ca_cert file not readable: {cert_path}")
        # client_cert and client_key are for mutual TLS — independent of validate_certs
        for cert_param in ['client_cert', 'client_key']:
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