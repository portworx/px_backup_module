#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Cluster Utility Functions
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from typing import Dict, Any, List, Optional

from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient

def inspect_cluster(
    client: PXBackupClient,
    org_id: str,
    name: str,
    uid: str,
    include_secrets: bool = False
) -> Dict[str, Any]:
    """Get details of a specific cluster."""
    params = {
        'include_secrets': include_secrets
    }

    return client.make_request(
        method='GET',
        endpoint=f"v1/cluster/{org_id}/{name}/{uid}",
        params=params
    )

def enumerate_clusters(
    client: PXBackupClient,
    org_id: str,
    labels: Optional[Dict[str, str]] = None,
    include_secrets: bool = False,
    only_backup_share: bool = False,
    cloud_credential_ref: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """List all clusters in an organization."""
    params = {
        'labels': labels or {},
        'include_secrets': include_secrets,
        'only_backup_share': only_backup_share,
        'cloud_credential_ref': cloud_credential_ref or {},
    }
    # Filter out empty or default values that the API might not like
    params = {k: v for k, v in params.items() if v}

    response = client.make_request(
        method='GET',
        endpoint=f"v1/cluster/{org_id}",
        params=params
    )
    return response.get('clusters', [])


def find_cluster_by_name(client: PXBackupClient, org_id: str, name: str) -> Optional[Dict[str, Any]]:
    """Find a cluster by its name."""
    clusters = enumerate_clusters(client, org_id)
    for cluster in clusters:
        if cluster.get('metadata', {}).get('name') == name:
            return cluster
    return None


def find_cluster_by_uid(client: PXBackupClient, org_id: str, uid: str) -> Optional[Dict[str, Any]]:
    """Find a cluster by its UID."""
    clusters = enumerate_clusters(client, org_id)
    for cluster in clusters:
        if cluster.get('metadata', {}).get('uid') == uid:
            return cluster
    return None
