#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Cluster Info Module

This Ansible module retrieves information about clusters in PX-Backup.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from typing import Dict, List, Any

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.cluster import inspect_cluster as inspect_cluster_util, find_cluster_by_name, enumerate_clusters as enumerate_clusters_util
import requests

DOCUMENTATION = r'''
---
module: cluster_info

short_description: Get information about clusters in PX-Backup

version_added: "2.9.0"

description:
    - Retrieve details of PX-Backup clusters.
    - Can be used to get information about a single cluster by name, or all clusters within an organization.

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
    name:
        description:
            - Name of the cluster to inspect. If provided, fetches a single cluster.
            - If omitted, fetches all clusters.
        required: false
        type: str
    uid:
        description:
            - Unique identifier of the cluster to inspect. This is optional.
            - If not provided, the module will look up the cluster by `name`.
            - If omitted, fetches all clusters.
        required: false
        type: str
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    labels:
        description: Labels to filter clusters by when listing all clusters.
        required: false
        type: dict
    include_secrets:
        description: Include sensitive information in the response.
        type: bool
        default: false
    only_backup_share:
        description:
            - When listing all clusters, only return clusters with backup sharing enabled.
        type: bool
        default: false
    cloud_credential_ref:
        description:
            - Reference to cloud credentials to filter clusters by.
        required: false
        type: dict
        suboptions:
            name:
                description: Name of cloud credential
                type: str
            uid:
                description: UID of cloud credential
                type: str

requirements:
    - python >= 3.9
    - requests

notes:
    - This module is for read-only operations. To create, update, or delete clusters, use the `cluster` module.
'''

EXAMPLES = r'''
# List all clusters in an organization
- name: List all clusters
  cluster_info:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
  register: all_clusters

# Get details of a specific cluster
- name: Inspect a single cluster
  cluster_info:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "prod-cluster"
    uid: "cluster-uid-123"
  register: single_cluster
'''

RETURN = r'''
clusters:
    description: A list of cluster details.
    type: list
    returned: always
    sample: [
        {
            "metadata": {
                "name": "prod-cluster",
                "org_id": "default",
                "uid": "cluster-uid-123"
            },
            "clusterinfo": {
                "status": "Online"
            }
        }
    ]
message:
    description: Operation result message.
    type: str
    returned: always
'''

def run_module():
    """Main module execution"""
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        org_id=dict(type='str', required=True),
        name=dict(type='str', required=False),
        uid=dict(type='str', required=False),
        validate_certs=dict(type='bool', default=True),
        labels=dict(type='dict', required=False),
        include_secrets=dict(type='bool', default=False),
        only_backup_share=dict(type='bool', default=False),
        cloud_credential_ref=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=True),
                uid=dict(type='str', required=True)
            )
        )
    )

    result = dict(
        clusters=[],
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(**result)

    client = PXBackupClient(
        module.params['api_url'],
        module.params['token'],
        module.params['validate_certs']
    )

    try:
        cluster_name = module.params.get('name')
        cluster_uid = module.params.get('uid')

        if cluster_name:
            # User wants to inspect one cluster.
            # If UID is not provided, find it.
            if not cluster_uid:
                try:
                    found_cluster = find_cluster_by_name(client, module.params['org_id'], cluster_name)
                    if not found_cluster:
                        result['message'] = f"Cluster with name '{cluster_name}' not found."
                        module.exit_json(**result)
                    cluster_uid = found_cluster.get('metadata', {}).get('uid')
                except Exception as e:
                    module.fail_json(msg=f"Failed to find cluster by name '{cluster_name}': {str(e)}")

            if not cluster_uid:
                module.fail_json(msg=f"Could not determine UID for cluster '{cluster_name}'.")

            try:
                cluster_details = inspect_cluster_util(
                    client,
                    module.params['org_id'],
                    cluster_name,
                    cluster_uid,
                    module.params.get('include_secrets', False),
                )
                if cluster_details:
                    result['clusters'] = [cluster_details]
                    result['message'] = "Successfully retrieved cluster details."
                else:
                    result['message'] = "Cluster not found."
            except Exception as e:
                module.fail_json(msg=f"Failed to inspect cluster: {str(e)}")
        elif cluster_uid:
            module.fail_json(msg="Parameter 'name' is required when 'uid' is provided to inspect a single cluster.")
        else:
            # Enumerate all clusters
            clusters_list = enumerate_clusters_util(client,
                                                    module.params['org_id'],
                                                    module.params.get('labels'),
                                                    module.params.get('include_secrets'),
                                                    module.params.get('only_backup_share'),
                                                    module.params.get('cloud_credential_ref'))
            result['clusters'] = clusters_list
            result['message'] = f"Found {len(clusters_list)} clusters."

    except Exception as e:
        module.fail_json(msg=f"An unexpected error occurred: {str(e)}")

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
