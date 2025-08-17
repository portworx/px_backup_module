#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Cluster Share Management Module

This Ansible module manages cluster and cluster backup sharing in PX-Backup.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from typing import Dict, Tuple, Any, List

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.cluster import inspect_cluster as inspect_cluster_util, find_cluster_by_name, find_cluster_by_uid
import requests

DOCUMENTATION = r'''
---
module: cluster_share

short_description: Manage cluster and backup sharing in PX-Backup

version_added: "2.9.0"

description:
    - "Manages sharing for both clusters and the backups associated with them."
    - "Uses a state-based approach (`present`/`absent`) for idempotent operations."

options:
    state:
        description:
            - "Whether the sharing configuration should be present or absent."
            - "`present` ensures that the specified sharing is active."
            - "`absent` ensures that the specified sharing is removed."
        required: true
        type: str
        choices: ['present', 'absent']
    share_target:
        description:
            - "The target of the sharing operation."
            - "`cluster` manages who can access the cluster itself."
            - "`backups` manages who can access the backups associated with the cluster."
        required: true
        type: str
        choices: ['cluster', 'backups']
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
        description: Name of the cluster.
        required: false
        type: str
    uid:
        description: Unique identifier of the cluster. Required if `name` is not provided.
        required: false
        type: str
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    users:
        description:
            - "List of user IDs for cluster sharing."
            - "Used when `share_target` is `cluster`."
        required: false
        type: list
        elements: str
    groups:
        description:
            - "List of group IDs for cluster sharing."
            - "Used when `share_target` is `cluster`."
        required: false
        type: list
        elements: str
    share_cluster_backups:
        description:
            - "When sharing a cluster, also share existing backups."
            - "Used when `share_target` is `cluster` and `state` is `present`."
        type: bool
        default: false
    backup_share:
        description:
            - "Configuration for sharing backups of the cluster."
            - "Used when `share_target` is `backups`."
        type: dict
        required: false
        suboptions:
            collaborators:
                description: List of user access configurations.
                type: list
                elements: dict
            groups:
                description: List of group access configurations.
                type: list
                elements: dict

requirements:
    - python >= 3.9
    - requests

notes:
    - To manage clusters (create, update, delete), use the `cluster` module.
    - To get cluster information, use the `cluster_info` module.
    - When `share_target` is `cluster`, the module is idempotent. It checks the current sharing state before making changes.
'''

EXAMPLES = r'''
# Share a cluster with a user and a group (idempotent)
- name: Ensure cluster is shared with the dev team
  cluster_share:
    state: present
    share_target: cluster
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "prod-cluster"
    uid: "cluster-uid-123"
    users:
      - "user@example.com"
    groups:
      - "dev-team"

# Add backup sharing permissions for a collaborator
- name: Add backup sharing permissions
  cluster_share:
    state: present
    share_target: backups
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "prod-cluster"
    uid: "cluster-uid-123"
    backup_share:
      collaborators:
        - id: "viewer@example.com"
          access: "View"

# Remove backup sharing permissions for a group
- name: Remove backup sharing permissions
  cluster_share:
    state: absent
    share_target: backups
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name: "prod-cluster"
    uid: "cluster-uid-123"
    backup_share:
      groups:
        - id: "old-team"
          access: "FullAccess"
'''

RETURN = r'''
cluster:
    description: The updated cluster object after the sharing operation.
    type: dict
    returned: on success
message:
    description: Operation result message.
    type: str
    returned: always
changed:
    description: Indicates if a change was made.
    type: bool
    returned: always
'''

def share_cluster(module: AnsibleModule, client: PXBackupClient, users: List[str], groups: List[str]) -> None:
    """Share cluster with specific users/groups."""
    request = {
        "org_id": module.params['org_id'],
        "cluster_ref": {"name": module.params['name'], "uid": module.params['uid']},
        "users": users,
        "groups": groups,
        "share_cluster_backups": module.params.get('share_cluster_backups', False)
    }
    client.make_request(method='PATCH', endpoint='v1/sharecluster', data=request)


def unshare_cluster(module: AnsibleModule, client: PXBackupClient, users: List[str], groups: List[str]) -> None:
    """Remove cluster sharing for specific users/groups."""
    request = {
        "org_id": module.params['org_id'],
        "cluster_ref": {"name": module.params['name'], "uid": module.params['uid']},
        "users": users,
        "groups": groups
    }
    client.make_request(method='PATCH', endpoint='v1/unsharecluster', data=request)


def manage_backup_share(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Add or remove backup sharing settings for a cluster."""
    access_type_map = {'Invalid': 0, 'View': 1, 'Restorable': 2, 'FullAccess': 3}

    def map_access_type(items):
        if not items:
            return []
        mapped_items = []
        for item in items:
            access_type = item.get('access')
            if access_type not in access_type_map:
                module.fail_json(msg=f"Invalid access_type: {access_type}. Must be one of: {', '.join(access_type_map.keys())}")
            mapped_items.append({"id": item["id"], "access": access_type_map[access_type]})
        return mapped_items

    state = module.params['state']
    backup_share_params = module.params.get('backup_share', {})
    if not backup_share_params:
        module.fail_json(msg="Parameter 'backup_share' is required when 'share_target' is 'backups'.")

    mapped_shares = {
        "groups": map_access_type(backup_share_params.get("groups", [])),
        "collaborators": map_access_type(backup_share_params.get("collaborators", []))
    }

    request = {"org_id": module.params['org_id'], "name": module.params['name'], "uid": module.params['uid']}

    if state == 'present':
        request['backupshare'] = mapped_shares
    else:  # absent
        request['backupshare'] = mapped_shares

    response = client.make_request(method='PUT', endpoint='v1/cluster/updatebackupshare', data=request)
    return response, True


def run_module():
    """Main module execution"""
    module_args = dict(
        state=dict(type='str', required=True, choices=['present', 'absent']),
        share_target=dict(type='str', required=True, choices=['cluster', 'backups']),
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        org_id=dict(type='str', required=True),
        name=dict(type='str', required=True),
        name=dict(type='str', required=False),
        uid=dict(type='str', required=False),
        validate_certs=dict(type='bool', default=True),
        users=dict(type='list', elements='str', required=False),
        groups=dict(type='list', elements='str', required=False),
        share_cluster_backups=dict(type='bool', default=False),
        backup_share=dict(
            type='dict',
            required=False,
            options=dict(
                collaborators=dict(type='list', elements='dict'),
                groups=dict(type='list', elements='dict')
            )
        )
    )

    result = dict(changed=False, cluster={}, message='')

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_one_of=[['name', 'uid']],
        required_if=[
            ('share_target', 'cluster', ['users', 'groups']),
            ('share_target', 'backups', ['backup_share']),
        ]
    )

    if module.check_mode:
        module.exit_json(**result)

    client = PXBackupClient(module.params['api_url'], module.params['token'], module.params['validate_certs'])
    share_target = module.params['share_target']
    state = module.params['state']
    name = module.params.get('name')
    uid = module.params.get('uid')

    if not uid and name:
        try:
            found_cluster = find_cluster_by_name(client, module.params['org_id'], name)
            if not found_cluster:
                module.fail_json(msg=f"Cluster with name '{name}' not found.")
            uid = found_cluster.get('metadata', {}).get('uid')
        except Exception as e:
            module.fail_json(msg=f"Failed to find cluster by name '{name}': {str(e)}")
    elif not name and uid:
        try:
            found_cluster = find_cluster_by_uid(client, module.params['org_id'], uid)
            if not found_cluster:
                module.fail_json(msg=f"Cluster with UID '{uid}' not found.")
            name = found_cluster.get('metadata', {}).get('name')
        except Exception as e:
            module.fail_json(msg=f"Failed to find cluster by UID '{uid}': {str(e)}")

    if not name or not uid:
        module.fail_json(msg="Could not determine both name and UID for the cluster.")

    # For subsequent calls, ensure both name and uid are in module.params
    module.params['name'] = name
    module.params['uid'] = uid

    try:
        if share_target == 'cluster':
            # NOTE: The structure of the cluster object's sharing information is assumed.
            # This is based on the behavior of the share/unshare APIs.
            try:
                current_cluster = inspect_cluster_util(client,
                                                       module.params['org_id'],
                                                       name,
                                                       uid)
            except Exception as e:
                module.fail_json(msg=f"Failed to inspect cluster for sharing state: {str(e)}")
            current_share_info = current_cluster.get('cluster', {}).get('metadata', {}).get('share', {})
            current_users = set(current_share_info.get('users', []))
            current_groups = set(current_share_info.get('groups', []))

            desired_users = set(module.params.get('users', []))
            desired_groups = set(module.params.get('groups', []))

            if state == 'present':
                users_to_add = list(desired_users - current_users)
                groups_to_add = list(desired_groups - current_groups)
                if users_to_add or groups_to_add:
                    share_cluster(module, client, users_to_add, groups_to_add)
                    result['changed'] = True
                    result['message'] = "Cluster sharing updated."
                else:
                    result['message'] = "Cluster sharing is already in the desired state."

            elif state == 'absent':
                users_to_remove = list(desired_users.intersection(current_users))
                groups_to_remove = list(desired_groups.intersection(current_groups))
                if users_to_remove or groups_to_remove:
                    unshare_cluster(module, client, users_to_remove, groups_to_remove)
                    result['changed'] = True
                    result['message'] = "Cluster sharing removed."
                else:
                    result['message'] = "Specified users/groups are not currently shared."

        elif share_target == 'backups':
            cluster_details, changed = manage_backup_share(module, client)
            result['cluster'] = cluster_details
            result['changed'] = changed
            result['message'] = "Cluster backup sharing updated successfully."

    except Exception as e:
        module.fail_json(msg=f"An unexpected error occurred: {str(e)}")

    module.exit_json(**result)


def main():
    run_module()

if __name__ == '__main__':
    main()
