#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup LDAP Configuration Management Module

This Ansible module manages LDAP configuration in PX-Backup, providing operations for:
- Creating LDAP configurations
- Updating existing LDAP configurations
- Deleting LDAP configurations
- Inspecting LDAP configurations (single or all)
- Testing LDAP connections
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from typing import Dict, Any, Tuple, Optional, List, Union
from dataclasses import dataclass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.px_backup.api import PXBackupClient
import requests

DOCUMENTATION = r'''
---
module: ldap

short_description: Manage LDAP configuration in PX-Backup

version_added: "2.8.1"

description: 
    - Manage LDAP configuration in PX-Backup
    - Supports update operation
    - Supports connection testing and validation
    - Provides both single configuration and bulk inspection capabilities

options:
    auth_url:
        description: px-central-ui URL
        required: true
        type: str
    token:
        description: Authentication token
        required: true
        type: str
    operation:
        description: 
            - Operation to perform on the LDAP configuration
            - 'UPDATE' modifies an existing LDAP configuration
        required: true
        type: str
        choices: ['UPDATE']
    name:
        description:
            - Name of the LDAP configuration
            - Required for all operations except INSPECT_ALL
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    uid:
        description: 
            - Unique identifier of the LDAP configuration
            - Required for UPDATE, DELETE, and TEST operations
        required: false
        type: str
    ldap_config:
        description: LDAP configuration details
        required: false
        type: dict
        suboptions:
            connection_url:
                description: LDAP server URL (e.g., ldap://server:port)
                type: str
                required: true
            bind_dn:
                description: Bind DN for LDAP authentication
                type: str
                required: true
            bind_credential:
                description: Password for bind DN
                type: str
                required: true
                no_log: true
            users_dn:
                description: Base DN for user search
                type: str
                required: true
            username_attribute:
                description: LDAP attribute for username
                type: str
                default: 'cn'
            user_object_classes:
                description: Object classes for user objects
                type: str
                default: 'person, organizationalPerson, user'
            search_scope:
                description: Search scope for LDAP queries
                type: str
                choices: ['1', '2']
                default: '2'
            vendor:
                description: LDAP vendor type
                type: str
                choices: ['ad', 'other']
                default: 'ad'
            uuid_attribute:
                description: Attribute for unique user ID
                type: str
                default: 'objectGUID'
            connection_pooling:
                description: Enable connection pooling
                type: bool
                default: false
            pagination:
                description: Enable result pagination
                type: bool
                default: false
            start_tls:
                description: Use StartTLS
                type: bool
                default: false
            import_enabled:
                description: Enable user import
                type: bool
                default: true
            sync_registrations:
                description: Enable registration synchronization
                type: bool
                default: true
            connection_timeout:
                description: Connection timeout in milliseconds
                type: int
                default: 10000
            read_timeout:
                description: Read timeout in milliseconds
                type: int
                default: 10000
            validate_certs:
                description: Verify SSL certificates
                type: bool
                default: true
            custom_user_search_filter:
                description: Custom LDAP filter for user search
                type: str
                required: false
            full_sync_period:
                description: Full synchronization period in seconds
                type: int
                default: -1
            changed_sync_period:
                description: Changed users sync period in seconds
                type: int
                default: -1
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true

requirements:
    - python >= 3.6
    - requests
'''

EXAMPLES = r'''
# Create new LDAP configuration
- name: Configure LDAP
  ldap:
    operation: UPDATE
    auth_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "corporate-ldap"
    org_id: "default"
    ldap_config:
      connection_url: "ldap://ldap.example.com:389"
      bind_dn: "cn=admin,dc=example,dc=com"
      bind_credential: "{{ ldap_password }}"
      users_dn: "ou=users,dc=example,dc=com"
      username_attribute: "cn"
      vendor: "ad"
      search_scope: "2"
'''


def update_ldap_config(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing LDAP configuration"""
    try:
        params = dict(module.params)
        ldap_request = build_ldap_request(params)
        ldap_request['id'] = params['uid']
        
        # Use the correct Keycloak admin API endpoint
        response = client.make_request(
            method='PUT',
            endpoint=f"/auth/admin/realms/master/components/{params['uid']}",
            data=ldap_request
        )
        
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update LDAP configuration: {str(e)}")


def build_ldap_request(params: Dict[str, Any]) -> Dict[str, Any]:
    """Build LDAP configuration request object"""
    config = params.get('ldap_config', {})
    
    # Basic request structure
    request = {
        "name": params['name'],
        "providerId": "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            "connectionUrl": [config.get('connection_url')],
            "bindDn": [config.get('bind_dn')],
            "bindCredential": [config.get('bind_credential')],
            "usersDn": [config.get('users_dn')],
            "usernameLDAPAttribute": [config.get('username_attribute', 'cn')],
            "userObjectClasses": [config.get('user_object_classes', 'person, organizationalPerson, user')],
            "searchScope": [config.get('search_scope', '2')],
            "vendor": [config.get('vendor', 'ad')],
            "uuidLDAPAttribute": [config.get('uuid_attribute', 'objectGUID')],
            "connectionPooling": [str(config.get('connection_pooling', False)).lower()],
            "pagination": [str(config.get('pagination', False)).lower()],
            "startTls": [str(config.get('start_tls', False)).lower()],
            "importEnabled": [str(config.get('import_enabled', True)).lower()],
            "syncRegistrations": [str(config.get('sync_registrations', True)).lower()],
            "connectionTimeout": [str(config.get('connection_timeout', 10000))],
            "readTimeout": [str(config.get('read_timeout', 10000))]
        }
    }
    
    # Add optional configurations
    if config.get('custom_user_search_filter'):
        request['config']['customUserSearchFilter'] = [config['custom_user_search_filter']]
    
    if config.get('full_sync_period') is not None:
        request['config']['fullSyncPeriod'] = [str(config['full_sync_period'])]
        
    if config.get('changed_sync_period') is not None:
        request['config']['changedSyncPeriod'] = [str(config['changed_sync_period'])]

    return request

def needs_update(current: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """Compare current and desired state to determine if update is needed"""
    def normalize_dict(d: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize dictionary for comparison"""
        if not isinstance(d, dict):
            return d
        return {k: normalize_dict(v) for k, v in d.items() if v is not None}

    # Compare relevant configuration fields
    current_config = normalize_dict(current.get('config', {}))
    desired_config = normalize_dict(desired.get('config', {}))
    
    return current_config != desired_config

def run_module():
    """Main module execution"""
    module_args = dict(
        auth_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(
            type='str', 
            required=True,
            choices=['UPDATE']
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        ldap_config=dict(
            type='dict',
            required=False,
            options=dict(
                connection_url=dict(type='str', required=True),
                bind_dn=dict(type='str', required=True),
                bind_credential=dict(type='str', required=True, no_log=True),
                users_dn=dict(type='str', required=True),
                username_attribute=dict(type='str', default='cn'),
                user_object_classes=dict(type='str', default='person, organizationalPerson, user'),
                search_scope=dict(type='str', choices=['1', '2'], default='2'),
                vendor=dict(type='str', choices=['ad', 'other'], default='ad'),
                uuid_attribute=dict(type='str', default='objectGUID'),
                connection_pooling=dict(type='bool', default=False),
                pagination=dict(type='bool', default=False),
                start_tls=dict(type='bool', default=False),
                import_enabled=dict(type='bool', default=True),
                sync_registrations=dict(type='bool', default=True),
                connection_timeout=dict(type='int', default=10000),
                read_timeout=dict(type='int', default=10000),
                custom_user_search_filter=dict(type='str', required=False),
                full_sync_period=dict(type='int', default=-1),
                changed_sync_period=dict(type='int', default=-1),
                validate_certs=dict(type='bool', default=True)
            )
        ),
        validate_certs=dict(type='bool', default=True)
    )

    result = dict(
        changed=False,
        ldap_config={},
        ldap_configs=[],
        test_result={},
        message=''
    )

    # Define required parameters for each operation
    operation_requirements = {
        'UPDATE': ['name', 'uid', 'ldap_config']
    }

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('operation', 'UPDATE', ['name', 'uid', 'ldap_config']),
        ]
    )

    try:
        # Validate operation parameters
        operation = module.params['operation']

        if module.check_mode:
            module.exit_json(**result)

        # Initialize client
        client = PXBackupClient(
            module.params['auth_url'],
            module.params['token'],
            module.params['validate_certs']
        )

        changed = False

        if operation == 'UPDATE':
            ldap_config, changed = update_ldap_config(module, client)
            result['ldap_config'] = ldap_config
            result['message'] = "LDAP configuration updated successfully"

        result['changed'] = changed

    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=error_msg)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()