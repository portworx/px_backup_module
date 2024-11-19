#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.px_backup.api import PXBackupClient
import requests
import json

DOCUMENTATION = r'''
---
module: cloud_credential

short_description: Manage cloud credential in PX-Backup

version_added: "2.8.1"

description: 
    - Manage cloud credential in PX-Backup
    - Supports create, update, delete, and list operations
    - Supports AWS, Azure, Google, IBM and Rancher credential

options:
    api_url:
        description: PX-Backup API URL
        required: true
        type: str
    token:
        description: Authentication token
        required: true
        type: str
    operation:
        description: 
            - Operation to be perform
            - 'CREATE'  create new cloud credential
            - 'DELETE'  delete cloud credential
            - 'UPDATE'  update cloud credential
            - 'UPDATE_OWNERSHIP' updates ownership settings of a cloud credential
            - 'INSPECT_ALL' lists all cloud credentials
            - 'INSPECT_ONE' retrieves details of a specific cloud credential
        choices: ['CREATE', 'DELETE', 'UPDATE', 'UPDATE_OWNERSHIP','INSPECT_ALL','INSPECT_ONE']
        default: CREATE
        type: str
    name:
        description: Name of the cloud credential
        required: false
        type: str
    org_id:
        description: Organization ID
        required: true
        type: str
    owner:
        description: Owner name
        required: false
        type: str
    uid:
        description: Unique identifier of the cloud credential (required for update/delete)
        required: false
        type: str
    credential_type:
        description: Type of cloud credential
        required: true
        choices: ['AWS', 'Azure', 'Google', 'IBM', 'Rancher']
        type: str
    "azure_config":
        description: Configuration for Azure Credential
        required: false
        type: dict
        suboptions:
            account_name:
                description: Account name
                type: str
            account_key:
                description: Account Key
                type: str
            client_secret:
                description: Client Secret
                type: bool
            client_id:
                description: Client ID
                type: bool
            tenant_id:
                description: Tenant ID
                type: str
            subscription_id:
                description: Subscription ID
                type: str
    aws_config:
        description: Configuration for AWS Credential
        required: false
        type: dict
        suboptions:
            access_key:
                description: AWS Access Key
                type: str
            secret_key:
                description: Secret Key
                type: str
    google_config:
        description: Configuration for Google Credential
        required: false
        type: dict
        suboptions:
            project_id:
                description: Google Project ID
                type: str
            json_key:
                description: Josn Key
                type: str
    rancher_config:
        description: Configuration for Rancher Credential
        required: false
        type: dict
        suboptions:
            endpoint:
                description: Rancher Endpoint
                type: str
            token:
                description: Racher Token
                type: str
    ibm_config:
        description: Configuration for IBM Credential
        required: false
        type: dict
        suboptions:
            api_key:
                description: IBM API Key
                type: str
    validate_certs:
        description: Verify SSL certificates
        type: bool
        default: true
    labels:
        description: Labels to attach to the cloud credential
        required: false
        type: dict
    ownership:
        description: Ownership configuration for the cloud credential
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the cloud credential
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
'''

def create_cloud_credential(module, client):
    """Create a new Cloud Credential"""
    cloud_credential_request = cloud_credential_request_body(module)
    
    try:
        response = client.make_request('POST', 'v1/cloudcredential', cloud_credential_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to create Cloud Credential: {str(e)}")

def update_cloud_credential(module, client):
    """Update an existing Cloud Credential"""
    cloud_credential_request = cloud_credential_request_body(module)
    cloud_credential_request['metadata']['uid'] = module.params['uid']
    
    try:    
        response = client.make_request('PUT', 'v1/cloudcredential', cloud_credential_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update Cloud Credential: {str(e)}")

def update_ownership(module, client):
    """Update ownership of a Cloud Credential"""
    ownership_request = {
        "org_id": module.params['org_id'],
        "name": module.params['name'],
        "ownership": module.params['ownership'],
        "uid": module.params['uid']
    }
    try:
        response = client.make_request('PUT', 'v1/cloudcredential/updateownership', ownership_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update Cloud Credential ownership: {str(e)}")

def enumerate_cloud_credentials(module, client):
    """List all Cloud Credentials"""
    params = {
        'include_secrets': module.params.get('include_secrets', False)
    }
    try:
        response = client.make_request('GET', f"v1/cloudcredential/{module.params['org_id']}", params=params)
        return response['cloud_credentials']
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate Cloud Credential: {str(e)}")

def inspect_cloud_credentials(module, client):
    """Get details of a specific Cloud Credential"""
    params = {
        'include_secrets': module.params.get('include_secrets', False)
    }
    try:
        response = client.make_request(
            'GET',
            f"v1/cloudcredential/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}",
            params=params
        )
        return response['cloud_credential']
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect Cloud Credential: {str(e)}")

def delete_cloud_credentials(module, client):
    """Delete a Cloud Credential"""
    try:
        response = client.make_request(
            'DELETE',
            f"v1/cloudcredential/{module.params['org_id']}/{module.params['name']}/{module.params['uid']}"
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete Cloud Credential: {str(e)}")

def cloud_credential_request_body(module):
    """Build the Cloud Credential request object"""
    cloud_credential_request = {
        "metadata": {
            "name": module.params['name'],
            "org_id": module.params['org_id'],
            "owner": module.params['owner']
        },
        "cloud_credential": {
            "type": module.params['credential_type']
        }
    }

    if module.params.get('labels'):
        cloud_credential_request['metadata']['labels'] = module.params['labels']
        
    if module.params.get('ownership'):
        cloud_credential_request['metadata']['ownership'] = module.params['ownership']

    if module.params['credential_type'] == 'AWS' and module.params.get('aws_config'):
        cloud_credential_request['cloud_credential']['aws_config'] = module.params['aws_config']

    elif module.params['credential_type'] == 'IBM' and module.params.get('ibm_config'):
        cloud_credential_request['cloud_credential']['ibm_config'] = module.params['ibm_config']
    
    elif module.params['credential_type'] == 'Azure' and module.params.get('azure_config'):
        cloud_credential_request['cloud_credential']['azure_config'] = module.params['azure_config']
    
    elif module.params['credential_type'] == 'Google' and module.params.get('google_config'):
        cloud_credential_request['cloud_credential']['google_config'] = module.params['google_config']
    
    elif module.params['credential_type'] == 'Rancher' and module.params.get('rancher_config'):
        cloud_credential_request['cloud_credential']['rancher_config'] = module.params['rancher_config']

    return cloud_credential_request

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

def run_module():
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(type='str', choices=['CREATE', 'UPDATE', 'DELETE','INSPECT_ALL','UPDATE_OWNERSHIP','INSPECT_ONE'], default='CREATE'),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        owner=dict(type='str', required=False),
        credential_type=dict(type='str', required=False, choices=['AWS', 'Azure', 'Google', 'IBM', 'Rancher']),

        aws_config=dict(type='dict', required=False, options=dict(
            access_key=dict(type='str',no_log=True),
            secret_key=dict(type='str',no_log=True),
        )),
        azure_config=dict(type='dict', required=False, options=dict(
            account_name=dict(type='str'),
            account_key=dict(type='str'),
            client_id=dict(type='str'),
            tenant_id=dict(type='str'),
            subscription_id=dict(type='str'),
            client_secret=dict(type='str')
        )),
        ibm_config=dict(type='dict', required=False, options=dict(
            api_key=dict(type='str')
        )),
        google_config=dict(type='dict', required=False, options=dict(
            project_id=dict(type='str'),
            json_key=dict(type='str')
        )),
        rancher_config=dict(type='dict', required=False, options=dict(
            endpoint=dict(type='str'),
            token=dict(type='str')
        )),
        validate_certs=dict(type='bool', default=True),
        labels=dict(type='dict', required=False),
        ownership=dict(type='dict', required=False, options=dict(
            owner=dict(type='str'),
            groups=dict(type='list', elements='dict', options=dict(
                id=dict(type='str'),
                access=dict(type='str', choices=['Invalid', 'Read', 'Write', 'Admin'])
            )),
            collaborators=dict(type='list', elements='dict', options=dict(
                id=dict(type='str'),
                access=dict(type='str', choices=['Invalid', 'Read', 'Write', 'Admin'])
            )),
            public=dict(type='dict', options=dict(
                type=dict(type='str', choices=['Invalid', 'Read', 'Write', 'Admin'])
            ))
        )),
    )

    result = dict(
        changed=False,
        cloud_credential={},
        cloud_credentials=[],
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('credential_type', 'AWS', ['aws_config']),
            ('credential_type', 'Azure', ['azure_config']),
            ('credential_type', 'Google', ['google_config']),
            ('credential_type', 'IBM', ['ibm_config']),
            ('credential_type', 'Racher', ['rancher_config'])
        ],

    )

    if module.check_mode:
        module.exit_json(**result)

    client = PXBackupClient(
        module.params['api_url'],
        module.params['token'],
        module.params['validate_certs']
    )

    try:

        # Handle other states
        if module.params['operation'] == 'CREATE':
            cloud_credential, changed = create_cloud_credential(module, client)
            result['message'] = "Cloud Credential created successfully"

        elif module.params['operation'] == 'UPDATE':
            # Update existing backup location
            cloud_credential, changed = update_cloud_credential(module, client)
            result['message'] = "Cloud Credential updated successfully"

        elif module.params['operation'] == 'UPDATE_OWNERSHIP':
            # Update existing backup location
            cloud_credential, changed = update_ownership(module, client)
            result['message'] = "Cloud Credential Ownership update successfully"

        elif module.params['operation'] == 'INSPECT_ALL':
            # Update existing backup location
            cloud_credentials = enumerate_cloud_credentials(module, client)
            message=f"Found {len(cloud_credentials)} Cloud Credential"
            result['message'] = message
            result['cloud_credentials']= cloud_credentials

        elif module.params['operation'] == 'INSPECT_ONE':
            # Update existing backup location
            cloud_credential = inspect_cloud_credentials(module, client)
            result['message'] = "Cloud Credential Found successfully"
            result['cloud_credential']= cloud_credential

        elif module.params['operation'] == 'DELETE':
            # Update existing backup location
            cloud_credential, changed = delete_cloud_credentials(module, client)
            result['message'] = "Cloud Credential Deleted successfully"




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