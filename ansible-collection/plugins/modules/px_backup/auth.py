#!/usr/bin/python

DOCUMENTATION = r'''
---
module: auth

short_description: Get Auth Token For PX-Backup

version_added: "2.8.1"

description: 
    - Generate auth token
    - Requires Username, Password and client_id

options:
    auth_url:
        description: Auth URL
        required: true
        type: str
    grant_type:
        description: Auth Type
        required: false
        type: str
    client_id:
        description: Client ID
        required: true
        type: str
    username:
        description: Username for auth
        required: true
        type: str
    password:
        description: Password
        required: true
        type: str
    token_duration:
        description: Duration of Token
        required: false
        type: str
    verify_ssl:
        description: Enable SSl verification
        required: false
        type: bool
        default: true
'''
from ansible.module_utils.basic import AnsibleModule
import requests

def request_bearer_token(auth_url, grant_type, client_id, username, password, token_duration, verify_ssl):
    """Send request to retrieve the bearer token."""
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Add protocol if not present
    if not auth_url.startswith(('http://', 'https://')):
        auth_url = f"http://{auth_url}" 
    url=f"{auth_url}/auth/realms/master/protocol/openid-connect/token"
    data = {
        'grant_type': grant_type,
        'client_id': client_id,
        'username': username,
        'password': password,
        'token-duration': token_duration
    }
    try:
        response = requests.post(url, headers=headers, data=data, verify=verify_ssl)
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error requesting bearer token: {e}")

def run_module():
    """Define the Ansible module."""
    module_args = dict(
        auth_url=dict(type='str', required=True),
        grant_type=dict(type='str', required=False, default="password", no_log=True),
        client_id=dict(type='str', required=True, no_log=True),
        username=dict(type='str', required=True, no_log=True),
        password=dict(type='str', required=True, no_log=True),
        token_duration=dict(type='str', required=False, default="7d"),
        verify_ssl=dict(type='bool', required=False, default=True)
    )

    result = dict(
        changed=False,
        access_token=None,
        error=None
    )

    # Initialize the module
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)

    # Collect input arguments
    auth_url = module.params['auth_url']
    grant_type = module.params['grant_type']
    client_id = module.params['client_id']
    username = module.params['username']
    password = module.params['password']
    token_duration = module.params['token_duration']
    verify_ssl = module.params['verify_ssl']

    try:
        # Make the API request to get the token
        token_response = request_bearer_token(auth_url, grant_type, client_id, username, password, token_duration, verify_ssl)
        
        # Extract the access token from the response
        access_token = token_response.get('access_token')

        if access_token:
            result['access_token'] = access_token
        else:
            result['error'] = 'Access token not found in response'
            module.fail_json(msg=result['error'])

    except Exception as e:
        result['error'] = str(e)
        module.fail_json(msg=result['error'])

    # Return the result to Ansible
    module.exit_json(**result)

if __name__ == '__main__':
    run_module()
