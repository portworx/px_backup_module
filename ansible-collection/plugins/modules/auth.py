#!/usr/bin/python

DOCUMENTATION = r'''
---
module: auth

short_description: Get Auth Token For PX-Backup

version_added: "2.8.1"

description:
    - Generate authentication token for PX-Backup operations
    - Supports username/password authentication
    - Handles token duration configuration
    - Manages client authentication
    - Provides secure token generation and retrieval

options:
    auth_url:
        description: 
            - URL of the authentication server
            - Used as the base URL for token generation
        required: true
        type: str
    grant_type:
        description:
            - Type of authentication grant to use
            - Currently only supports "password" grant type
        required: false
        type: str
        default: "password"
    client_id:
        description:
            - Client identifier for authentication
            - Used to identify the application requesting access
        required: true
        type: str
        no_log: true
    username:
        description:
            - Username for authentication
            - Must be a valid user with appropriate permissions
        required: true
        type: str
        no_log: true
    password:
        description:
            - Password for authentication
            - Used in combination with username for authentication
        required: true
        type: str
        no_log: true
    token_duration:
        description:
            - Duration for which the token should be valid
            - "Format examples: '7d' for 7 days, '24h' for 24 hours"
            - Default is 7 days if not specified
        required: false
        type: str
        default: "7d"

requirements:
    - python >= 3.9
    - requests

notes:
    - "Token generation requires valid credentials"
    - "The token should be securely stored and handled"
    - "Token duration affects security - shorter durations are more secure"
    - "Invalid credentials will result in authentication failure"
    - "Network connectivity to auth server required"
'''

EXAMPLES = r'''
# Generate a token with default settings
- name: Get PX-Backup auth token
  auth:
    auth_url: "https://px-backup-auth.example.com"
    client_id: "px-backup"
    username: "admin"
    password: "{{ admin_password }}"

# Generate a token with custom duration
- name: Get short-lived token
  auth:
    auth_url: "https://px-backup-auth.example.com"
    client_id: "px-backup"
    username: "admin"
    password: "{{ admin_password }}"
    token_duration: "1h"
    
# Generate and store token for later use
- name: Get and store token
  auth:
    auth_url: "{{ px_backup_auth_url }}"
    client_id: "{{ px_backup_client_id }}"
    username: "{{ px_backup_username }}"
    password: "{{ px_backup_password }}"
  register: auth_result

- name: Use generated token
  set_fact:
    px_backup_token: "{{ auth_result.access_token }}"
'''

RETURN = r'''
access_token:
    description: The generated authentication token
    type: str
    returned: success
    sample: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
error:
    description: Error message if token generation failed
    type: str
    returned: failure
    sample: "Authentication failed: Invalid credentials"
changed:
    description: Whether the token generation changed anything
    type: bool
    returned: always
    sample: false
'''
from ansible.module_utils.basic import AnsibleModule
import requests

def request_bearer_token(auth_url, grant_type, client_id, username, password, token_duration):
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
        response = requests.post(url, headers=headers, data=data)
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
        token_duration=dict(type='str', required=False, default="7d")
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

    try:
        # Make the API request to get the token
        token_response = request_bearer_token(auth_url, grant_type, client_id, username, password, token_duration)
        
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
