#!/usr/bin/python

DOCUMENTATION = r'''
---
module: auth

short_description: Get Auth Token For PX-Backup

version_added: "2.9.0"

description:
    - Generate authentication token for PX-Backup operations
    - Supports username/password authentication
    - Handles token duration configuration
    - Manages client authentication
    - Provides secure token generation and retrieval
    - Supports custom SSL/TLS certificate configuration

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
    verify_ssl:
        description: 
            - Enable SSL verification
            - Can be set to false for self-signed certificates
            - Overridden by ca_cert if provided
        required: false
        type: bool
        default: true
    ca_cert:
        description:
            - Path to CA certificate file to verify SSL certificates
            - If provided, this CA certificate will be used instead of system CA certificates
            - Takes precedence over verify_ssl setting
        required: false
        type: path
        version_added: "2.10.0"
    client_cert:
        description:
            - Path to client certificate file for mutual TLS authentication
            - Must be used together with client_key
        required: false
        type: path
        version_added: "2.10.0"
    client_key:
        description:
            - Path to client key file for mutual TLS authentication
            - Required if client_cert is provided
            - File permissions should be restricted (e.g., 600)
        required: false
        type: path
        no_log: true
        version_added: "2.10.0"

requirements:
    - python >= 3.9
    - requests

notes:
    - "Token generation requires valid credentials"
    - "The token should be securely stored and handled"
    - "Token duration affects security - shorter durations are more secure"
    - "Invalid credentials will result in authentication failure"
    - "Network connectivity to auth server required"
    - "When using client certificates, both client_cert and client_key must be provided"
    - "Certificate files must be readable by the user running the playbook"
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

# Generate token with custom CA certificate
- name: Get token with custom CA
  auth:
    auth_url: "https://px-backup-auth.example.com"
    client_id: "px-backup"
    username: "admin"
    password: "{{ admin_password }}"
    ca_cert: "/etc/ssl/certs/custom-ca.pem"

# Generate token with mutual TLS authentication
- name: Get token with client certificates
  auth:
    auth_url: "https://px-backup-auth.example.com"
    client_id: "px-backup"
    username: "admin"
    password: "{{ admin_password }}"
    ca_cert: "/etc/ssl/certs/custom-ca.pem"
    client_cert: "/etc/ssl/certs/client.pem"
    client_key: "/etc/ssl/private/client.key"
    
# Generate and store token for later use
- name: Get and store token
  auth:
    auth_url: "{{ px_backup_auth_url }}"
    client_id: "{{ px_backup_client_id }}"
    username: "{{ px_backup_username }}"
    password: "{{ px_backup_password }}"
    ca_cert: "{{ px_backup_ca_cert | default(omit) }}"
    client_cert: "{{ px_backup_client_cert | default(omit) }}"
    client_key: "{{ px_backup_client_key | default(omit) }}"
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

def request_bearer_token(auth_url, grant_type, client_id, username, password, 
                        token_duration, verify_ssl, ca_cert=None, client_cert=None, client_key=None):
    """Send request to retrieve the bearer token."""
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Add protocol if not present
    if not auth_url.startswith(('http://', 'https://')):
        auth_url = f"http://{auth_url}" 
    url = f"{auth_url}/auth/realms/master/protocol/openid-connect/token"
    
    data = {
        'grant_type': grant_type,
        'client_id': client_id,
        'username': username,
        'password': password,
        'token-duration': token_duration
    }
    
    # Determine certificate verification
    # certificate verification logic
    if not verify_ssl:
        # If SSL verification is disabled, ignore ca_cert
        verify = False
    elif ca_cert:
        # If SSL verification enabled and custom CA provided
        verify = ca_cert
    else:
        # If SSL verification enabled, use system certificates
        verify = True

    # Handle client certificates for mutual TLS
    cert = None
    if client_cert and client_key:
        cert = (client_cert, client_key)
    elif client_cert:
        # If only client_cert is provided without key, it might be a combined file
        cert = client_cert
    
    try:
        response = requests.post(
            url, 
            headers=headers, 
            data=data, 
            verify=verify,
            cert=cert
        )
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        # Enhanced error handling for certificate issues
        error_msg = str(e)
        if "certificate verify failed" in error_msg.lower():
            error_msg = f"SSL certificate verification failed: {error_msg}. Consider using ca_cert parameter or setting verify_ssl to false."
        elif "SSLError" in error_msg:
            error_msg = f"SSL error occurred: {error_msg}. Check your certificate paths and permissions."
        raise Exception(f"Error requesting bearer token: {error_msg}")

def run_module():
    """Define the Ansible module."""
    module_args = dict(
        auth_url=dict(type='str', required=True),
        grant_type=dict(type='str', required=False, default="password", no_log=False),
        client_id=dict(type='str', required=True, no_log=False),
        username=dict(type='str', required=True, no_log=False),
        password=dict(type='str', required=True, no_log=False),
        token_duration=dict(type='str', required=False, default="7d"),
        verify_ssl=dict(type='bool', required=False, default=True),
        ca_cert=dict(type='path'),
        client_cert=dict(type='path'),
        client_key=dict(type='path', no_log=False), 
    )

    result = dict(
        changed=False,
        access_token=None,
        error=None
    )

    # Initialize the module
    module = AnsibleModule(
        argument_spec=module_args, 
        supports_check_mode=False,
        # Add mutual exclusion or dependencies if needed
        required_together=[
            ['client_cert', 'client_key']  # If client_cert is provided, client_key must also be provided
        ]
    )

    # Collect input arguments
    auth_url = module.params['auth_url']
    grant_type = module.params['grant_type']
    client_id = module.params['client_id']
    username = module.params['username']
    password = module.params['password']
    token_duration = module.params['token_duration']
    verify_ssl = module.params['verify_ssl']
    ca_cert = module.params.get('ca_cert')
    client_cert = module.params.get('client_cert')
    client_key = module.params.get('client_key')

    # Validate certificate files exist if provided
    for cert_param, cert_path in [('ca_cert', ca_cert), ('client_cert', client_cert), ('client_key', client_key)]:
        if cert_path:
            import os
            if not os.path.exists(cert_path):
                module.fail_json(msg=f"{cert_param} file not found: {cert_path}")
            if not os.access(cert_path, os.R_OK):
                module.fail_json(msg=f"{cert_param} file not readable: {cert_path}")

    try:
        # Make the API request to get the token with certificate support
        token_response = request_bearer_token(
            auth_url, 
            grant_type, 
            client_id, 
            username, 
            password, 
            token_duration, 
            verify_ssl,
            ca_cert,
            client_cert,
            client_key
        )
        
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