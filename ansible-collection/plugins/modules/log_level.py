#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purepx.px_backup.plugins.module_utils.px_backup.api import PXBackupClient

DOCUMENTATION = r'''
---
module: log_level
short_description: Manage PX-Backup log levels
description:
    - Get and set log levels for PX-Backup services
    - Allows runtime log level changes without service restart
    - Supports Debug, Info, and Trace log levels
version_added: "2.10.0"

options:
    operation:
        description:
            - Operation to perform on log level
            - "INSPECT: retrieves current log level"
            - "UPDATE: sets new log level"
        required: true
        type: str
        choices: ['INSPECT', 'UPDATE']
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
    level:
        description:
            - Log level to set
            - Required when operation is UPDATE
            - "Debug: Most verbose logging"
            - "Info: Standard informational logging"
            - "Trace: Detailed trace logging"
        required: false
        type: str
        choices: ['Debug', 'Info', 'Trace']
    ssl_config:
        description: SSL certificate configuration
        required: false
        type: dict
        default: {}
        suboptions:
            validate_certs:
                description: Whether to validate SSL certificates
                type: bool
                default: true
            ca_cert:
                description: Path to CA certificate file
                type: path
            client_cert:
                description: Path to client certificate file
                type: path
            client_key:
                description: Path to client private key file
                type: path

requirements:
    - python >= 3.9

notes:
    - This module requires PX-Backup 2.10.0 or later
    - Log level changes take effect immediately without service restart
    - Log levels are organization-scoped
'''

EXAMPLES = r'''
# Get current log level
- name: Get current log level
  log_level:
    operation: INSPECT
    api_url: "http://px-backup.example.com:10001"
    token: "{{ px_backup_token }}"
    org_id: "default"

# Set log level to Debug
- name: Set log level to Debug
  log_level:
    operation: UPDATE
    api_url: "http://px-backup.example.com:10001"
    token: "{{ px_backup_token }}"
    org_id: "default"
    level: "Debug"

# Set log level to Info with SSL configuration
- name: Set log level to Info
  log_level:
    operation: UPDATE
    api_url: "https://px-backup.example.com:10001"
    token: "{{ px_backup_token }}"
    org_id: "default"
    level: "Info"
    ssl_config:
      validate_certs: true
      ca_cert: "/path/to/ca.pem"
'''

RETURN = r'''
level:
    description: Current or newly set log level
    type: str
    returned: always
    sample: "Debug"
changed:
    description: Whether the log level was changed
    type: bool
    returned: always
    sample: true
message:
    description: Operation result message
    type: str
    returned: always
    sample: "Log level set to Debug successfully"
'''


# Configure logging
logger = logging.getLogger('role')
logger.addHandler(logging.NullHandler())


# Custom exceptions
class LogLevelError(Exception):
    """Base exception for log level operations"""
    pass

class ValidationError(LogLevelError):
    """Raised when validation fails"""
    pass

class APIError(LogLevelError):
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


def handle_api_error(e: Exception, operation: str) -> str:
    """
    Handle API errors and format error message

    Args:
        e: Exception object
        operation: Operation being performed

    Returns:
        Formatted error message
    """
    import requests
    error_msg = str(e)
    if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
        try:
            error_detail = e.response.json()
            error_msg = f"{error_msg}: {error_detail}"
        except ValueError:
            error_msg = f"{error_msg}: {e.response.text}"
    return f"Failed to {operation.lower()} log level: {error_msg}"


def get_log_level(module: AnsibleModule, client: PXBackupClient) -> str:
    """Get current log level"""
    try:
        response = client.make_request(
            method='GET',
            endpoint=f"v1/loglevel/{module.params['org_id']}"
        )
        return response['current_level'] 

    except Exception as e:
        error_msg = handle_api_error(e, "inspect")
        logger.exception(error_msg)
        raise APIError(error_msg)


def set_log_level(module: AnsibleModule, client: PXBackupClient) -> bool:
    """Set log level"""
    try:
        # Use string level values as in original implementation
        request_payload = {
            "org_id": module.params['org_id'],
            "level": module.params['level']
        }

        client.make_request(
            method='POST',
            endpoint='v1/loglevel',
            data=request_payload
        )
        return True
        
    except Exception as e:
        error_msg = handle_api_error(e, "update")
        logger.exception(error_msg)
        raise APIError(error_msg)


def perform_operation(module: AnsibleModule, client: PXBackupClient, operation: str) -> OperationResult:
    """
    Perform the requested operation

    Args:
        module: Ansible module instance
        client: PX-Backup API client
        operation: Operation to perform

    Returns:
        OperationResult with operation details
    """
    try:
        if operation == 'INSPECT':
            current_level = get_log_level(module, client)
            return OperationResult(
                success=True,
                changed=False,
                data={'level': current_level},
                message=f"Current log level is {current_level}"
            )

        elif operation == 'UPDATE':
            # Get current level first to determine if change is needed
            current_level = get_log_level(module, client)
            new_level = module.params['level']

            if current_level != new_level:
                set_log_level(module, client)

                # Verify the change was actually applied
                verified_level = get_log_level(module, client)
                if verified_level == new_level:
                    return OperationResult(
                        success=True,
                        changed=True,
                        data={'level': new_level, 'previous_level': current_level},
                        message=f"Log level changed from {current_level} to {new_level}"
                    )
                else:
                    return OperationResult(
                        success=False,
                        changed=False,
                        data={'level': verified_level, 'expected_level': new_level},
                        message=f"Log level update failed. Expected: {new_level}, Actual: {verified_level}",
                        error=f"API reported success but level remains {verified_level} instead of {new_level}"
                    )
            else:
                return OperationResult(
                    success=True,
                    changed=False,
                    data={'level': current_level},
                    message=f"Log level already set to {current_level}"
                )
        else:
            raise ValidationError(f"Unsupported operation: {operation}")

    except (APIError, ValidationError) as e:
        return OperationResult(
            success=False,
            changed=False,
            error=str(e)
        )
    except Exception as e:
        error_msg = f"Unexpected error during {operation.lower()}: {str(e)}"
        logger.exception(error_msg)
        return OperationResult(
            success=False,
            changed=False,
            error=error_msg
        )



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


def run_module():
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(type='str', choices=['INSPECT', 'UPDATE'], required=True),
        org_id=dict(type='str', required=True),
        level=dict(type='str', choices=['Debug', 'Info', 'Trace'], required=False),
        ssl_config=dict(
            type='dict',
            required=False,
            default={},
            options=dict(
                validate_certs=dict(type='bool', default=True),
                ca_cert=dict(type='path'),
                client_cert=dict(type='path'),
                client_key=dict(type='path', no_log=True)
            )
        )
    )

    result = dict(
        changed=False,
        level='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('operation', 'UPDATE', ['level'])
        ]
    )

    if module.check_mode:
        module.exit_json(**result)

    # Initialize API client
    ssl_config = module.params.get('ssl_config', {})

    # Validate certificate files exist if provided in ssl_config
    import os
    for cert_param in ['ca_cert', 'client_cert', 'client_key']:
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

    operation_requirements = {
        'UPDATE': ['level'],
        'INSPECT': ['org_id'],
    }

    client = PXBackupClient(
        api_url=module.params['api_url'],
        token=module.params['token'],
        validate_certs=ssl_config.get('validate_certs', True),
        ca_cert=ssl_config.get('ca_cert'),
        client_cert=ssl_config.get('client_cert'),
        client_key=ssl_config.get('client_key')
    )

    try:
        # Validate operation parameters
        operation = module.params['operation']
        validate_params(module.params, operation, operation_requirements[operation])

        # Perform the operation using the standardized pattern
        operation_result = perform_operation(module, client, module.params['operation'])

        if operation_result.success:
         # Update result with operation data
            if operation_result.data:
                result.update(operation_result.data)
            result['message'] = operation_result.message
            result['changed'] = operation_result.changed
            module.exit_json(**result)
        else:
            # Operation failed
            error_msg = operation_result.error or "Unknown error occurred"
            module.fail_json(msg=error_msg)

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
