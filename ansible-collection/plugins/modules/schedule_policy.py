# !/usr/bin/python
# -*- coding: utf-8 -*-

"""
PX-Backup Schedule Policy Management Module

This Ansible module manages schedule policies in PX-Backup, providing operations for:
- Creating policies
- Updating existing policies
- Deleting policies
- Inspecting policies (single or all)
- Managing policy ownership

Version 2.11.0 adds support for advanced scheduling features:
- Multi-day weekly schedules
- Bi-weekly scheduling
- Relative monthly policies (first/second/third/fourth/last weekday of month)
- Selective monthly policies (specific dates with month selection)
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
module: schedule_policy

short_description: Manage schedule policy in PX-Backup

version_added: "2.11.0"

description: 
    - Manage schedule policy in PX-Backup
    - Supports create, update, update_ownership, delete, and list operations
    - Version 2.11.0 adds support for advanced scheduling features including multi-day weekly,
      bi-weekly, relative monthly, and selective monthly policies

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
            - "- CREATE:  create new schedule policy"
            - "- DELETE:  delete schedule policy"
            - "- UPDATE:  update schedule policy"
            - "- UPDATE_OWNERSHIP: updates ownership settings of a schedule policy"
            - "- INSPECT_ALL: lists all schedule policies"
            - "- INSPECT_ONE: retrieves details of a specific schedule policy"
        choices: ['CREATE', 'DELETE', 'UPDATE', 'UPDATE_OWNERSHIP','INSPECT_ALL','INSPECT_ONE']
        default: CREATE
        type: str
    name:
        description: Name of the schedule policy
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
        description: Unique identifier of the schedule policy
        required: false
        type: str
    ssl_config:
        description:
            - SSL configuration dictionary containing certificate settings
            - Contains validate_certs, ca_cert, client_cert, and client_key options
            - If not provided, defaults to standard SSL verification
        required: false
        type: dict
        default: {}
        options:
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
        description: Labels to attach to the schedule policy
        required: false
        type: dict
    schedule_policy:
        description: Configuration for schedule policies, defining intervals, retention, and scheduling details.
        required: false
        type: dict
        suboptions:
            interval:
                description: Interval-based scheduling configuration.
                type: dict
                suboptions:
                    minutes:
                        description: The interval in minutes for the schedule.
                        type: int
                    retain:
                        description: The number of schedules to retain.
                        type: int
                    incremental_count:
                        description: Configuration for incremental schedule count.
                        type: dict
                        suboptions:
                            count:
                                description: Number of incremental schedules to retain.
                                type: int
            daily:
                description: Daily scheduling configuration.
                type: dict
                suboptions:
                    time:
                        description: 
                            - The time of day for the daily schedule.
                            - Expected format is time.Kitchen eg 12:04PM or 12:04pm.
                        type: str
                    retain:
                        description: The number of daily schedules to retain.
                        type: int
                    incremental_count:
                        description: Configuration for incremental schedule count.
                        type: dict
                        suboptions:
                            count:
                                description: Number of incremental schedules to retain.
                                type: int
            weekly:
                description: Weekly scheduling configuration.
                type: dict
                suboptions:
                    day:
                        description: 
                            - The day(s) of the week for the schedule.
                            - Single day example - "sunday" or "sun"
                            - Multiple days can be configured with comma separation.
                            - Multiple days example - "sunday,monday" or "sun,mon" or "Sun,Mon"
                        type: str
                    time:
                        description: 
                            - The time of day for the weekly schedule.
                            - Expected format is time.Kitchen eg 12:04PM or 12:04pm.
                        type: str
                    retain:
                        description: The number of weekly schedules to retain (default 5).
                        type: int
                    incremental_count:
                        description: Configuration for incremental schedule count.
                        type: dict
                        suboptions:
                            count:
                                description: Number of incremental schedules to retain.
                                type: int
                    bi_weekly:
                        description: 
                            - Enable bi-weekly scheduling (alternate weeks).
                            - When true, schedule will happen on alternate weeks.
                            - When false (default), schedule will happen every week.
                        type: bool
                        default: false
                        version_added: "2.11.0"
            monthly:
                description: 
                    - Monthly scheduling configuration.
                    - Supports two modes - relative_monthly_policy and selective_monthly_policy.
                    - The legacy date/time/retain/incremental_count fields are deprecated.
                    - Use relative_monthly_policy for scheduling by week position (first/last Monday, etc).
                    - Use selective_monthly_policy for scheduling by specific date with month selection.
                type: dict
                suboptions:
                    date:
                        description: 
                            - DEPRECATED - Use selective_monthly_policy instead.
                            - Date of the month when the policy should be triggered.
                            - If a given date doesn't exist in a month, it will be skipped.
                        type: int
                    time:
                        description: 
                            - DEPRECATED - Use selective_monthly_policy or relative_monthly_policy instead.
                            - The time of day for the monthly schedule.
                            - Expected format is time.Kitchen eg 12:04PM or 12:04pm.
                        type: str
                    retain:
                        description: 
                            - DEPRECATED - Use selective_monthly_policy or relative_monthly_policy instead.
                            - The number of monthly schedules to retain (default 12).
                        type: int
                    incremental_count:
                        description: 
                            - DEPRECATED - Use selective_monthly_policy or relative_monthly_policy instead.
                            - Configuration for incremental schedule count.
                        type: dict
                        suboptions:
                            count:
                                description: Number of incremental schedules to retain.
                                type: int
                    relative_monthly_policy:
                        description: 
                            - Schedule by relative week position within the month.
                            - Use this to schedule on "first Monday", "last Friday", etc.
                        type: dict
                        version_added: "2.11.0"
                        suboptions:
                            day:
                                description: 
                                    - Day of the week for the schedule.
                                    - Only one day can be specified.
                                    - Examples - "sun", "mon", "tue", "wed", "thu", "fri", "sat"
                                type: str
                                required: true
                            weekly_index:
                                description: 
                                    - Which occurrence of the day within the month.
                                    - "first" - First occurrence (1st-7th)
                                    - "second" - Second occurrence (8th-14th)
                                    - "third" - Third occurrence (15th-21st)
                                    - "fourth" - Fourth occurrence (22nd-28th)
                                    - "last" - Last occurrence of the day in the month
                                    - Note - fourth and last may differ (e.g., Nov 2025 fourth Sun != last Sun)
                                type: str
                                choices: ['first', 'second', 'third', 'fourth', 'last']
                                required: true
                            time:
                                description: 
                                    - The time of day for the schedule.
                                    - Expected format is time.Kitchen eg 12:04PM or 12:04pm.
                                type: str
                                required: true
                            retain:
                                description: Number of monthly schedules to retain (default 12).
                                type: int
                            incremental_count:
                                description: Configuration for incremental schedule count.
                                type: dict
                                suboptions:
                                    count:
                                        description: Number of incremental schedules to retain.
                                        type: int
                    selective_monthly_policy:
                        description: 
                            - Schedule by specific date with optional month selection.
                            - Use this to schedule on specific dates (e.g., 15th of every month).
                            - Can optionally specify which months to run.
                        type: dict
                        version_added: "2.11.0"
                        suboptions:
                            date:
                                description: 
                                    - Date of the month when the policy should be triggered (1-31).
                                    - If a given date doesn't exist in a month, it will be skipped.
                                    - For example, if 30 is specified, it will be skipped in February.
                                type: int
                                required: true
                            time:
                                description: 
                                    - The time of day for the schedule.
                                    - Expected format is time.Kitchen eg 12:04PM or 12:04pm.
                                type: str
                                required: true
                            retain:
                                description: Number of monthly schedules to retain (default 12).
                                type: int
                            incremental_count:
                                description: Configuration for incremental schedule count.
                                type: dict
                                suboptions:
                                    count:
                                        description: Number of incremental schedules to retain.
                                        type: int
                            months:
                                description: 
                                    - Comma-separated list of months on which schedule needs to run.
                                    - If empty, the schedule will run on every month of the year.
                                    - Examples - "jan,feb,mar" or "Jan,Feb,Mar" or "january,february,march"
                                type: str
            backup_schedule:
                description: A list of backup schedules as strings.
                type: list
                elements: str
            for_object_lock:
                description: Indicates whether the schedule is for object-locked backup
                type: bool
            auto_delete:
                description: Specifies whether the schedule should be auto-deleted when no longer needed.
                type: bool
            supports_advanced_features:
                description: 
                    - Indicates whether the policy supports advanced features.
                    - Advanced features include multi-day weekly, bi-weekly, relative monthly, and selective monthly.
                    - This is automatically set by the API based on the policy configuration.
                type: bool
                version_added: "2.11.0"
    ownership:
        description: Ownership configuration for the schedule policy
        required: false
        type: dict
        suboptions:
            owner:
                description: Owner of the schedule policy
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

EXAMPLES = r'''
# Create a simple daily schedule policy
- name: Create daily backup schedule
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "daily-backup-policy"
    org_id: "default"
    owner: "admin"
    schedule_policy:
      daily:
        time: "02:00AM"
        retain: 7

# Create a weekly schedule with multiple days (v2.11.0+)
- name: Create multi-day weekly backup schedule
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "weekday-backup-policy"
    org_id: "default"
    owner: "admin"
    schedule_policy:
      weekly:
        day: "mon,wed,fri"
        time: "11:00PM"
        retain: 5

# Create a bi-weekly schedule (v2.11.0+)
- name: Create bi-weekly backup schedule
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "biweekly-backup-policy"
    org_id: "default"
    owner: "admin"
    schedule_policy:
      weekly:
        day: "sunday"
        time: "01:00AM"
        retain: 10
        bi_weekly: true

# Create a relative monthly schedule - first Monday of each month (v2.11.0+)
- name: Create first Monday monthly backup
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "first-monday-policy"
    org_id: "default"
    owner: "admin"
    schedule_policy:
      monthly:
        relative_monthly_policy:
          day: "mon"
          weekly_index: "first"
          time: "03:00AM"
          retain: 12

# Create a relative monthly schedule - last Friday of each month (v2.11.0+)
- name: Create last Friday monthly backup
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "last-friday-policy"
    org_id: "default"
    owner: "admin"
    schedule_policy:
      monthly:
        relative_monthly_policy:
          day: "fri"
          weekly_index: "last"
          time: "11:00PM"
          retain: 12
          incremental_count:
            count: 3

# Create a selective monthly schedule - 15th of specific months (v2.11.0+)
- name: Create quarterly backup on 15th
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "quarterly-15th-policy"
    org_id: "default"
    owner: "admin"
    schedule_policy:
      monthly:
        selective_monthly_policy:
          date: 15
          time: "02:00AM"
          retain: 4
          months: "jan,apr,jul,oct"

# Create a selective monthly schedule - 1st of every month (v2.11.0+)
- name: Create monthly backup on 1st
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "monthly-1st-policy"
    org_id: "default"
    owner: "admin"
    schedule_policy:
      monthly:
        selective_monthly_policy:
          date: 1
          time: "04:00AM"
          retain: 12

# Update a schedule policy
- name: Update schedule policy
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: UPDATE
    name: "daily-backup-policy"
    org_id: "default"
    uid: "policy-uid-12345"
    schedule_policy:
      daily:
        time: "03:00AM"
        retain: 14

# Delete a schedule policy
- name: Delete schedule policy
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: DELETE
    name: "old-backup-policy"
    org_id: "default"

# Inspect all schedule policies
- name: List all schedule policies
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: INSPECT_ALL
    org_id: "default"
  register: all_policies

# Inspect a specific schedule policy
- name: Get schedule policy details
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: INSPECT_ONE
    name: "daily-backup-policy"
    org_id: "default"
  register: policy_details

# Update ownership of a schedule policy
- name: Update schedule policy ownership
  purepx.px_backup.schedule_policy:
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    operation: UPDATE_OWNERSHIP
    name: "daily-backup-policy"
    org_id: "default"
    ownership:
      owner: "new-owner"
      groups:
        - id: "backup-admins"
          access: "Admin"
      collaborators:
        - id: "user@example.com"
          access: "Read"
'''

RETURN = r'''
schedule_policy:
    description: The schedule policy object returned from operations (CREATE, UPDATE, INSPECT_ONE, UPDATE_OWNERSHIP)
    type: dict
    returned: on success for single policy operations
    sample:
        metadata:
            name: "daily-backup-policy"
            org_id: "default"
            uid: "abc123-def456"
        schedule_policy:
            daily:
                time: "02:00AM"
                retain: 7
            supports_advanced_features: false

schedule_policies:
    description: List of schedule policies returned from INSPECT_ALL operation
    type: list
    returned: on success for INSPECT_ALL
    sample:
        - metadata:
              name: "daily-backup-policy"
              org_id: "default"
          schedule_policy:
              daily:
                  time: "02:00AM"
                  retain: 7
        - metadata:
              name: "weekly-backup-policy"
              org_id: "default"
          schedule_policy:
              weekly:
                  day: "mon,wed,fri"
                  time: "11:00PM"
                  retain: 5
                  bi_weekly: false

changed:
    description: Whether the operation resulted in a change
    type: bool
    returned: always

message:
    description: Status message describing the operation result
    type: str
    returned: always
    sample: "Schedule Policy created successfully"
'''


# Weekly index mapping for relative monthly policy
WEEKLY_INDEX_MAP = {
    'first': 1,
    'second': 2,
    'third': 3,
    'fourth': 4,
    'last': 5
}


def create_schedule_policy(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Create a new Schedule Policy"""
    try:
        params = dict(module.params)
        schedule_policy_request = schedule_policy_request_body(module)

        # Make the create request
        response = client.make_request(
            method='POST',
            endpoint='v1/schedulepolicy',
            data=schedule_policy_request
        )
        
        # Return the schedule_policy from the response
        if isinstance(response, dict) and 'schedule_policy' in response:
            return response['schedule_policy'], True
            
        # If we get an unexpected response format, raise an error
        raise ValueError(f"Unexpected API response format: {response}")
        
    except Exception as e:
        error_msg = str(e)
        if isinstance(e, requests.exceptions.RequestException) and hasattr(e, 'response'):
            try:
                error_detail = e.response.json()
                error_msg = f"{error_msg}: {error_detail}"
            except ValueError:
                error_msg = f"{error_msg}: {e.response.text}"
        module.fail_json(msg=f"Failed to create schedule policy: {error_msg}")


def update_schedule_policy(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update an existing Schedule Policy"""
    try:    
        schedule_policy_request = schedule_policy_request_body(module)
        schedule_policy_request['metadata']['uid'] = module.params.get('uid', '')
        
        response = client.make_request('PUT', 'v1/schedulepolicy', schedule_policy_request)
        return response, True
        
    except Exception as e:
        module.fail_json(msg=f"Failed to update Schedule Policy: {str(e)}")


def update_ownership(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Update ownership of a Schedule Policy"""
    ownership_request = {
        "org_id": module.params['org_id'],
        "name": module.params['name'],
        "ownership": module.params['ownership'],
        "uid": module.params.get('uid', '')
    }
    try:
        response = client.make_request('PUT', 'v1/schedulepolicy/updateownership', ownership_request)
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to update Schedule Policy ownership: {str(e)}")


def enumerate_schedule_policies(module: AnsibleModule, client: PXBackupClient) -> List[Dict[str, Any]]:
    """List all Schedule Policies"""
    params = {
        'include_secrets': module.params.get('include_secrets', False)
    }
    try:
        response = client.make_request('GET', f"v1/schedulepolicy/{module.params['org_id']}", params=params)
        return response.get('schedule_policies', [])
    except Exception as e:
        module.fail_json(msg=f"Failed to enumerate Schedule Policy: {str(e)}")


def inspect_schedule_policies(module: AnsibleModule, client: PXBackupClient) -> Dict[str, Any]:
    """Get details of a specific Schedule Policy"""
    params = {
        'include_secrets': module.params.get('include_secrets', False)
    }
    try:
        response = client.make_request(
            'GET',
            f"v1/schedulepolicy/{module.params['org_id']}/{module.params['name']}",
            params=params
        )
        return response['schedule_policy']
    except Exception as e:
        module.fail_json(msg=f"Failed to inspect Schedule Policy: {str(e)}")


def delete_schedule_policies(module: AnsibleModule, client: PXBackupClient) -> Tuple[Dict[str, Any], bool]:
    """Delete a Schedule Policy"""
    try:
        response = client.make_request(
            'DELETE',
            f"v1/schedulepolicy/{module.params['org_id']}/{module.params['name']}"
        )
        return response, True
    except Exception as e:
        module.fail_json(msg=f"Failed to delete Schedule Policy: {str(e)}")


def build_monthly_policy(monthly_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build monthly policy configuration handling both legacy and new formats.
    
    Supports:
    - Legacy format: date, time, retain, incremental_count (deprecated)
    - New format: relative_monthly_policy or selective_monthly_policy
    """
    monthly_policy = {}
    
    # Check for new policy formats first (v2.11.0+)
    if monthly_config.get('relative_monthly_policy'):
        rel_policy = monthly_config['relative_monthly_policy']
        relative_monthly = {}
        
        if rel_policy.get('day'):
            relative_monthly['day'] = rel_policy['day']
        
        if rel_policy.get('weekly_index'):
            # Convert string to enum value
            weekly_index = rel_policy['weekly_index'].lower()
            if weekly_index in WEEKLY_INDEX_MAP:
                relative_monthly['weekly_index'] = WEEKLY_INDEX_MAP[weekly_index]
            else:
                relative_monthly['weekly_index'] = weekly_index
        
        if rel_policy.get('time'):
            relative_monthly['time'] = rel_policy['time']
        
        if rel_policy.get('retain') is not None:
            relative_monthly['retain'] = rel_policy['retain']
        
        if rel_policy.get('incremental_count'):
            relative_monthly['incremental_count'] = rel_policy['incremental_count']
        
        monthly_policy['relative_monthly_policy'] = relative_monthly
        
    elif monthly_config.get('selective_monthly_policy'):
        sel_policy = monthly_config['selective_monthly_policy']
        selective_monthly = {}
        
        if sel_policy.get('date') is not None:
            selective_monthly['date'] = sel_policy['date']
        
        if sel_policy.get('time'):
            selective_monthly['time'] = sel_policy['time']
        
        if sel_policy.get('retain') is not None:
            selective_monthly['retain'] = sel_policy['retain']
        
        if sel_policy.get('incremental_count'):
            selective_monthly['incremental_count'] = sel_policy['incremental_count']
        
        if sel_policy.get('months'):
            selective_monthly['months'] = sel_policy['months']
        
        monthly_policy['selective_monthly_policy'] = selective_monthly
        
    else:
        # Legacy format (deprecated but still supported for backwards compatibility)
        if monthly_config.get('date') is not None:
            monthly_policy['date'] = monthly_config['date']
        
        if monthly_config.get('time'):
            monthly_policy['time'] = monthly_config['time']
        
        if monthly_config.get('retain') is not None:
            monthly_policy['retain'] = monthly_config['retain']
        
        if monthly_config.get('incremental_count'):
            monthly_policy['incremental_count'] = monthly_config['incremental_count']
    
    return monthly_policy


def build_weekly_policy(weekly_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build weekly policy configuration with support for v2.11.0 features.
    
    Supports:
    - Multiple days (comma-separated): "mon,wed,fri"
    - Bi-weekly scheduling: bi_weekly: true
    """
    weekly_policy = {}
    
    if weekly_config.get('day'):
        weekly_policy['day'] = weekly_config['day']
    
    if weekly_config.get('time'):
        weekly_policy['time'] = weekly_config['time']
    
    if weekly_config.get('retain') is not None:
        weekly_policy['retain'] = weekly_config['retain']
    
    if weekly_config.get('incremental_count'):
        weekly_policy['incremental_count'] = weekly_config['incremental_count']
    
    # v2.11.0: bi_weekly support
    if weekly_config.get('bi_weekly') is not None:
        weekly_policy['bi_weekly'] = weekly_config['bi_weekly']
    
    return weekly_policy


def schedule_policy_request_body(module: AnsibleModule) -> Dict[str, Any]:
    """Build the Schedule Policy request object"""
    schedule_policy_config = module.params.get('schedule_policy', {}) or {}
    
    # Build the schedule_policy section with proper handling
    processed_schedule_policy = {}
    
    # Handle interval policy
    if schedule_policy_config.get('interval'):
        processed_schedule_policy['interval'] = schedule_policy_config['interval']
    
    # Handle daily policy
    if schedule_policy_config.get('daily'):
        processed_schedule_policy['daily'] = schedule_policy_config['daily']
    
    # Handle weekly policy with v2.11.0 enhancements
    if schedule_policy_config.get('weekly'):
        processed_schedule_policy['weekly'] = build_weekly_policy(schedule_policy_config['weekly'])
    
    # Handle monthly policy with v2.11.0 enhancements
    if schedule_policy_config.get('monthly'):
        processed_schedule_policy['monthly'] = build_monthly_policy(schedule_policy_config['monthly'])
    
    # Handle backup_schedule list
    if schedule_policy_config.get('backup_schedule'):
        processed_schedule_policy['backup_schedule'] = schedule_policy_config['backup_schedule']
    
    # Handle for_object_lock
    if schedule_policy_config.get('for_object_lock') is not None:
        processed_schedule_policy['for_object_lock'] = schedule_policy_config['for_object_lock']
    
    # Handle auto_delete
    if schedule_policy_config.get('auto_delete') is not None:
        processed_schedule_policy['auto_delete'] = schedule_policy_config['auto_delete']
    
    # Handle supports_advanced_features (read-only, but include if explicitly set)
    if schedule_policy_config.get('supports_advanced_features') is not None:
        processed_schedule_policy['supports_advanced_features'] = schedule_policy_config['supports_advanced_features']
    
    schedule_policy_request = {
        "metadata": {
            "name": module.params['name'],
            "org_id": module.params['org_id'],
            "owner": module.params.get('owner')
        },
        "schedule_policy": processed_schedule_policy
    }

    if module.params.get('labels'):
        schedule_policy_request['metadata']['labels'] = module.params['labels']
        
    if module.params.get('ownership'):
        schedule_policy_request['metadata']['ownership'] = module.params['ownership']

    return schedule_policy_request


def validate_monthly_policy(monthly_config: Dict[str, Any]) -> Optional[str]:
    """
    Validate monthly policy configuration.
    
    Returns error message if validation fails, None if valid.
    """
    if not monthly_config:
        return None
    
    has_relative = bool(monthly_config.get('relative_monthly_policy'))
    has_selective = bool(monthly_config.get('selective_monthly_policy'))
    has_legacy = any(monthly_config.get(k) for k in ['date', 'time', 'retain', 'incremental_count']
                     if k in monthly_config and monthly_config.get(k) is not None)
    
    # Check for conflicting configurations
    if has_relative and has_selective:
        return "Cannot specify both relative_monthly_policy and selective_monthly_policy"
    
    if (has_relative or has_selective) and has_legacy:
        return "Cannot mix legacy monthly fields (date, time, retain) with new policy types"
    
    # Validate relative_monthly_policy
    if has_relative:
        rel_policy = monthly_config['relative_monthly_policy']
        if not rel_policy.get('day'):
            return "relative_monthly_policy requires 'day' field"
        if not rel_policy.get('weekly_index'):
            return "relative_monthly_policy requires 'weekly_index' field"
        if not rel_policy.get('time'):
            return "relative_monthly_policy requires 'time' field"
        
        valid_weekly_indices = ['first', 'second', 'third', 'fourth', 'last']
        if rel_policy['weekly_index'].lower() not in valid_weekly_indices:
            return f"Invalid weekly_index '{rel_policy['weekly_index']}'. Must be one of: {', '.join(valid_weekly_indices)}"
    
    # Validate selective_monthly_policy
    if has_selective:
        sel_policy = monthly_config['selective_monthly_policy']
        if sel_policy.get('date') is None:
            return "selective_monthly_policy requires 'date' field"
        if not sel_policy.get('time'):
            return "selective_monthly_policy requires 'time' field"
        
        # Validate date range
        if not (1 <= sel_policy['date'] <= 31):
            return f"Invalid date '{sel_policy['date']}'. Must be between 1 and 31"
    
    return None


def needs_update(current: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """Compare current and desired state to determine if update is needed"""
    def normalize_dict(d):
        """Normalize dictionary for comparison by removing None values and sorting lists"""
        if not isinstance(d, dict):
            return d
        return {k: normalize_dict(v) for k, v in d.items() if v is not None}
    
    current_normalized = normalize_dict(current)
    desired_normalized = normalize_dict(desired)
    return current_normalized != desired_normalized


def run_module():
    # Define incremental_count spec for reuse
    incremental_count_spec = dict(
        type='dict',
        required=False,
        options=dict(
            count=dict(type='int', required=False)
        )
    )
    
    # Define relative_monthly_policy spec
    relative_monthly_policy_spec = dict(
        type='dict',
        required=False,
        options=dict(
            day=dict(type='str', required=True),
            weekly_index=dict(
                type='str',
                required=True,
                choices=['first', 'second', 'third', 'fourth', 'last']
            ),
            time=dict(type='str', required=True),
            retain=dict(type='int', required=False),
            incremental_count=incremental_count_spec
        )
    )
    
    # Define selective_monthly_policy spec
    selective_monthly_policy_spec = dict(
        type='dict',
        required=False,
        options=dict(
            date=dict(type='int', required=True),
            time=dict(type='str', required=True),
            retain=dict(type='int', required=False),
            incremental_count=incremental_count_spec,
            months=dict(type='str', required=False)
        )
    )
    
    module_args = dict(
        api_url=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        operation=dict(
            type='str',
            choices=['CREATE', 'UPDATE', 'DELETE', 'INSPECT_ALL', 'UPDATE_OWNERSHIP', 'INSPECT_ONE'],
            required=True
        ),
        name=dict(type='str', required=False),
        org_id=dict(type='str', required=True),
        uid=dict(type='str', required=False),
        owner=dict(type='str', required=False),
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
        
        include_secrets=dict(type='bool', default=False),
        labels=dict(type='dict', required=False),
        schedule_policy=dict(
            type='dict',
            required=False,
            options=dict(
                interval=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        minutes=dict(type='int', required=False),
                        retain=dict(type='int', required=False),
                        incremental_count=incremental_count_spec
                    )
                ),
                daily=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        time=dict(type='str', required=False),
                        retain=dict(type='int', required=False),
                        incremental_count=incremental_count_spec
                    )
                ),
                weekly=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        day=dict(type='str', required=False),
                        time=dict(type='str', required=False),
                        retain=dict(type='int', required=False),
                        incremental_count=incremental_count_spec,
                        # v2.11.0: bi-weekly support
                        bi_weekly=dict(type='bool', required=False, default=False)
                    )
                ),
                monthly=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        # Legacy fields (deprecated)
                        date=dict(type='int', required=False),
                        time=dict(type='str', required=False),
                        retain=dict(type='int', required=False),
                        incremental_count=incremental_count_spec,
                        # v2.11.0: new policy types
                        relative_monthly_policy=relative_monthly_policy_spec,
                        selective_monthly_policy=selective_monthly_policy_spec
                    )
                ),
                backup_schedule=dict(
                    type='list',
                    required=False,
                    elements='str'
                ),
                for_object_lock=dict(type='bool', required=False, default=False),
                auto_delete=dict(type='bool', required=False, default=False),
                # v2.11.0: supports_advanced_features flag
                supports_advanced_features=dict(type='bool', required=False)
            )
        ),
        # metadata-related arguments
        ownership=dict(
            type='dict',
            required=False,
            options=dict(
                owner=dict(type='str'),
                groups=dict(
                    type='list',
                    required=False,
                    elements='dict',
                    options=dict(
                        id=dict(type='str', required=True),
                        access=dict(
                            type='str',
                            choices=['Read', 'Write', 'Admin'],
                            required=True
                        )
                    )
                ),
                collaborators=dict(
                    type='list',
                    required=False,
                    elements='dict',
                    options=dict(
                        id=dict(type='str', required=True),
                        access=dict(
                            type='str',
                            choices=['Read', 'Write', 'Admin'],
                            required=True
                        )
                    )
                ),
                public=dict(
                    type='dict',
                    options=dict(
                        type=dict(
                            type='str',
                            choices=['Read', 'Write', 'Admin']
                        )
                    )
                )
            )
        )
    )

    result = dict(
        changed=False,
        schedule_policy={},
        schedule_policies=[],
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=[
            ('operation', 'CREATE', ['name', 'schedule_policy']),
            ('operation', 'UPDATE', ['name', 'schedule_policy']),
            ('operation', 'DELETE', ['name']),
            ('operation', 'INSPECT_ONE', ['name']),
            ('operation', 'UPDATE_OWNERSHIP', ['name', 'ownership'])
        ]
    )

    try:
        # Get SSL configuration
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

        # Validate monthly policy configuration
        schedule_policy_config = module.params.get('schedule_policy', {})
        if schedule_policy_config and schedule_policy_config.get('monthly'):
            validation_error = validate_monthly_policy(schedule_policy_config['monthly'])
            if validation_error:
                module.fail_json(msg=f"Invalid monthly policy configuration: {validation_error}")

        client = PXBackupClient(
            api_url=module.params['api_url'],
            token=module.params['token'],
            validate_certs=ssl_config.get('validate_certs', True),
            ca_cert=ssl_config.get('ca_cert'),
            client_cert=ssl_config.get('client_cert'),
            client_key=ssl_config.get('client_key')
        )

        changed = False
        operation = module.params['operation']

        if operation == 'CREATE':
            schedule_policy, changed = create_schedule_policy(module, client)
            result['schedule_policy'] = schedule_policy
            result['message'] = "Schedule Policy created successfully"
            
        elif operation == 'UPDATE':
            schedule_policy, changed = update_schedule_policy(module, client)
            result['schedule_policy'] = schedule_policy
            result['message'] = "Schedule Policy updated successfully"
            
        elif operation == 'UPDATE_OWNERSHIP':
            schedule_policy, changed = update_ownership(module, client)
            result['schedule_policy'] = schedule_policy
            result['message'] = "Schedule Policy Ownership updated successfully"
            
        elif operation == 'INSPECT_ALL':
            schedule_policies = enumerate_schedule_policies(module, client)
            result['schedule_policies'] = schedule_policies
            result['message'] = f"Found {len(schedule_policies)} Schedule Policies"
            
        elif operation == 'INSPECT_ONE':
            schedule_policy = inspect_schedule_policies(module, client)
            result['schedule_policy'] = schedule_policy
            result['message'] = "Schedule Policy found successfully"
            
        elif operation == 'DELETE':
            schedule_policy, changed = delete_schedule_policies(module, client)
            result['message'] = "Schedule Policy deleted successfully"

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