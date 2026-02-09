"""
Common enumerate options handler for PX-Backup Ansible modules.

This module provides standardized handling for pagination, filtering, and sorting
options across all PX-Backup enumerate operations. It ensures consistency in how
enumerate options are defined, built, and processed across all modules.

Supported Features:
- Pagination: max_objects, object_index
- Time-based filtering: time_range (start_time, end_time)
- Sorting: sort_option (sortBy, sortOrder)
- Name filtering: name_filter, cluster_name_filter
- Label filtering: labels

Usage:
    from ansible_collections.portworx.pxbackup.plugins.module_utils.px_backup.enumerate import (
        get_enumerate_options_spec,
        build_enumerate_query_params,
        build_enumerate_request_body,
        extract_enumerate_response
    )
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


# =============================================================================
# SORT OPTIONS CONSTANTS
# =============================================================================

SORT_BY_CHOICES = [
    'Invalid',
    'CreationTimestamp',
    'Name',
    'ClusterName',
    'Size',
    'RestoreBackupName',
    'LastUpdateTimestamp'
]

SORT_ORDER_CHOICES = [
    'Invalid',
    'Ascending',
    'Descending'
]


# =============================================================================
# ARGUMENT SPEC DEFINITIONS
# =============================================================================

def get_common_enumerate_options_spec():
    """
    Returns the argument spec for CommonEnumerateOptions (base pagination).
    
    This is the simpler base structure used by volume_resource_only_policy
    (nested in generic_enumerate_options).
    
    Fields:
        - labels: Label selectors for filtering
        - max_objects: Maximum objects to fetch (pagination limit)
        - name_filter: Filter by object name pattern
        - object_index: Starting index for pagination (offset)
        - sort_option: Sorting configuration
        - time_range: Time-based filtering
    
    Returns:
        dict: Argument spec dictionary for Ansible module
    """
    return dict(
        labels=dict(type='dict', required=False),
        max_objects=dict(type='int', required=False),
        name_filter=dict(type='str', required=False),
        object_index=dict(type='int', required=False),
        sort_option=dict(
            type='dict',
            required=False,
            options=dict(
                sortBy=dict(
                    type='str',
                    choices=SORT_BY_CHOICES,
                    default='Invalid'
                ),
                sortOrder=dict(
                    type='str',
                    choices=SORT_ORDER_CHOICES,
                    default='Invalid'
                )
            )
        ),
        time_range=dict(
            type='dict',
            required=False,
            options=dict(
                start_time=dict(type='str', required=False),
                end_time=dict(type='str', required=False)
            )
        )
    )


def get_enumerate_options_spec():
    """
    Returns the argument spec for EnumerateOptions (full pagination).
    
    This is the full structure used by most endpoints:
    backup, restore, backup_schedule, backup_location, cloud_credential, cluster, role
    
    Extends CommonEnumerateOptions with additional fields:
        - cluster_name_filter: Filter by cluster name
        - cluster_uid_filter: Filter by cluster UID
        - include_detailed_resources: Include full resource details
        - owners: Filter by owner UIDs
        - backup_object_type: Filter by backup object type
        - status: Filter by object status
    
    Returns:
        dict: Argument spec dictionary for Ansible module
    """
    # Start with common options
    spec = get_common_enumerate_options_spec()
    
    # Add extended options for EnumerateOptions
    spec.update(dict(
        cluster_name_filter=dict(type='str', required=False),
        cluster_uid_filter=dict(type='str', required=False),
        include_detailed_resources=dict(type='bool', required=False, default=False),
        owners=dict(type='list', elements='str', required=False),
        backup_object_type=dict(type='str', required=False),
        status=dict(type='list', elements='str', required=False),
        schedule_policy_ref=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),
        backup_schedule_ref=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),
        volume_resource_only_policy_ref=dict(
            type='list',
            elements='dict',
            required=False,
            options=dict(
                name=dict(type='str'),
                uid=dict(type='str')
            )
        ),
        # Additional filters (per swagger.json EnumerateOptions)
        resource_info=dict(
            type='dict',
            required=False,
            options=dict(
                name=dict(type='str', required=False),
                namespace=dict(type='str', required=False),
                group=dict(type='str', required=False),
                kind=dict(type='str', required=False),
                version=dict(type='str', required=False)
            )
        ),
        vm_volume_name=dict(type='str', required=False),
        exclude_failed_resource=dict(type='bool', required=False)
    ))
    
    return spec


# =============================================================================
# QUERY PARAM BUILDERS (for GET requests)
# =============================================================================

def build_enumerate_query_params(enumerate_options, prefix='enumerate_options'):
    """
    Build query parameters for GET requests from enumerate_options dict.

    Converts the nested enumerate_options structure into flat query parameters
    suitable for GET requests. Handles all common and extended enumerate options.

    Args:
        enumerate_options: Dict of enumerate options from module params
        prefix: Parameter prefix (default: 'enumerate_options')

    Returns:
        dict: Flattened query parameters for GET request

    Example:
        Input:  {'max_objects': 100, 'time_range': {'start_time': '2026-01-01T00:00:00Z'}}
        Output: {'enumerate_options.max_objects': 100,
                 'enumerate_options.time_range.start_time': '2026-01-01T00:00:00Z'}
    """
    if not enumerate_options:
        return {}

    params = {}

    # Core pagination fields
    if enumerate_options.get('max_objects') is not None:
        params[f'{prefix}.max_objects'] = enumerate_options['max_objects']

    if enumerate_options.get('object_index') is not None:
        params[f'{prefix}.object_index'] = enumerate_options['object_index']

    if enumerate_options.get('name_filter'):
        params[f'{prefix}.name_filter'] = enumerate_options['name_filter']

    # Time range
    time_range = enumerate_options.get('time_range') or {}
    if time_range.get('start_time'):
        params[f'{prefix}.time_range.start_time'] = time_range['start_time']
    if time_range.get('end_time'):
        params[f'{prefix}.time_range.end_time'] = time_range['end_time']

    # Sort option
    sort_option = enumerate_options.get('sort_option') or {}
    if sort_option.get('sortBy') and sort_option['sortBy'] != 'Invalid':
        params[f'{prefix}.sort_option.sortBy.type'] = sort_option['sortBy']
    if sort_option.get('sortOrder') and sort_option['sortOrder'] != 'Invalid':
        params[f'{prefix}.sort_option.sortOrder.type'] = sort_option['sortOrder']

    # Extended options (for EnumerateOptions)
    if enumerate_options.get('cluster_name_filter'):
        params[f'{prefix}.cluster_name_filter'] = enumerate_options['cluster_name_filter']

    if enumerate_options.get('cluster_uid_filter'):
        params[f'{prefix}.cluster_uid_filter'] = enumerate_options['cluster_uid_filter']

    if enumerate_options.get('include_detailed_resources') is not None:
        params[f'{prefix}.include_detailed_resources'] = enumerate_options['include_detailed_resources']

    if enumerate_options.get('owners'):
        params[f'{prefix}.owners'] = enumerate_options['owners']

    if enumerate_options.get('backup_object_type'):
        params[f'{prefix}.backup_object_type'] = enumerate_options['backup_object_type']

    if enumerate_options.get('status'):
        params[f'{prefix}.status'] = enumerate_options['status']

    # Additional filters
    if enumerate_options.get('vm_volume_name'):
        params[f'{prefix}.vm_volume_name'] = enumerate_options['vm_volume_name']

    if enumerate_options.get('exclude_failed_resource') is not None:
        params[f'{prefix}.exclude_failed_resource'] = enumerate_options['exclude_failed_resource']

    # Resource info (nested)
    resource_info = enumerate_options.get('resource_info') or {}
    if resource_info.get('name'):
        params[f'{prefix}.resource_info.name'] = resource_info['name']
    if resource_info.get('namespace'):
        params[f'{prefix}.resource_info.namespace'] = resource_info['namespace']
    if resource_info.get('group'):
        params[f'{prefix}.resource_info.group'] = resource_info['group']
    if resource_info.get('kind'):
        params[f'{prefix}.resource_info.kind'] = resource_info['kind']
    if resource_info.get('version'):
        params[f'{prefix}.resource_info.version'] = resource_info['version']

    return params


# =============================================================================
# REQUEST BODY BUILDERS (for POST requests)
# =============================================================================

def build_enumerate_request_body(enumerate_options):
    """
    Build request body for POST requests from enumerate_options dict.

    Converts the enumerate_options dict into the proper nested structure
    expected by POST enumerate endpoints.

    Args:
        enumerate_options: Dict of enumerate options from module params

    Returns:
        dict: Request body for POST request

    Example:
        Input:  {'max_objects': 100, 'sort_option': {'sortBy': 'Name', 'sortOrder': 'Ascending'}}
        Output: {
            'max_objects': 100,
            'sort_option': {
                'sortBy': {'type': 'Name'},
                'sortOrder': {'type': 'Ascending'}
            }
        }
    """
    if not enumerate_options:
        return {}

    body = {}

    # Simple fields (direct copy)
    simple_fields = [
        'max_objects', 'object_index', 'name_filter', 'labels',
        'cluster_name_filter', 'cluster_uid_filter', 'include_detailed_resources',
        'owners', 'backup_object_type', 'status',
        'vm_volume_name', 'exclude_failed_resource'
    ]

    for field in simple_fields:
        value = enumerate_options.get(field)
        if value is not None and value != '' and value != []:
            body[field] = value

    # Resource info (nested dict, direct copy)
    resource_info = enumerate_options.get('resource_info')
    if resource_info:
        ri = {k: v for k, v in resource_info.items() if v is not None}
        if ri:
            body['resource_info'] = ri

    # Time range (nested dict, direct copy)
    time_range = enumerate_options.get('time_range')
    if time_range:
        tr = {}
        if time_range.get('start_time'):
            tr['start_time'] = time_range['start_time']
        if time_range.get('end_time'):
            tr['end_time'] = time_range['end_time']
        if tr:
            body['time_range'] = tr

    # Sort option (needs transformation to API format)
    sort_option = enumerate_options.get('sort_option')
    if sort_option:
        so = {}
        if sort_option.get('sortBy') and sort_option['sortBy'] != 'Invalid':
            so['sortBy'] = {'type': sort_option['sortBy']}
        if sort_option.get('sortOrder') and sort_option['sortOrder'] != 'Invalid':
            so['sortOrder'] = {'type': sort_option['sortOrder']}
        if so:
            body['sort_option'] = so

    # Reference lists (schedule_policy_ref, backup_schedule_ref, etc.)
    ref_fields = ['schedule_policy_ref', 'backup_schedule_ref', 'volume_resource_only_policy_ref']
    for field in ref_fields:
        value = enumerate_options.get(field)
        if value:
            body[field] = value

    return body


def build_vro_enumerate_request_body(enumerate_options):
    """
    Build request body for VolumeResourceOnlyPolicy enumerate POST requests.

    This handles the special nested structure used by volume_resource_only_policy:
    {
        'generic_enumerate_options': { ... CommonEnumerateOptions ... },
        'volume_types': [...]
    }

    Args:
        enumerate_options: Dict with 'generic_enumerate_options' and 'volume_types'

    Returns:
        dict: Request body for VRO enumerate POST request
    """
    if not enumerate_options:
        return {}

    body = {}

    # Handle generic_enumerate_options (CommonEnumerateOptions)
    generic_opts = enumerate_options.get('generic_enumerate_options')
    if generic_opts:
        body['generic_enumerate_options'] = build_enumerate_request_body(generic_opts)

    # Handle volume_types
    volume_types = enumerate_options.get('volume_types')
    if volume_types:
        body['volume_types'] = volume_types

    return body


# =============================================================================
# RESPONSE HANDLERS
# =============================================================================

def extract_enumerate_response(response, items_key):
    """
    Extract items and pagination metadata from enumerate API response.

    This function standardizes the response format by extracting items and
    pagination metadata (total_count, complete) from API responses.

    Args:
        response: API response dict
        items_key: Key to extract items from (e.g., 'backup_locations', 'backups')

    Returns:
        dict: Standardized response with 'items', 'total_count', 'complete'

    Example:
        Input:  {'backup_locations': [...], 'total_count': 150, 'complete': False}
        Output: {
            'items': [...],
            'total_count': 150,
            'complete': False
        }
    """
    if not response:
        return {
            'items': [],
            'total_count': 0,
            'complete': True
        }

    return {
        'items': response.get(items_key, []),
        'total_count': response.get('total_count'),
        'complete': response.get('complete', True)
    }


def add_pagination_metadata(result, response):
    """
    Add pagination metadata fields to module result.

    This helper adds total_count and complete fields to the module result
    dict if they are present in the API response.

    Args:
        result: Module result dict to update (modified in place)
        response: API response dict containing pagination metadata

    Returns:
        dict: Updated result dict with pagination metadata
    """
    if response:
        if 'total_count' in response:
            result['total_count'] = response['total_count']
        # Default to True if 'complete' is not in response
        # (API omits this field when all results are returned)
        result['complete'] = response.get('complete', True)

    return result


# =============================================================================
# SPECIALIZED QUERY PARAM BUILDERS
# =============================================================================

def build_vro_enumerate_query_params(enumerate_options):
    """
    Build query parameters for VolumeResourceOnlyPolicy enumerate GET requests.

    This handles the special nested structure used by volume_resource_only_policy:
    enumerate_options.generic_enumerate_options.xxx

    Args:
        enumerate_options: Dict with 'generic_enumerate_options' and 'volume_types'

    Returns:
        dict: Flattened query parameters for GET request
    """
    if not enumerate_options:
        return {}

    params = {}

    # Handle generic_enumerate_options
    generic_opts = enumerate_options.get('generic_enumerate_options')
    if generic_opts:
        # Build with nested prefix
        nested_params = build_enumerate_query_params(
            generic_opts,
            prefix='enumerate_options.generic_enumerate_options'
        )
        params.update(nested_params)

    # Handle volume_types (list)
    volume_types = enumerate_options.get('volume_types')
    if volume_types:
        for i, vt in enumerate(volume_types):
            params[f'enumerate_options.volume_types[{i}]'] = vt

    return params


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_vro_enumerate_options_spec():
    """
    Returns the argument spec for VolumeResourceOnlyPolicyEnumerateOptions.

    This is the nested structure used specifically by volume_resource_only_policy:
    {
        'generic_enumerate_options': { ... CommonEnumerateOptions ... },
        'volume_types': [...]
    }

    Returns:
        dict: Argument spec dictionary for Ansible module
    """
    return dict(
        generic_enumerate_options=dict(
            type='dict',
            required=False,
            options=get_common_enumerate_options_spec()
        ),
        volume_types=dict(
            type='list',
            elements='str',
            required=False,
            choices=['Invalid', 'Portworx', 'Csi', 'Nfs']
        )
    )

