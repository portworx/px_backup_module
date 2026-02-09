# Enumerate Options Configuration

All PX-Backup modules that support listing resources (INSPECT_ALL operations) use **flat top-level parameters** for pagination, filtering, and sorting.

## Overview

These parameters provide a consistent way to:
- **Paginate** through large result sets using `max_objects` and `object_index`
- **Filter** results by name, labels, time range, cluster, status, and more
- **Sort** results by various fields in ascending or descending order

## Supported Modules

| Module | Parameter Style | Notes |
|--------|-----------------|-------|
| backup | Flat top-level | Full filtering with backup-specific options |
| backup_location | Flat top-level | Full filtering support |
| backup_schedule | Flat top-level | Supports both GET and POST methods |
| cloud_credential | Flat top-level | Full filtering support |
| cluster | Flat top-level | Only `sort_option` supported (server limitation) |
| restore | Flat top-level | Full filtering with restore-specific options |
| role | Flat top-level | Server ignores all enumerate params |
| volume_resource_only_policy | Nested `enumerate_options` | Uses unique `generic_enumerate_options` structure (API requirement) |

## Common Parameters

These parameters are available as **top-level module parameters** (except VRO which uses a nested structure):

| Parameter | Type | Description |
|-----------|------|-------------|
| `max_objects` | integer | Maximum number of objects to return per request |
| `object_index` | integer | Starting index for pagination (zero-based) |
| `name_filter` | string | Filter by name using substring matching |
| `labels` | dict | Filter by key-value label pairs |
| `time_range` | dict | Filter by object creation time range |
| `sort_option` | dict | Sorting configuration |

### Pagination Behavior

#### max_objects Values

| Value | Server Behavior |
|-------|-----------------|
| `0` | Returns **all objects** (no limit) - same as not specifying the parameter |
| `1` or higher | Limits results to that exact number |
| Not specified | Returns all objects (default behavior) |

> **Note**: Setting `max_objects: 0` is effectively the same as not setting it at all. If you want to limit results, always use a value of `1` or greater.

#### object_index (Offset)

The `object_index` parameter specifies the starting position for pagination:
- `object_index: 0` - Start from the first object (default)
- `object_index: 10` - Skip the first 10 objects, start from the 11th

### time_range Structure

The `time_range` is a **filter** that applies to the **object creation time** only. It excludes objects created outside the specified range.

| Parameter | Type | Description |
|-----------|------|-------------|
| `start_time` | string | Start time in RFC3339/ISO 8601 format (e.g., `2026-01-01T00:00:00Z`) |
| `end_time` | string | End time in RFC3339/ISO 8601 format (e.g., `2026-12-31T23:59:59Z`) |

### sort_option Structure

The `sort_option` controls the **ordering** of results after all filters have been applied. It does not filter or exclude any objects.

| Parameter | Type | Choices | Description |
|-----------|------|---------|-------------|
| `sortBy` | string | `Invalid`, `CreationTimestamp`, `Name`, `ClusterName`, `Size`, `RestoreBackupName`, `LastUpdateTimestamp` | Field to sort by |
| `sortOrder` | string | `Invalid`, `Ascending`, `Descending` | Sort direction |

#### sortBy Options

| Value | Description |
|-------|-------------|
| `CreationTimestamp` | Order by when the object was created |
| `LastUpdateTimestamp` | Order by when the object was last modified |
| `Name` | Order alphabetically by object name |
| `ClusterName` | Order by associated cluster name |
| `Size` | Order by backup size (backup/restore only) |
| `RestoreBackupName` | Order by the backup name used for restore (restore only) |


### Example: Combining Filter and Sort

```yaml
# Get objects created in January 2026, ordered by last update time
backup:
  operation: INSPECT_ALL
  api_url: "{{ px_backup_api_url }}"
  token: "{{ px_backup_token }}"
  org_id: "default"
  time_range:                        # FILTER: only objects created in this range
    start_time: "2026-01-01T00:00:00Z"
    end_time: "2026-01-31T23:59:59Z"
  sort_option:                       # SORT: order filtered results by last update
    sortBy: "LastUpdateTimestamp"
    sortOrder: "Descending"
  max_objects: 20                    # PAGINATION: return first 20 results
```

## Extended Parameters

These additional parameters are available for most modules (except VRO which uses only common parameters):

| Parameter | Type | Description |
|-----------|------|-------------|
| `cluster_name_filter` | string | Filter by cluster name |
| `cluster_uid_filter` | string | Filter by cluster UID |
| `include_detailed_resources` | boolean | Include detailed resource information |
| `owners` | list | Filter by owner IDs |
| `backup_object_type` | string | Filter by backup object type (`All`, `VirtualMachine`) |
| `status` | list | Filter by status values |
| `backup_schedule_ref` | list | Filter by backup schedule references |
| `schedule_policy_ref` | list | Filter by schedule policy references |

## 🔧 Configuration Examples

### Basic Pagination

```yaml
- name: List first 10 backups
  backup:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    max_objects: 10
    object_index: 0
```

### Pagination with Next Page

```yaml
- name: Get next page of backups
  backup:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    max_objects: 10
    object_index: 10  # Start from 11th item
```

### Filtering by Name

```yaml
- name: List backups matching name pattern
  backup:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    name_filter: "prod-"
    max_objects: 50
```

### Filtering by Time Range

```yaml
- name: List backups created in last month
  backup:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    time_range:
      start_time: "2026-01-01T00:00:00Z"
      end_time: "2026-01-31T23:59:59Z"
```

### Sorting Results

```yaml
- name: List backups sorted by creation time
  backup:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    sort_option:
      sortBy: "CreationTimestamp"
      sortOrder: "Descending"
```

### Filtering by Cluster

```yaml
- name: List backups from specific cluster
  backup:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    cluster_name_filter: "production-cluster"
    max_objects: 100
```

### Combined Filters

```yaml
- name: List production backups with multiple filters
  backup:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    max_objects: 20
    name_filter: "prod-"
    cluster_name_filter: "production"
    labels:
      environment: "production"
    time_range:
      start_time: "2026-01-01T00:00:00Z"
    sort_option:
      sortBy: "CreationTimestamp"
      sortOrder: "Descending"
```

## Volume Resource Only Policy (VRO) Structure

The VRO module uses a nested structure with `generic_enumerate_options`:

```yaml
- name: List VRO policies with filtering
  volume_resource_only_policy:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    enumerate_options:
      generic_enumerate_options:
        max_objects: 10
        name_filter: "prod-"
        sort_option:
          sortBy: "CreationTimestamp"
          sortOrder: "Descending"
      volume_types:
        - "Portworx"
        - "Csi"
```

### VRO-specific Parameters

| Parameter | Type | Choices | Description |
|-----------|------|---------|-------------|
| `volume_types` | list | `Invalid`, `Portworx`, `Csi`, `Nfs` | Filter policies by volume types |

## Response Metadata

When using pagination, the API response includes metadata to help navigate through results:

| Field | Type | Description |
|-------|------|-------------|
| `total_count` | integer | Total number of objects matching the filter (may be `null` if not provided by API) |
| `complete` | boolean | `true` if all matching results were returned, `false` if more pages exist |

**Note**: The `complete` field defaults to `true` when the API doesn't explicitly return it (which typically happens when all results fit in a single response without pagination).

### Checking for More Pages

```yaml
- name: List backups with pagination
  backup:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    max_objects: 10
    object_index: 0
  register: result

- name: Check if more results exist (for modules with pagination metadata)
  debug:
    msg: "More results available: {{ not result.complete }}"
  when: result.complete is defined
```

## Important Notes

1. **Server-Side Limitations**
   - **cluster**: Only `sort_option` is supported (Name, CreationTimestamp). Pagination and filtering are NOT implemented.
   - **role**: Server ignores ALL enumerate params. All roles are returned.
   - **schedule_policy**: No enumerate params supported. Only `org_id` is used.
   - **backup_schedule**: Sorting is not supported. Labels filtering is client-side only.

2. **Pagination Best Practices**
   - Only use `max_objects` for modules that support pagination (see support matrix above)
   - Use `sort_option` with pagination for consistent ordering
   - Check `complete` field to determine if more pages exist (where supported)

3. **Time Range Format**
   - Use RFC3339/ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`
   - Times are interpreted as UTC
   - Both `start_time` and `end_time` are optional within `time_range`

4. **Version Requirements**
   - Full enumerate options support requires PX-Backup >= 2.11.0
   - Some sorting options require PX-Backup >= 2.9.0

## Module-Specific Examples

### Cluster (Sort Only)

```yaml
# Cluster only supports sort_option (Name, CreationTimestamp)
- name: List clusters sorted by creation time
  cluster:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
    sort_option:
      sortBy: "CreationTimestamp"
      sortOrder: "Descending"
```

### Role (No Options Supported)

```yaml
# Role does not support any enumerate params - all roles are returned
- name: List all roles
  role:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
```

### Schedule Policy (No Options Supported)

```yaml
# Schedule policy does not support enumerate params - all policies are returned
- name: List all schedule policies
  schedule_policy:
    operation: INSPECT_ALL
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "default"
```

## Global Configuration

Configure default pagination and filtering options in your inventory:

```yaml
# inventory/group_vars/backup/enumerate.yaml

# Pagination parameters
max_objects: 10
object_index: 0

# Sort option
sort_option:
  sortBy: "CreationTimestamp"
  sortOrder: "Descending"
```

This allows consistent pagination defaults across all playbooks.

