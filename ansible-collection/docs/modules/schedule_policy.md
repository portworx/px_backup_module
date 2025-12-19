# Schedule Policy Module

The schedule policy module manages schedule policies in PX-Backup, enabling configuration and management of schedule details for various intervals.

## Synopsis

* Create and manage schedule policies in PX-Backup
* Access control and ownership management
* Comprehensive policy inspection capabilities
* Advanced scheduling with multi-day, bi-weekly, and flexible monthly options (v2.11.0+)

## Requirements

* PX-Backup >= 2.11.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation        | Description                               |
| ------------------ | ------------------------------------------- |
| CREATE           | Create a new schedule policy              |
| UPDATE           | Modify existing schedule policy           |
| DELETE           | Remove a schedule policy                  |
| INSPECT_ONE      | Get details of a specific schedule policy |
| INSPECT_ALL      | List all schedule policies                |
| UPDATE_OWNERSHIP | Update schedule policy ownership settings |

## Parameters

### Common Parameters


| Parameter       | Type   | Required | Default | Description                   | Choices                                  |
| ----------------- | -------- | ---------- | --------- | ------------------------------- | ------------------------------------------ |
| api_url         | string | yes      |         | PX-Backup API URL             |                                          |
| token           | string | yes      |         | Authentication token          |                                          |
| operation       | string | yes      | CREATE  | Operation to perform          |                                          |
| name            | string | varies   |         | Name of the schedule policy   |                                          |
| org_id          | string | yes      |         | Organization ID               |                                          |
| uid             | string | varies   |         | Unique identifier             |                                          |
| owner           | string | no       |         | Owner name                    |                                          |
| schedule_policy | dict   | yes      |         | Schedule Policy configuration | `interval`, `daily`, `weekly`, `monthly` |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### Ownership Parameters


| Parameter                        | Type   | Required | Choices          | Description                  |
| ---------------------------------- | -------- | ---------- | ------------------ | ------------------------------ |
| ownership.owner                  | string | no       |                  | Owner of the schedule policy |
| ownership.groups[].id            | string | yes      |                  | Group identifier             |
| ownership.groups[].access        | string | yes      | Read/Write/Admin | Group access level           |
| ownership.collaborators[].id     | string | yes      |                  | Collaborator identifier      |
| ownership.collaborators[].access | string | yes      | Read/Write/Admin | Collaborator access level    |
| ownership.public.type            | string | no       | Read/Write/Admin | Public access level          |

### Schedule Policy Parameters

#### Global Options


| Parameter                  | Type | Required | Choices    | Description                                                                            |
| ---------------------------- | ------ | ---------- | ------------ | ---------------------------------------------------------------------------------------- |
| supports_advanced_features | bool | no       | true/false | Required for v2.11.0 features (multi-day, bi-weekly, relative/selective monthly)       |
| backup_schedule            | list | no       |            | A list of custom backup schedules (each schedule as a string)                          |
| for_object_lock            | bool | no       | true/false | Enables a locked schedule policy for object-locked backups                             |
| auto_delete                | bool | no       | true/false | Specifies whether backups are automatically deleted after the retention period expires |

#### Interval Schedule


| Parameter                        | Type | Required | Description                                                 |
| ---------------------------------- | ------ | ---------- | ------------------------------------------------------------- |
| interval.minutes                 | int  | yes      | Defines the interval in minutes for periodic scheduling     |
| interval.retain                  | int  | yes      | Specifies the number of periodic backups to retain          |
| interval.incremental_count.count | int  | no       | Number of incremental backups to retain within the schedule |

#### Daily Schedule


| Parameter                     | Type   | Required | Description                                                       |
| ------------------------------- | -------- | ---------- | ------------------------------------------------------------------- |
| daily.time                    | string | yes      | Time of day for daily backups (format: HH:MMAM/PM, e.g., 01:00AM) |
| daily.retain                  | int    | yes      | Number of daily backups to retain                                 |
| daily.incremental_count.count | int    | no       | Number of incremental backups to retain within the schedule       |

#### Weekly Schedule


| Parameter                      | Type   | Required | Default | Description                                                                               |
| -------------------------------- | -------- | ---------- | --------- | ------------------------------------------------------------------------------------------- |
| weekly.day                     | string | yes      |         | Day(s) of the week. Single:`sunday`. Multiple: `mon,wed,fri`                              |
| weekly.time                    | string | yes      |         | Time of day for weekly backups (format: HH:MMAM/PM)                                       |
| weekly.retain                  | int    | yes      | 5       | Number of weekly backups to retain                                                        |
| weekly.incremental_count.count | int    | no       |         | Number of incremental backups to retain within the schedule                               |
| weekly.bi_weekly               | bool   | no       | false   | Enable bi-weekly scheduling (alternate weeks). Requires`supports_advanced_features: true` |

#### Monthly Schedule

The monthly schedule supports three modes:

1. **Legacy mode** (deprecated): Direct `date`, `time`, `retain` fields
2. **Relative monthly policy** (v2.11.0+): Schedule by week position (e.g., "first Monday", "last Friday")
3. **Selective monthly policy** (v2.11.0+): Schedule by specific date with optional month selection

##### Legacy Monthly Parameters (Deprecated)


| Parameter                       | Type   | Required | Choices | Description                                                            |
| --------------------------------- | -------- | ---------- | --------- | ------------------------------------------------------------------------ |
| monthly.date                    | int    | yes      | 1-31    | Day of the month. If date doesn't exist in a month, it will be skipped |
| monthly.time                    | string | yes      |         | Time of day for monthly backups (format: HH:MMAM/PM)                   |
| monthly.retain                  | int    | yes      | 12      | Number of monthly backups to retain                                    |
| monthly.incremental_count.count | int    | no       |         | Number of incremental backups to retain within the schedule            |

##### Relative Monthly Policy (v2.11.0+)

Schedule backups on a relative day of the month (e.g., "first Monday", "last Friday"). Requires `supports_advanced_features: true`.


| Parameter                                               | Type   | Required | Choices                        | Description                                  |
| --------------------------------------------------------- | -------- | ---------- | -------------------------------- | ---------------------------------------------- |
| monthly.relative_monthly_policy.day                     | string | yes      | sun/mon/tue/wed/thu/fri/sat    | Day of the week                              |
| monthly.relative_monthly_policy.weekly_index            | string | yes      | first/second/third/fourth/last | Which occurrence of the day within the month |
| monthly.relative_monthly_policy.time                    | string | yes      |                                | Time of day (format: HH:MMAM/PM)             |
| monthly.relative_monthly_policy.retain                  | int    | no       | 12                             | Number of monthly backups to retain          |
| monthly.relative_monthly_policy.incremental_count.count | int    | no       |                                | Number of incremental backups to retain      |

> **Note**: `fourth` and `last` may differ. For example, in November 2025, the fourth Sunday ≠ last Sunday. In months where a weekday occurs exactly 4 times, `fourth` and `last` are the same.

##### Selective Monthly Policy (v2.11.0+)

Schedule backups on a specific date with optional month filtering. Requires `supports_advanced_features: true`.


| Parameter                                                | Type   | Required | Choices | Description                                                         |
| ---------------------------------------------------------- | -------- | ---------- | --------- | --------------------------------------------------------------------- |
| monthly.selective_monthly_policy.date                    | int    | yes      | 1-31    | Day of the month. Skipped if date doesn't exist in the month        |
| monthly.selective_monthly_policy.time                    | string | yes      |         | Time of day (format: HH:MMAM/PM)                                    |
| monthly.selective_monthly_policy.retain                  | int    | no       | 12      | Number of monthly backups to retain                                 |
| monthly.selective_monthly_policy.incremental_count.count | int    | no       |         | Number of incremental backups to retain                             |
| monthly.selective_monthly_policy.months                  | string | no       |         | Comma-separated months (e.g.,`jan,apr,jul,oct`). Empty = all months |

## Examples

### Basic Daily Schedule

```yaml
- name: Create daily backup schedule
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "daily-backup-policy"
    org_id: "default"
    schedule_policy:
      daily:
        time: "02:00AM"
        retain: 7
```

### Multi-Day Weekly Schedule (v2.11.0+)

```yaml
- name: Create weekday backup schedule
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "weekday-backups"
    org_id: "default"
    schedule_policy:
      supports_advanced_features: true
      weekly:
        day: "mon,wed,fri"
        time: "11:00PM"
        retain: 5
```

### Bi-Weekly Schedule (v2.11.0+)

```yaml
- name: Create bi-weekly backup schedule
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "biweekly-backup"
    org_id: "default"
    schedule_policy:
      supports_advanced_features: true
      weekly:
        day: "sunday"
        time: "01:00AM"
        retain: 10
        bi_weekly: true
```

### Relative Monthly - First Monday (v2.11.0+)

```yaml
- name: Create first Monday monthly backup
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "first-monday-backup"
    org_id: "default"
    schedule_policy:
      supports_advanced_features: true
      monthly:
        relative_monthly_policy:
          day: "mon"
          weekly_index: "first"
          time: "03:00AM"
          retain: 12
```

### Relative Monthly - Last Friday (v2.11.0+)

```yaml
- name: Create last Friday monthly backup
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "last-friday-backup"
    org_id: "default"
    schedule_policy:
      supports_advanced_features: true
      monthly:
        relative_monthly_policy:
          day: "fri"
          weekly_index: "last"
          time: "11:00PM"
          retain: 12
          incremental_count:
            count: 3
```

### Selective Monthly - Quarterly on 15th (v2.11.0+)

```yaml
- name: Create quarterly backup on 15th
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "quarterly-backup"
    org_id: "default"
    schedule_policy:
      supports_advanced_features: true
      monthly:
        selective_monthly_policy:
          date: 15
          time: "02:00AM"
          retain: 4
          months: "jan,apr,jul,oct"
```

### Selective Monthly - 1st of Every Month (v2.11.0+)

```yaml
- name: Create monthly backup on 1st
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "monthly-1st-backup"
    org_id: "default"
    schedule_policy:
      supports_advanced_features: true
      monthly:
        selective_monthly_policy:
          date: 1
          time: "04:00AM"
          retain: 12
```

### Vars File Example (v2.11.0+)

```yaml
---
schedule_policies:
  # Multi-day weekly
  - name: "weekday-backups"
    schedule_policy:
      supports_advanced_features: true
      weekly:
        day: "mon,wed,fri"
        time: "11:00PM"
        retain: 5

  # Bi-weekly
  - name: "biweekly-backup"
    schedule_policy:
      supports_advanced_features: true
      weekly:
        day: "sunday"
        time: "01:00AM"
        retain: 10
        bi_weekly: true

  # First Monday of month
  - name: "first-monday-backup"
    schedule_policy:
      supports_advanced_features: true
      monthly:
        relative_monthly_policy:
          day: "mon"
          weekly_index: "first"
          time: "03:00AM"
          retain: 12

  # Quarterly on 15th
  - name: "quarterly-backup"
    schedule_policy:
      supports_advanced_features: true
      monthly:
        selective_monthly_policy:
          date: 15
          time: "02:00AM"
          retain: 4
          months: "jan,apr,jul,oct"
```

### Inspect All Policies

```yaml
- name: List all schedule policies
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: INSPECT_ALL
    org_id: "default"
  register: all_policies
```

### Update Ownership

```yaml
- name: Update schedule policy ownership
  purepx.px_backup.schedule_policy:
    api_url: "{{ px_backup_api_url }}"
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
```

## Error Handling

The module implements comprehensive error handling:

1. **Parameter Validation**

   - Required parameter checks
   - Format validation
   - Reference validation
   - Monthly policy conflict detection (cannot mix legacy and new formats)
2. **Common Error Scenarios**

   - Invalid schedule policies
   - Missing required configurations
   - Permission issues
   - Network connectivity problems
   - API errors
   - `supports_advanced_features` not set for advanced features

## Notes

1. **Version Compatibility**

   - Basic scheduling (interval, daily, weekly, legacy monthly): PX-Backup >= 2.9.0
   - Advanced features (multi-day, bi-weekly, relative/selective monthly): PX-Backup >= 2.11.0
   - Advanced features require `supports_advanced_features: true` in the schedule_policy
2. **Security Considerations**

   - Access control configuration
   - Token security
   - SSL certificate validation
   - Secret key protection
3. **Best Practices**

   - Use `selective_monthly_policy` or `relative_monthly_policy` for new monthly schedules
   - Legacy monthly fields (date, time, retain at root level) are deprecated
   - Set `supports_advanced_features: true` when using any v2.11.0 features
   - Cannot mix legacy monthly fields with new policy types
4. **Weekly Index Behavior**

   - `first`: 1st occurrence of the day (days 1-7)
   - `second`: 2nd occurrence (days 8-14)
   - `third`: 3rd occurrence (days 15-21)
   - `fourth`: 4th occurrence (days 22-28)
   - `last`: Last occurrence in the month (may differ from fourth)
5. **Limitations**

   - Only one monthly policy type can be specified (legacy OR relative OR selective)
   - `relative_monthly_policy` accepts only a single day
   - Dates that don't exist in a month are skipped (e.g., Feb 30)

## Troubleshooting

1. **Creation Issues**

   - Verify `supports_advanced_features: true` is set for v2.11.0 features
   - Ensure you're not mixing legacy and new monthly formats
   - Validate configurations
   - Ensure unique names
2. **Access Problems**

   - Verify ownership settings
   - Check group permissions
   - Validate token access
   - Review public access
3. **Update Failures**

   - Confirm schedule policy exists
   - Check update permissions
   - Validate new configurations
   - Review ownership rights
4. **Common Solutions**

   - Validate schedule policies structure
   - Check network connectivity
   - Verify SSL certificates
   - Review error messages
   - Check API endpoints
   - Ensure PX-Backup version supports requested features
