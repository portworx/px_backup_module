# Schedule Policy Module

The schedule policy module manages schedule policies in PX-Backup, enabling configuration and management of schedule details for various intervals.

## Synopsis

* Create and manage schedule policies in PX-Backup
* Access control and ownership management
* Comprehensive policy inspection capabilities

## Requirements

* PX-Backup >= 2.10.0
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
| schedule_policy | string | yes      |         | Schedule Policy configuration | `interval`, `daily`, `weekly`, `monthly` |

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


| Parameter                        | Type   | Required | Choices       | Description                                                                             |
| ---------------------------------- | -------- | ---------- | --------------- | ----------------------------------------------------------------------------------------- |
| interval.minutes                 | int    | yes      |               | Defines the interval in minutes for periodic scheduling.                                |
| interval.retain                  | int    | yes      |               | Specifies the number of periodic backups to retain.                                     |
| interval.incremental_count.count | int    | no       |               | Number of incremental backups to retain within the periodic schedule.                   |
| daily.time                       | string | yes      |               | Specifies the time of day for daily backups (format: HH:MMAM/PM, e.g., 01:00AM).        |
| daily.retain                     | int    | yes      |               | Number of daily backups to retain.                                                      |
| daily.incremental_count.count    | int    | no       |               | Number of incremental backups to retain within the daily schedule.                      |
| weekly.day                       | string | yes      | Monday-Sunday | Day of the week for weekly backups (e.g., Sunday).                                      |
| weekly.time                      | string | yes      |               | Time of day for weekly backups (format: HH:MMAM/PM).                                    |
| weekly.retain                    | int    | yes      |               | Number of weekly backups to retain.                                                     |
| weekly.incremental_count.count   | int    | no       |               | Number of incremental backups to retain within the weekly schedule.                     |
| monthly.date                     | string | yes      | 1-31          | Day of the month for monthly backups (e.g., 1 for the 1st day of the month).            |
| monthly.time                     | string | yes      |               | Time of day for monthly backups (format: HH:MMAM/PM).                                   |
| monthly.retain                   | int    | yes      |               | Number of monthly backups to retain.                                                    |
| monthly.incremental_count.count  | int    | no       |               | Number of incremental backups to retain within the monthly schedule.                    |
| backup_schedule                  | list   | no       |               | A list of custom backup schedules (each schedule as a string).                          |
| for_object_lock                  | bool   | no       | true/false    | Enables a locked schedule policy for object-locked backups.                             |
| auto_delete                      | bool   | no       | true/false    | Specifies whether backups are automatically deleted after the retention period expires. |

## Error Handling

The module implements comprehensive error handling:

1. Parameter Validation

   - Required parameter checks
   - Format validation
   - Reference validation
2. Common Error Scenarios

   - Invalid schedule policies
   - Missing required configurations
   - Permission issues
   - Network connectivity problems
   - API errors

## notes

1. **Security Considerations**

   - Access control configuration
   - Token security
   - SSL certificate validation
   - Secret key protection
2. **Cloud Provider Requirements**

   - Interval-specific configurations
   - Authentication methods
   - Required permissions
   - Access scope considerations
3. **Best Practices**

   - Minimal permission scope
   - Access control review
   - Audit logging
   - Encryption at rest
4. **Limitations**

   - Permission boundaries
   - Update constraints
   - schedule policy validation

## Troubleshooting

1. **Creation Issues**

   - Verify schedule policies are correct
   - Check permissions
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

   - Validate schedule policies
   - Check network connectivity
   - Verify SSL certificates
   - Review error messages
   - Check API endpoints
