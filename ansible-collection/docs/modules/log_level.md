# Log Level Module

## Overview

The log level module enables runtime management of PX-Backup service log levels without requiring `pod` restarts. This module is new in PX-Backup 2.10.0 and provides dynamic log level control for troubleshooting and debugging.

## Synopsis

* Get current log level for PX-Backup services
* Set log level dynamically without service restart
* Support for Debug, Info, and Trace log levels
* Organization-scoped log level management
* Immediate effect without downtime

## Requirements

* PX-Backup >= 2.10.0
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:

| Operation | Description |
|-----------|-------------|
| INSPECT | Retrieve current log level |
| UPDATE | Set new log level |

## Parameters

### Common Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| operation | string | yes | - | Operation to perform (INSPECT or UPDATE) |
| api_url | string | yes | - | PX-Backup API URL |
| token | string | yes | - | Authentication token |
| org_id | string | yes | - | Organization ID |
| level | string | no | - | Log level to set (required for SET operation) |
| ssl_config | dict | no | {} | SSL certificate configuration(inherited from the auth module) |

### Log Levels

| Level | Value | Description |
|-------|-------|-------------|
| Debug | 0 | Most verbose logging, includes all debug information |
| Info | 1 | Standard informational logging, recommended for production |
| Trace | 2 | Detailed trace logging, useful for deep debugging |


## Examples

### Get Current Log Level

```yaml
- name: Get current log level
  log_level:
    operation: INSPECT
    api_url: "http://px-backup.example.com:10001"
    token: "{{ px_backup_token }}"
    org_id: "default"
```

### Set Log Level to Debug

```yaml
- name: Enable debug logging
  log_level:
    operation: UPDATE
    api_url: "http://px-backup.example.com:10001"
    token: "{{ px_backup_token }}"
    org_id: "default"
    level: "Debug"
```

### Automated Troubleshooting Workflow

```yaml
- name: Automated troubleshooting with log level management
  block:
    - name: Enable debug logging
      log_level:
        operation: UPDATE
        api_url: "{{ px_backup_api_url }}"
        token: "{{ px_backup_token }}"
        org_id: "{{ org_id }}"
        level: "Debug"

    - name: Perform troubleshooting operations
      # Your troubleshooting tasks here
      debug:
        msg: "Performing operations with debug logging enabled"

    - name: Restore normal logging
      log_level:
        operation: UPDATE
        api_url: "{{ px_backup_api_url }}"
        token: "{{ px_backup_token }}"
        org_id: "{{ org_id }}"
        level: "Info"
```

## Return Values

| Key | Type | Description |
|-----|------|-------------|
| level | string | Current or newly set log level |
| changed | boolean | Whether the log level was changed |
| message | string | Operation result message |

## Use Cases

### 1. Troubleshooting Issues

Enable debug logging when investigating problems:

```yaml
- name: Enable debug for troubleshooting
  log_level:
    operation: UPDATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "{{ org_id }}"
    level: "Debug"
```

### 2. Production Monitoring

Ensure appropriate log level for production:

```yaml
- name: Set production log level
  log_level:
    operation: UPDATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "{{ org_id }}"
    level: "Info"
```

### 3. Deep Debugging

Use trace level for detailed analysis:

```yaml
- name: Enable trace logging
  log_level:
    operation: UPDATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    org_id: "{{ org_id }}"
    level: "Trace"
```

## Best Practices

1. **Use Info level for production** - Provides adequate logging without excessive verbosity
2. **Enable Debug/Trace temporarily** - Use higher log levels only during troubleshooting
3. **Automate log level restoration** - Always restore appropriate log level after debugging
4. **Monitor log volume** - Debug and Trace levels generate significantly more logs
5. **Coordinate with team** - Inform team members when changing log levels in shared environments

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "Failed to get log level" | API connection or permission issue | Check token and API URL |
| "Failed to set log level" | Invalid level or permission issue | Verify log level value and permissions |
| "Invalid log level" | Incorrect level value | Use Debug, Info, or Trace |

## Notes

- Log level changes take effect immediately without service restart
- Log levels are organization-scoped
- Higher log levels (Debug, Trace) generate more log data
- Consider log storage capacity when using verbose logging
- This feature requires PX-Backup 2.10.0 or later