# Receiver Module

The receiver module provides comprehensive management of PX-Backup alert receivers, enabling configuration and management of email notification endpoints for system alerts. It supports creation, modification, deletion, SMTP validation, and inspection of email receivers.

## Synopsis

* Create and manage alert receivers in PX-Backup
* Configure and validate SMTP settings
* Manage email notification endpoints
* Support for multiple email configurations
* Comprehensive inspection and enumeration capabilities

## Requirements

* PX-Backup >= 2.8.4
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:

| Operation      | Description                           |
|---------------|---------------------------------------|
| CREATE        | Create a new receiver                 |
| UPDATE        | Modify existing receiver              |
| DELETE        | Remove a receiver                     |
| VALIDATE_SMTP | Validate SMTP configuration           |
| INSPECT_ONE   | Get details of a specific receiver    |
| INSPECT_ALL   | List all receivers                    |

## Parameters

### Common Parameters

| Parameter      | Type    | Required | Default | Description                                                                             |
|---------------|---------|----------|---------|-----------------------------------------------------------------------------------------|
| api_url       | string  | yes      |         | PX-Backup API URL                                                                       |
| token         | string  | yes      |         | Authentication token                                                                    |
| name          | string  | varies   |         | Name of the receiver (required for all operations except INSPECT_ALL)                   |
| org_id        | string  | yes      |         | Organization ID                                                                         |
| operation     | string  | yes      |         | Operation to perform                                                                    |
| uid           | string  | varies   |         | Receiver unique identifier (required for UPDATE, DELETE, and INSPECT_ONE)               |
| validate_certs| boolean | no       | true    | Whether to validate SSL certificates                                                    |

### Email Configuration Parameters

| Parameter               | Type    | Required | Default | Description                    |
|------------------------|---------|----------|---------|--------------------------------|
| receiver_type          | string  | no       | EMAIL   | Type of receiver              |
| email_config.from      | string  | yes      |         | Sender email address          |
| email_config.host      | string  | yes      |         | SMTP host address             |
| email_config.port      | string  | yes      |         | SMTP port                     |
| email_config.encryption_ssl     | boolean | no       | false   | Enable SSL encryption          |
| email_config.encryption_starttls| boolean | no       | false   | Enable STARTTLS encryption    |
| email_config.authentication    | boolean | no       | false   | Enable SMTP authentication    |
| email_config.auth_username     | string  | no       |         | SMTP authentication username  |
| email_config.auth_password     | string  | no       |         | SMTP authentication password  |

### SMTP Validation Parameters

| Parameter    | Type    | Required | Default | Description                      |
|-------------|---------|----------|---------|----------------------------------|
| recipient_id| list    | no       |         | List of test recipient addresses |

## Examples

### Creating an Email Receiver

```yaml
- name: Create email receiver
  receiver:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "alerts-email"
    org_id: "default"
    email_config:
      from: "alerts@example.com"
      host: "smtp.example.com"
      port: "587"
      encryption_starttls: true
      authentication: true
      auth_username: "alerts@example.com"
      auth_password: "{{ smtp_password }}"
```

### Validating SMTP Configuration

```yaml
- name: Validate SMTP configuration
  receiver:
    operation: VALIDATE_SMTP
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "alerts-email"
    org_id: "default"
    email_config:
      from: "alerts@example.com"
      host: "smtp.example.com"
      port: "587"
      encryption_starttls: true
      authentication: true
      auth_username: "alerts@example.com"
      auth_password: "{{ smtp_password }}"
    recipient_id:
      - "test@example.com"
```

## Error Handling

The module implements comprehensive error handling:

1. Parameter validation
2. SMTP configuration validation
3. Authentication failures
4. API communication errors
5. Email delivery validation

Common error scenarios:

- Invalid SMTP credentials
- Connection failures
- Invalid port configurations
- Authentication errors
- SSL/TLS configuration issues
- Email delivery failures

## Notes

1. **Security Considerations**
   - Secure password management
   - Authentication settings
   - Access control

2. **SMTP Configuration Considerations**
   - Port selection
   - Encryption options
   - Authentication requirements
   - Server restrictions

3. **Best Practices**
   - Regular validation testing
   - Proper error handling
   - Monitoring delivery success
   - Configuration backups

4. **Limitations**
   - Currently supports only EMAIL type receivers
   - Operation-specific requirements
   - SMTP server restrictions
   - Email delivery policies

## Return Values

The module returns the following information:

| Key      | Type   | Description                            |
|----------|--------|----------------------------------------|
| changed  | bool   | Whether the operation changed state    |
| receiver | dict   | Details of the affected receiver       |
| receivers| list   | List of receivers (for INSPECT_ALL)    |
| message  | string | Operation status message               |

The receiver object structure includes:

```yaml
receiver:
  metadata:
    name: "alerts-email"
    org_id: "default"
    uid: "123-456"
    create_time: "2024-12-19T06:29:03Z"
  receiver_info:
    type: "EMAIL"
    email_config:
      from: "alerts@example.com"
      host: "smtp.example.com"
      port: "587"
      authentication: true
```