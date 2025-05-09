# Recipient Module

The recipient module provides comprehensive management of alert recipients in PX-Backup, including creation, modification, deletion and inspection capabilities for configuring alert notifications.

## Synopsis

* Create and manage alert recipients in PX-Backup
* Configure recipient email lists
* Link recipients to alert receivers
* Set alert severity levels
* Control notification activity status
* Comprehensive inspection and enumeration capabilities

## Requirements

* PX-Backup >= 2.8.4
* Stork >= 24.3.3
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:

| Operation    | Description                          |
|-------------|--------------------------------------|
| CREATE      | Create a new recipient               |
| UPDATE      | Modify existing recipient            |
| DELETE      | Remove a recipient                   |
| INSPECT_ONE | Get details of a specific recipient  |
| INSPECT_ALL | List all recipients                  |

## Parameters

### Common Parameters

| Parameter      | Type    | Required | Default | Description                                                                |
|---------------|---------|----------|---------|----------------------------------------------------------------------------|
| api_url       | string  | yes      |         | PX-Backup API URL                                                          |
| token         | string  | yes      |         | Authentication token                                                       |
| name          | string  | varies   |         | Name of the recipient (required for all operations except INSPECT_ALL)     |
| org_id        | string  | yes      |         | Organization ID                                                            |
| operation     | string  | yes      |         | Operation to perform                                                       |
| uid           | string  | varies   |         | Recipient unique identifier (required for UPDATE, DELETE, and INSPECT_ONE) |
| validate_certs| boolean | no       | true    | Whether to validate SSL certificates                                       |

### Recipient Configuration Parameters

| Parameter      | Type    | Required | Description                        | Choices                              |
|---------------|---------|----------|------------------------------------|--------------------------------------|
| recipient_type| string  | no       | Type of recipient                  | 'EMAIL'                              |
| recipient_ids | list    | varies   | List of recipient email addresses  |                                      |
| active        | boolean | no       | Whether the recipient is active    |                                      |
| severity      | string  | no       | Alert severity level               | 'UNKNOWN', 'CRITICAL', 'WARNING'     |

### Receiver Reference

| Parameter                | Type   | Required | Description                |
|-------------------------|--------|----------|----------------------------|
| receiver_ref.name       | string | yes      | Name of the receiver      |
| receiver_ref.uid        | string | yes      | UID of the receiver       |

### Labels Configuration

| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| labels    | dict   | no       | Key-value pairs for recipient labels   |

## Operation-Specific Requirements

### CREATE Operation
Required parameters:
- name
- recipient_ids
- receiver_ref

### UPDATE Operation
Required parameters:
- name
- uid

### DELETE Operation
Required parameters:
- name
- uid

### INSPECT_ONE Operation
Required parameters:
- name
- uid

### INSPECT_ALL Operation
Required parameters:
- org_id

## Examples

### Create a recipient
```yaml
- name: Create email recipient
  recipient:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "dev-team"
    org_id: "default"
    recipient_type: "EMAIL"
    recipient_ids:
      - "dev1@example.com"
      - "dev2@example.com"
    receiver_ref:
      name: "smtp-server"
      uid: "receiver-uid"
    severity: "CRITICAL"
    active: true
```

### Update a recipient
```yaml
- name: Update email recipient
  recipient:
    operation: UPDATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "dev-team"
    uid: "recipient-uid"
    org_id: "default"
    recipient_ids:
      - "dev1@example.com"
      - "dev2@example.com"
      - "dev3@example.com"
    severity: "WARNING"
```

### Delete a recipient
```yaml
- name: Delete recipient
  recipient:
    operation: DELETE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "dev-team"
    uid: "recipient-uid"
    org_id: "default"
```

## Return Values

The module returns the following information:

| Key       | Type   | Description                          |
|-----------|--------|--------------------------------------|
| changed   | bool   | Whether the operation changed state  |
| recipient | dict   | Details of the affected recipient    |
| recipients| list   | List of recipients (for INSPECT_ALL) |
| message   | string | Operation status message             |

### Recipient Object Structure

```yaml
recipient:
  metadata:
    name: "dev-team"
    org_id: "default"
    uid: "123-456"
    create_time: "2024-12-19T06:29:03Z"
    ownership:
      owner: "user-id"
  recipient_info:
    type: "EMAIL"
    recipient_id:
      - "dev1@example.com"
      - "dev2@example.com"
    active: true
    severity: "CRITICAL"
    receiver_ref:
      name: "smtp-server"
      uid: "receiver-uid"
```

## Error Handling

The module implements comprehensive error handling:

1. Parameter validation
2. API communication errors
3. Authentication failures
4. Resource state validation
5. Permission checks

Common error scenarios:
- Invalid recipient configuration
- Duplicate recipient names
- Invalid receiver reference
- Permission denied
- Network connectivity issues

## Notes

1. **Configuration Considerations**
   - Email address validation
   - Severity level selection
   - Receiver connectivity
   - Alert filtering

2. **Best Practices**
   - Regular validation of email addresses
   - Proper severity level configuration
   - Clear recipient naming conventions
   - Monitoring alert delivery

3. **Limitations**
   - Currently supports only EMAIL type recipients
   - Operation-specific requirements
   - Recipient naming restrictions
   - Alert delivery policies

4. **Security Considerations**
   - Access control
   - Email address privacy
