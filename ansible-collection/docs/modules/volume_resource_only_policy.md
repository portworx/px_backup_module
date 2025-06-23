# Volume Resource Only Policy Module

The volume_resource_only_policy module provides comprehensive management of PX-Backup volume resource only policies, which allow you to skip backing up volume data for specific volume types, CSI drivers, or NFS servers while still backing up the resource definitions.

## Synopsis

* Create and manage volume resource only policies in PX-Backup
* Configure policies to skip volume data backup for specific volume types
* Manage CSI driver-specific exclusions
* Control NFS server-specific backup exclusions
* Handle policy ownership and access control
* List and filter policies with advanced enumeration options

## Requirements

* PX-Backup >= 2.9.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:

| Operation        | Description                              |
| ------------------ | ------------------------------------------ |
| CREATE           | Create a new volume resource only policy |
| UPDATE           | Modify existing policy configuration     |
| DELETE           | Remove a volume resource only policy     |
| INSPECT_ONE      | Get details of a specific policy         |
| INSPECT_ALL      | List all volume resource only policies   |
| UPDATE_OWNERSHIP | Update policy ownership settings         |

## Parameters

### Common Parameters

| Parameter      | Type    | Required | Default | Description                                                                               |
| ---------------- | --------- | ---------- | --------- | ------------------------------------------------------------------------------------------- |
| api_url        | string  | yes      |         | PX-Backup API URL                                                                         |
| token          | string  | yes      |         | Authentication token                                                                      |
| name           | string  | varies   |         | Name of the policy (required for all operations except INSPECT_ALL)                       |
| org_id         | string  | yes      |         | Organization ID                                                                           |
| operation      | string  | yes      |         | Operation to perform                                                                      |
| uid            | string  | varies   |         | Policy unique identifier (required for UPDATE, DELETE, INSPECT_ONE, and UPDATE_OWNERSHIP) |
| validate_certs | boolean | no       | true    | Whether to validate SSL certificates                                                      |

### Policy Configuration Parameters

| Parameter    | Type | Required | Default | Description                                                             |
| -------------- | ------ | ---------- | --------- | ------------------------------------------------------------------------- |
| volume_types | list | no       |         | List of volume types to skip for volume data backup                     |
| csi_drivers  | list | no       |         | List of CSI drivers that should skip volume data backup                 |
| nfs_servers  | list | no       |         | List of NFS servers that should skip volume data backup for NFS volumes |

#### volume_types Values

| Value    | Description                               |
| ---------- | ------------------------------------------- |
| Invalid  | Invalid volume type (not recommended)     |
| Portworx | Portworx volumes                          |
| Csi      | CSI (Container Storage Interface) volumes |
| Nfs      | NFS (Network File System) volumes         |

### Metadata Parameters

| Parameter | Type       | Required | Description                    |
| ----------- | ------------ | ---------- | -------------------------------- |
| ownership | dictionary | no       | Ownership and access control   |

### Enumeration Parameters

| Parameter        | Type       | Required | Description                                              |
| ------------------ | ------------ | ---------- | ---------------------------------------------------------- |
| enumerate_options | dictionary | no       | Options for controlling enumeration behavior (INSPECT_ALL only) |

#### enumerate_options Structure

| Parameter                              | Type       | Required | Description                                                                          |
| ---------------------------------------- | ------------ | ---------- | -------------------------------------------------------------------------------------- |
| enumerate_options.generic_enumerate_options | dictionary | no       | Common enumeration options for filtering and pagination                              |

#### generic_enumerate_options Structure

| Parameter                                          | Type       | Required | Description                                                                    |
| ---------------------------------------------------- | ------------ | ---------- | -------------------------------------------------------------------------------- |
| generic_enumerate_options.labels                   | dictionary | no       | Key-value pairs for filtering policies by labels                               |
| generic_enumerate_options.max_objects              | integer    | no       | Maximum number of policies to return (useful for pagination)                  |
| generic_enumerate_options.name_filter              | string     | no       | Filter policies by name using substring matching (case-sensitive)             |
| generic_enumerate_options.object_index             | integer    | no       | Starting index for pagination (zero-based, used with max_objects)             |

### Ownership Configuration

| Parameter               | Type       | Required | Description                                |
| ------------------------- | ------------ | ---------- | -------------------------------------------- |
| ownership               | dictionary | no       | Ownership and access control configuration |
| ownership.owner         | string     | no       | Owner of the volume resource only policy   |
| ownership.groups        | list       | no       | List of group access configurations        |
| ownership.collaborators | list       | no       | List of collaborator access configurations |
| ownership.public        | dictionary | no       | Public access configuration                |

#### Ownership Access Configuration

| Parameter | Type   | Required | Choices                  | Description                      |
| ----------- | -------- | ---------- | -------------------------- | ---------------------------------- |
| id        | string | yes      |                          | Group or collaborator identifier |
| access    | string | yes      | 'Read', 'Write', 'Admin' | Access level                     |

## Examples

### Basic Usage

```yaml
# Create a basic volume resource only policy for Portworx volumes
- name: Create volume resource only policy for Portworx
  volume_resource_only_policy:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-portworx-data"
    org_id: "default"
    volume_types:
      - "Portworx"
```

### Advanced Configuration

```yaml
# Create a comprehensive policy with multiple volume types and CSI drivers
- name: Create comprehensive volume resource only policy
  volume_resource_only_policy:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-cloud-volumes"
    org_id: "default"
    volume_types:
      - "Portworx"
      - "Csi"
    csi_drivers:
      - "ebs.csi.aws.com"
      - "disk.csi.azure.com"
      - "pd.csi.storage.gke.io"
    labels:
      environment: "production"
      team: "platform"
      created_by: "ansible"
```

### NFS Configuration

```yaml
# Create policy for specific NFS servers
- name: Create NFS volume resource only policy
  volume_resource_only_policy:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-nfs-servers"
    org_id: "default"
    volume_types:
      - "Nfs"
    nfs_servers:
      - "nfs1.example.com"
      - "nfs2.example.com"
      - "192.168.1.100"
```

### Management Operations

```yaml
# List all volume resource only policies
- name: List all volume resource only policies
  volume_resource_only_policy:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"

# Get details of a specific policy
- name: Inspect specific volume resource only policy
  volume_resource_only_policy:
    operation: INSPECT_ONE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-portworx-data"
    org_id: "default"
    uid: "policy-uid-123"

# Update an existing policy
- name: Update volume resource only policy
  volume_resource_only_policy:
    operation: UPDATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-portworx-data"
    org_id: "default"
    uid: "policy-uid-123"
    volume_types:
      - "Portworx"
      - "Csi"
    csi_drivers:
      - "ebs.csi.aws.com"

# Delete a policy
- name: Delete volume resource only policy
  volume_resource_only_policy:
    operation: DELETE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-portworx-data"
    org_id: "default"
    uid: "policy-uid-123"
```

### Enumeration with Filtering

```yaml
# List policies with basic filtering
- name: List volume resource only policies with label filtering
  volume_resource_only_policy:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"

# List policies with advanced enumeration options
- name: List policies with pagination and filtering
  volume_resource_only_policy:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    enumerate_options:
      generic_enumerate_options:
        max_objects: 10
        name_filter: "prod"
        object_index: 0
        labels:
          environment: "production"

# List policies with name filtering
- name: Find policies by name pattern
  volume_resource_only_policy:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    enumerate_options:
      generic_enumerate_options:
        name_filter: "skip-"
        max_objects: 50

# Paginate through large policy lists
- name: Get next page of policies
  volume_resource_only_policy:
    operation: INSPECT_ALL
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    org_id: "default"
    enumerate_options:
      generic_enumerate_options:
        max_objects: 20
        object_index: 20  # Start from 21st policy
```

### Ownership Management

```yaml
# Update policy ownership
- name: Update volume resource only policy ownership
  volume_resource_only_policy:
    operation: UPDATE_OWNERSHIP
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    name: "skip-portworx-data"
    org_id: "default"
    uid: "policy-uid-123"
    ownership:
      owner: "admin@example.com"
      groups:
        - id: "backup-admins"
          access: "Admin"
        - id: "platform-team"
          access: "Write"
      collaborators:
        - id: "user1@example.com"
          access: "Read"
        - id: "user2@example.com"
          access: "Write"
      public:
        type: "Read"
```

## Return Values

### Single Policy Operations

For CREATE, UPDATE, INSPECT_ONE, DELETE, and UPDATE_OWNERSHIP operations:

```yaml
volume_resource_only_policy:
  description: Details of the volume resource only policy
  type: dict
  returned: success
  sample:
    metadata:
      name: "skip-portworx-data"
      org_id: "default"
      uid: "123456"
      labels:
        environment: "production"
        team: "platform"
      ownership:
        owner: "admin@company.com"
        groups:
          - id: "backup-admins"
            access: "Admin"
        collaborators:
          - id: "user@company.com"
            access: "Write"
    volume_resource_only_policy_info:
      volume_types: ["Portworx", "Csi"]
      csi_drivers: ["ebs.csi.aws.com", "disk.csi.azure.com"]
```

### Multiple Policies Operations

For INSPECT_ALL operations:

```yaml
volume_resource_only_policies:
  description: List of volume resource only policies
  type: list
  returned: when operation is INSPECT_ALL
  sample:
    - metadata:
        name: "policy1"
        org_id: "default"
        uid: "123"
      volume_resource_only_policy_info:
        volume_types: ["Portworx"]
        csi_drivers: []
        nfs_servers: []
    - metadata:
        name: "policy2"
        org_id: "default"
        uid: "456"
      volume_resource_only_policy_info:
        volume_types: ["Csi"]
        csi_drivers: ["ebs.csi.aws.com"]
        nfs_servers: []
```

### Common Return Values

```yaml
message:
  description: Operation result message
  type: str
  returned: always

changed:
  description: Whether the operation changed the policy
  type: bool
  returned: always
```

## Enumeration Use Cases

### Pagination Example

When dealing with large numbers of policies, use pagination:

```yaml
# Get first 20 policies
- name: Get first page of policies
  volume_resource_only_policy:
    operation: INSPECT_ALL
    org_id: "default"
    enumerate_options:
      generic_enumerate_options:
        max_objects: 20
        object_index: 0

# Get next 20 policies
- name: Get second page of policies
  volume_resource_only_policy:
    operation: INSPECT_ALL
    org_id: "default"
    enumerate_options:
      generic_enumerate_options:
        max_objects: 20
        object_index: 20
```

### Filtering Best Practices

1. **Combine Filters**: Use multiple filtering options together for precise results
2. **Label-based Organization**: Use consistent labeling strategies for easier filtering
3. **Name Patterns**: Adopt naming conventions that work well with substring filtering
4. **Pagination**: Always use pagination for production environments with many policies

## Error Handling

The module implements comprehensive error handling:

1. **Parameter Validation**
   - Required parameter checks
   - Valid enum value validation
   - Format validation
   - Enumeration option validation

2. **API Communication Errors**
   - Connection failures
   - Authentication errors
   - API response parsing

3. **Resource State Validation**
   - Policy existence checks
   - Update conflict detection
   - Dependency validation

4. **Permission Checks**
   - Access control validation
   - Ownership verification

### Common Error Scenarios

- **Invalid volume type**: When an unsupported volume type is specified
- **Policy not found**: When referencing a non-existent policy
- **Permission denied**: When user lacks required permissions
- **Invalid CSI driver**: When specifying non-existent CSI drivers
- **Network connectivity**: When API endpoint is unreachable
- **Invalid enumeration parameters**: When pagination or filtering parameters are malformed