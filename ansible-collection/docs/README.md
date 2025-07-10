# PX-Backup Collection Documentation

Complete documentation for the PX-Backup Ansible collection modules, playbooks, and operations.

## Module Reference

### Cloud Credential Module

- [cloud_credential](modules/cloud_credential.md)
  - Manage cloud provider credentials
  - Support for AWS, Azure, Google, IBM, and Rancher
  - Credential access control

### Cluster Module

- [cluster](modules/cluster.md)
  - Manage cluster operations
  - Control cluster access
  - Update cluster configurations

### Backup Location Module

- [backup_location](modules/backup_location.md)
  - Manage backup location
  - Support for S3, Azure, Google, and NFS storage
  - Backup location validation and ownership management

### Backup Schedule Module

- [backup_schedule](modules/backup_schedule.md)
  - Schedule backup operations
  - Configure backup policies and retention
  - Monitor backup execution status

### Backup Module

- [backup](modules/backup.md)
  - Backup operations
  - Configure backup policies and retention
  - Monitor backup execution status

### Restore Module

- [restore](modules/restore.md)
  - Restore operations
  - Monitor restore execution status

### Resource Collector Module

- [resource_collector](modules/resource_collector.md)
  - List the available resources on a cluster for backup

### Rule Module
- [rule](modules/rule.md)
  - Manage rule operations
  - Control rule access
  - Update rule configurations

### Role Module
- [role](modules/role.md)
  - Manage role operations
  - Update role configurations
  - Fetch role permissions

### Schedule Policy Module
- [schedule_policy](modules/schedule_policy.md)
  - Manage schedule policy operations
  - Update schedule policy configurations
  - Control policy access

### Volume Resource Only Policy Module
- [volume_resource_only_policy](modules/volume_resource_only_policy.md)
  - Manage volume resource only policies for selective backup exclusion
  - Skip volume data backup while preserving resource definitions
  - Support for Portworx, CSI, and NFS volume types
  - Configure CSI driver-specific and NFS server-specific exclusions
  - Control policy ownership and access permissions

## Configuration

### Authentication

PX-Backup uses token-based authentication. Configure your authentication token in your inventory variables:

```yaml
# inventory/group_vars/common/all.yml
# inventory/group_vars/common/all.yml
px_backup_api_url: "https://your-px-backup-instance-api-url"
# Get the port by creating a Node Port or External IP on the px-backup service
# > kubectl expose svc px-backup --type NodePort --port 10001 --name px-backup-exposed -n central
# service/px-backup-exposed exposed
# > kubectl get svc -n central | grep "px-backup-exposed"
# px-backup-exposed                        NodePort       10.233.9.90     <none>        10001:32218/TCP
px_backup_token: "your-auth-token" #skip if providing username and password
org_id: "default"
pxcentral_auth_url: "https://your-px-backup-instance-auth-url"
pxcentral_client_id: "client_id"
pxcentral_username: "username"
pxcentral_password: "password"
```

## API Integration

This collection integrates with PX-Backup API v2.9.0. For detailed API documentation, visit:

- [PX-Backup Proto File](https://github.com/portworx/px-backup-api/blob/master/pkg/apis/v1/api.proto)
- [PX-Backup Product Documentation](https://docs.portworx.com/portworx-backup-on-prem)

## Inventory Structure

```
inventory/
├── group_vars/
│   ├── backup/
│   ├── backup_location/
│   ├── backup_schedule/
│   ├── cloud_credential/
│   ├── cluster/
│   ├── common/
│   ├── restore/
│   ├── rule/
│   ├── role/
│   ├── schedule_policy/
│   └── volume_resource_only_policy/
└── hosts
```

For detailed examples of each operation, refer to the [examples](../examples/) directory.
