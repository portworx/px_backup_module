# PX-Backup Ansible Collection

Ansible collection for managing PX-Backup operations. This collection provides modules for managing backup locations, schedules, cloud credentials, and cluster operations in PX-Backup.

## Requirements

- Ansible Core >= 2.17.6
- Python >= 3.9
- PX-Backup >= 2.8.4
- Stork >= 24.3.3
- Python Requests library

## Installation

```bash
ansible-galaxy collection install purepx.px_backup
```

For development and reference setup:
```bash
git clone https://github.com/portworx/px_backup_module.git
cd px_backup_module
```


## Quick Start

1. Configure your PX-Backup authentication:
```yaml
# inventory/group_vars/common/all.yml
px_backup_api_url: "https://your-px-backup-instance-api-url"
# Get the port by creating a Node Port or External IP on the px-backup service
# > kubectl expose svc px-backup --type NodePort --port 10001 --name px-backup-exposed -n central
# service/px-backup-exposed exposed
# > kubectl get svc -n central | grep "px-backup-exposed"
# px-backup-exposed                        NodePort       10.233.9.90     <none>        10001:32218/TCP
px_backup_token: "your-auth-token" # Skip if providing username and password
org_id: "default"
pxcentral_auth_url: "https://your-px-backup-instance-auth-url"
pxcentral_client_id: "client_id"
pxcentral_username: "username"
pxcentral_password: "password"
```

2. Create a backup location:
```yaml
---
- name: Configure PX-Backup S3 Backup Location
  hosts: localhost
  gather_facts: false
  collections:
  - purepx.px_backup # Add the collection name to your playbooks

- name: Create S3 backup location
  backup_location: # Import the modules directly
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    name: "prod-backup"
    org_id: "default"
    location_type: "S3"
    path: "my-backup-bucket"
    s3_config:
      region: "us-east-1"
      endpoint: "s3.amazonaws.com"
```

## Documentation

Detailed documentation is available in the following locations:
- [Module Documentation (GITHUB LINK)](ansible-collection/docs/README.md)
- [Example Playbooks (GITHUB LINK)](ansible-collection/examples/)
- [PX-Backup Documentation](https://docs.portworx.com/portworx-backup-on-prem)

## License

Apache-2.0