# PX-Backup Ansible Collection

Ansible collection for managing PX-Backup operations. This collection provides modules for managing backup locations, schedules, cloud credentials, and cluster operations in PX-Backup.

## Requirements

- Ansible Core >= 2.17.6
- Python >= 3.9
- PX-Backup >= 2.9.0
- Stork >= 25.3.0
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

# Output configuration
output_config:
  enabled: true                                                     # Master switch for output handling
  display:
    console: true                                                   # Display to console/stdout
    format: "yaml"                                                  # Default display format: yaml, json
  file:
    enabled: true                                                   # Save to file
    formats:                                                        # Multiple formats can be saved
      - yaml
      - json
    # see files saved at: ansible-collection/output
    directory: "{{ playbook_dir | dirname | dirname }}/output"      # Output directory
    timestamp: true                                                 # Add timestamp to filename
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

### Configuration Files
The collection includes important configuration files for optimal operation:

#### Ansible Configuration (`ansible.cfg`)
```ini
[defaults]
library = ./plugins/modules
module_utils = ./plugins/module_utils
inventory = ./inventory/hosts
hash_behaviour = merge
host_key_checking = False
interpreter_python = /usr/bin/python3 
callback_result_format = yaml

[inventory]
enable_plugins = host_list, yaml, ini
vars_plugins_paths = inventory/group_vars
```

Key settings:
- **callback_result_format = yaml**: Forces Ansible to display task results in YAML format for better readability and consistency with the output configuration
- **library/module_utils**: Points to the collection's custom modules and utilities
- **hash_behaviour = merge**: Enables variable merging for complex configurations
- **vars_plugins_paths**: Automatically loads variables from group_vars structure

#### Output Configuration (`all.yml`)

The collection includes output configuration in the `all.yml` file that provides flexible output handling for better debugging and result tracking:

- **enabled**: Master switch to enable/disable output handling globally
- **display.console**: Controls whether output is displayed to console/stdout  
- **display.format**: Default format for console output (`yaml` or `json`)
- **file.enabled**: Enable/disable saving output to files
- **file.formats**: List of formats to save (supports `yaml` and `json`)
- **file.directory**: Output directory path (supports Ansible variables like `playbook_dir`)
- **file.timestamp**: Add timestamp to output filenames for uniqueness

Output files are automatically saved to `ansible-collection/output/` with timestamps when enabled.

## Documentation

Detailed documentation is available in the following locations:
- [Module Documentation (GITHUB LINK)](https://github.com/portworx/px_backup_module/blob/main/ansible-collection/docs/README.md)
- [Example Playbooks (GITHUB LINK)](https://github.com/portworx/px_backup_module/tree/main/ansible-collection/examples)
- [PX-Backup Documentation](https://docs.portworx.com/portworx-backup-on-prem)

## License

Apache-2.0
