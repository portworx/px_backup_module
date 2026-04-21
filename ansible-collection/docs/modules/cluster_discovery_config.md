# Cluster Discovery Config Module

The cluster discovery config module manages cluster discovery configurations in PX-Backup, enabling automatic and manual discovery of Kubernetes clusters from external platforms such as Gardener.

## Synopsis

* Create and manage cluster discovery configurations in PX-Backup
* Automatic discovery of Gardener Shoot clusters with configurable frequency
* Manual trigger for cluster discovery and credential refresh
* Label selector-based filtering for targeted cluster discovery
* Comprehensive configuration inspection and enumeration

## Requirements

* PX-Backup >= 3.0.0
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation         | Description                                                       |
| ------------------- | ------------------------------------------------------------------- |
| CREATE            | Create a new cluster discovery configuration                     |
| UPDATE            | Modify existing cluster discovery configuration                  |
| DELETE            | Remove a cluster discovery configuration                         |
| INSPECT_ONE       | Get details of a specific cluster discovery configuration        |
| INSPECT_ALL       | List all cluster discovery configurations                        |
| DISCOVER_CLUSTERS | Manually trigger cluster discovery for a configuration           |
| REFRESH_CLUSTERS  | Manually trigger credential refresh for all discovered clusters  |

## Parameters

### Common Parameters


| Parameter | Type   | Required | Default   | Description                                     |
| ----------- | -------- | ---------- | ----------- | ------------------------------------------------- |
| api_url   | string | yes      |           | PX-Backup API URL                               |
| token     | string | yes      |           | Authentication token                            |
| operation | string | yes      |           | Operation to perform                            |
| name      | string | varies   |           | Name of the cluster discovery config            |
| org_id    | string | yes      | `default` | Organization ID                                 |
| uid       | string | no       |           | Unique identifier (for exact match operations)  |
| labels    | dict   | no       |           | Metadata labels for the configuration           |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### Discovery Config Parameters


| Parameter          | Type   | Required | Choices        | Description                                              |
| -------------------- | -------- | ---------- | ---------------- | ---------------------------------------------------------- |
| config_type        | string | varies   | `Shoot`, `All` | Type of discovery configuration                          |
| shoot_config       | dict   | varies   |                | Gardener Shoot discovery configuration                   |
| settings           | dict   | no       |                | Common discovery settings (auto-discover, frequency)     |
| include_secrets    | bool   | no       | true/false     | Include sensitive fields in the response                 |
| confirm_update     | bool   | varies   | true/false     | Required confirmation flag for update operations         |
| gardener_kubeconfig| string | no       |                | Updated Gardener kubeconfig, base64-encoded (for UPDATE operations only) |

#### shoot_config


| Parameter                        | Type   | Required | Description                                                    |
| ---------------------------------- | -------- | ---------- | ---------------------------------------------------------------- |
| shoot_config.gardener_kubeconfig | string | yes      | Gardener API server kubeconfig for authentication (must be base64-encoded) |
| shoot_config.project_name        | string | yes      | Gardener project name to discover Shoot clusters from          |
| shoot_config.label_selector      | string | no       | Label selector to filter Shoot clusters (K8s selector syntax)  |

#### settings


| Parameter                              | Type | Required | Default | Description                                           |
| ---------------------------------------- | ------ | ---------- | --------- | ------------------------------------------------------- |
| settings.auto_discover                 | bool | no       |         | Enable or disable automatic periodic discovery        |
| settings.auto_discover_frequency       | dict | no       |         | Frequency of automatic discovery                      |
| settings.auto_discover_frequency.days  | int  | no       | 0       | Days between discovery runs (0-365)                   |
| settings.auto_discover_frequency.hours | int  | no       | 0       | Hours between discovery runs (0-23)                   |
| settings.auto_discover_frequency.minutes| int | no       | 0       | Minutes between discovery runs (0-59)                 |

> **Note**: The minimum total auto-discover interval is 15 minutes.

### Operation-Specific Required Parameters


| Operation         | Required Parameters                                      |
| ------------------- | ---------------------------------------------------------- |
| CREATE            | `name`, `org_id`, `config_type`, `shoot_config`          |
| UPDATE            | `name`, `org_id`, `confirm_update` (must be `true`)      |
| DELETE            | `name`, `org_id`                                         |
| INSPECT_ONE       | `name`, `org_id`                                         |
| INSPECT_ALL       | `org_id`                                                 |
| DISCOVER_CLUSTERS | `name`, `org_id`                                         |
| REFRESH_CLUSTERS  | `name`, `org_id`                                         |


## Examples

### Create Shoot Discovery Config (Auto-Discover Enabled)

```yaml
- name: Create Gardener Shoot discovery config
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "gardener-shoot-discovery"
    org_id: "default"
    config_type: "Shoot"
    shoot_config:
      gardener_kubeconfig: "{{ gardener_kubeconfig }}"
      project_name: "my-gardener-project"
      label_selector: "environment=staging"
    settings:
      auto_discover: true
      auto_discover_frequency:
        days: 1
        hours: 0
        minutes: 0
    labels:
      team: "platform"
      environment: "staging"
```

### Create Shoot Discovery Config (Manual-Only)

```yaml
- name: Create manual-only discovery config
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: CREATE
    name: "gardener-shoot-manual"
    org_id: "default"
    config_type: "Shoot"
    shoot_config:
      gardener_kubeconfig: "{{ gardener_kubeconfig }}"
      project_name: "my-gardener-project"
      label_selector: "team=backend"
    settings:
      auto_discover: false
      auto_discover_frequency:
        days: 1
        hours: 0
        minutes: 0
```

### Update Discovery Config

```yaml
- name: Toggle auto-discover off
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: UPDATE
    name: "gardener-shoot-discovery"
    org_id: "default"
    settings:
      auto_discover: false
    confirm_update: true

- name: Rotate Gardener kubeconfig
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: UPDATE
    name: "gardener-shoot-discovery"
    org_id: "default"
    gardener_kubeconfig: "{{ new_gardener_kubeconfig }}"
    confirm_update: true

- name: Update everything at once
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: UPDATE
    name: "gardener-shoot-discovery"
    org_id: "default"
    gardener_kubeconfig: "{{ new_gardener_kubeconfig }}"
    settings:
      auto_discover: true
      auto_discover_frequency:
        days: 1
        hours: 0
        minutes: 0
    labels:
      team: "sre"
      rotated: "true"
    confirm_update: true
```

### Inspect Discovery Config

```yaml
- name: Inspect a specific discovery config
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: INSPECT_ONE
    name: "gardener-shoot-discovery"
    org_id: "default"
    include_secrets: true
  register: inspect_result
```

### Enumerate All Discovery Configs

```yaml
- name: List all discovery configs
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: INSPECT_ALL
    org_id: "default"
  register: all_configs
```

### Trigger Manual Discovery

```yaml
- name: Manually trigger cluster discovery
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: DISCOVER_CLUSTERS
    name: "gardener-shoot-discovery"
    org_id: "default"
```

### Trigger Credential Refresh

```yaml
- name: Refresh kubeconfigs for all discovered clusters
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: REFRESH_CLUSTERS
    name: "gardener-shoot-discovery"
    org_id: "default"
```

### Delete Discovery Config

```yaml
- name: Delete a discovery config
  purepx.px_backup.cluster_discovery_config:
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    operation: DELETE
    name: "gardener-shoot-discovery"
    org_id: "default"
```


## Error Handling

The module implements comprehensive error handling:

1. **Parameter Validation**

   - Required parameter checks per operation
   - Config type validation
   - SSL certificate file existence checks
   - Mutual TLS cert/key pairing validation

2. **Common Error Scenarios**

   - Invalid or expired Gardener kubeconfig
   - Gardener project not found
   - Duplicate discovery config (same project + label_selector combination)
   - Missing `confirm_update: true` on update requests
   - Discovery config not found (inspect/delete/discover/refresh)
   - Permission denied
   - Network connectivity issues

## Notes

1. **Async Operations**

   - `DISCOVER_CLUSTERS` and `REFRESH_CLUSTERS` are asynchronous — the response confirms triggering, not completion
   - Use `INSPECT_ONE` to poll `status` and `refresh_status` fields for completion

2. **Update Behavior**

   - `confirm_update: true` is mandatory for all update operations; otherwise the API rejects the request
   - In UPDATE, `gardener_kubeconfig` is a top-level field (not nested inside `shoot_config`)
   - The Gardener API server endpoint within the kubeconfig cannot be changed via update

3. **Label Selectors**

   - `shoot_config.label_selector` filters which Gardener Shoot clusters to discover
   - Supports standard Kubernetes label selector syntax: `key=value`, `key in (v1,v2)`, `!key`
   - `labels` are metadata labels on the discovery config object itself (not discovery filters)

4. **Security Considerations**

   - `gardener_kubeconfig` and `token` are marked `no_log` and will not appear in Ansible output
   - Use `include_secrets: true` only when you need to retrieve the stored kubeconfig

5. **Auto-Discover Frequency**

   - Minimum allowed total interval is 15 minutes
   - When `auto_discover: false`, the frequency is stored but not active — use `DISCOVER_CLUSTERS` for manual runs

6. **Uniqueness Constraint**

   - A discovery config is unique per Gardener project + label_selector combination
   - Creating a second config with the same project and label_selector will result in a 409 Conflict

## Troubleshooting

1. **Creation Issues**

   - Verify the Gardener kubeconfig is valid and has access to the specified project
   - Ensure the project + label_selector combination is not already used by another config
   - Check that auto_discover_frequency totals at least 15 minutes

2. **Discovery Failures**

   - Inspect the config and check `status.reason` for error details
   - Verify the Gardener kubeconfig token has not expired
   - Ensure the Gardener API server is reachable from the PX-Backup cluster

3. **Refresh Failures**

   - Inspect the config and check `refresh_status.reason` for error details
   - Verify there are discovered clusters to refresh (check `discovery_stats`)

4. **Update Failures**

   - Ensure `confirm_update: true` is set
   - Verify the config exists and the uid matches (if provided)
