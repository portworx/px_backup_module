# SSL Certificate Configuration

All PX-Backup modules support comprehensive SSL/TLS certificate management for secure communication with PX-Backup API servers and PXCentral authentication.

## 📋 SSL Configuration Structure

SSL configuration is now organized under a single `ssl_config` variable with separate sections for different services:

```yaml
ssl_config:
  # SSL Certificate Configuration (optional)
  # Uncomment and set these if you need custom SSL certificates for PX-Backup API
  px_backup:
    validate_certs: false                    # Enable/disable SSL certificate validation
    ca_cert: "{{ playbook_dir | dirname | dirname }}/certs/new/invalid.pem"         # Custom CA certificate file
    # ca_cert: "{{ playbook_dir | dirname | dirname }}/certs/new/appspwx-ocp-56-241pwxpurestoragecom_include_chain.pem"         # Custom CA certificate file
    # client_cert: "/path/to/client-cert.pem" # Client certificate for mutual TLS
    # client_key: "/path/to/client-key.pem"   # Client private key for mutual TLS

  # SSL Certificate Configuration for PXCentral Auth (optional)
  # Use these if PXCentral auth server requires custom SSL certificates
  pxcentral:
    validate_certs: false
    ca_cert: "{{ playbook_dir | dirname | dirname }}/certs/new/invalid.pem"         # Custom CA certificate file
    # ca_cert: "{{ playbook_dir | dirname | dirname }}/certs/new/appspwx-ocp-56-241pwxpurestoragecom_include_chain.pem"
    # client_cert: "/path/to/pxcentral-client-cert.pem"
    # client_key: "/path/to/pxcentral-client-key.pem"
```

## 📋 SSL Configuration Parameters

### 🔧 PX-Backup API SSL Parameters (`ssl_config.px_backup`)


| Parameter        | Type    | Required | Default | Description                                                                             |
| ------------------ | --------- | ---------- | --------- | ----------------------------------------------------------------------------------------- |
| `validate_certs` | boolean | no       | `true`  | Enable SSL certificate validation for PX-Backup API. Set to`false` only for development |
| `ca_cert`        | path    | no       | -       | Path to custom CA certificate file for validating PX-Backup API server certificates     |
| `client_cert`    | path    | no       | -       | Path to client certificate file for mutual TLS authentication with PX-Backup API        |
| `client_key`     | path    | no       | -       | Path to client private key file for PX-Backup API. Required if`client_cert` is provided |

### 🔐 PXCentral Auth SSL Parameters (`ssl_config.pxcentral`)


| Parameter        | Type    | Required | Default | Description                                                                              |
| ------------------ | --------- | ---------- | --------- | ------------------------------------------------------------------------------------------ |
| `validate_certs` | boolean | no       | `true`  | Enable SSL certificate validation for PXCentral Auth. Set to`false` only for development |
| `ca_cert`        | path    | no       | -       | Path to custom CA certificate file for validating PXCentral Auth server certificates     |
| `client_cert`    | path    | no       | -       | Path to client certificate file for mutual TLS authentication with PXCentral Auth        |
| `client_key`     | path    | no       | -       | Path to client private key file for PXCentral Auth. Required if`client_cert` is provided |

## 🔧 Configuration Examples

### Basic SSL Configuration

```yaml
# Disable SSL verification (development only)
ssl_config:
  px_backup:
    validate_certs: false
  pxcentral:
    validate_certs: false
```

### Custom CA Certificate

```yaml
# Use custom CA certificate for both services
ssl_config:
  px_backup:
    validate_certs: true
    ca_cert: "/etc/ssl/certs/custom-ca.pem"
  pxcentral:
    validate_certs: true
    ca_cert: "/etc/ssl/certs/custom-ca.pem"
```

### Mutual TLS Authentication

```yaml
# Full mutual TLS setup
ssl_config:
  px_backup:
    validate_certs: true
    ca_cert: "/etc/ssl/certs/custom-ca.pem"
    client_cert: "/etc/ssl/certs/px-backup-client.pem"
    client_key: "/etc/ssl/private/px-backup-client.key"
  pxcentral:
    validate_certs: true
    ca_cert: "/etc/ssl/certs/custom-ca.pem"
    client_cert: "/etc/ssl/certs/pxcentral-client.pem"
    client_key: "/etc/ssl/private/pxcentral-client.key"
```

## 🔧 SSL Configuration Combinations

### 🔧 PX-Backup API SSL Combinations


| Configuration Type       | Parameters                                                                   | Use Case                                     |
| -------------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------- |
| **Default Validation**   | `ssl_config.px_backup.validate_certs: true`                                  | Uses system's trusted CA certificates        |
| **Custom CA Validation** | `ssl_config.px_backup.validate_certs: true` + `ssl_config.px_backup.ca_cert` | Validates against your private CA            |
| **Mutual TLS**           | `ssl_config.px_backup.client_cert` + `ssl_config.px_backup.client_key`       | Provides client authentication to server     |
| **No Validation**        | `ssl_config.px_backup.validate_certs: false`                                 | ⚠️ Disables validation (development only!) |

### 🔐 PXCentral Auth SSL Combinations


| Configuration Type       | Parameters                                                                   | Use Case                                      |
| -------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------- |
| **Default Validation**   | `ssl_config.pxcentral.validate_certs: true`                                  | Uses system's trusted CA certificates         |
| **Custom CA Validation** | `ssl_config.pxcentral.validate_certs: true` + `ssl_config.pxcentral.ca_cert` | Validates against your private CA             |
| **Mutual TLS**           | `ssl_config.pxcentral.client_cert` + `ssl_config.pxcentral.client_key`       | Provides client authentication to auth server |
| **No Validation**        | `ssl_config.pxcentral.validate_certs: false`                                 | ⚠️ Disables validation (development only!)  |

## ⚠️ Important Notes

### 🔧 PX-Backup API SSL Notes

- **`ssl_config.px_backup.ca_cert`** is for validating the **PX-Backup API server's** certificate
- **`ssl_config.px_backup.client_cert`/`ssl_config.px_backup.client_key`** are for authenticating **YOUR CLIENT** to the PX-Backup API
- Both `ssl_config.px_backup.client_cert` and `ssl_config.px_backup.client_key` must be provided together for mutual TLS

### 🔐 PXCentral Auth SSL Notes

- **`ssl_config.pxcentral.ca_cert`** is for validating the **PXCentral Auth server's** certificate
- **`ssl_config.pxcentral.client_cert`/`ssl_config.pxcentral.client_key`** are for authenticating **YOUR CLIENT** to the PXCentral Auth server
- Both `ssl_config.pxcentral.client_cert` and `ssl_config.pxcentral.client_key` must be provided together for mutual TLS

### 🚨 General SSL Notes

- These configurations are **independent**: you can have custom CA validation without mutual TLS, or vice versa
- Setting `ssl_config.*.validate_certs: false` disables **ALL** server certificate validation (insecure!)
- **PX-Backup API SSL** is used for all backup operations (backup, restore, schedule, etc.)
- **PXCentral Auth SSL** is used only for authentication when obtaining tokens

## 🌐 Global Configuration (Recommended)

Configure SSL settings globally in your inventory using the new `ssl_config` structure:

```yaml
# inventory/group_vars/common/all.yaml

# SSL Certificate Configuration
ssl_config:
  # SSL Certificate Configuration (optional)
  # Uncomment and set these if you need custom SSL certificates for PX-Backup API
  px_backup:
    validate_certs: false                    # Enable/disable SSL certificate validation
    ca_cert: "{{ playbook_dir | dirname | dirname }}/certs/new/invalid.pem"         # Custom CA certificate file
    # ca_cert: "{{ playbook_dir | dirname | dirname }}/certs/new/appspwx-ocp-56-241pwxpurestoragecom_include_chain.pem"         # Custom CA certificate file
    # client_cert: "/path/to/client-cert.pem" # Client certificate for mutual TLS
    # client_key: "/path/to/client-key.pem"   # Client private key for mutual TLS

  # SSL Certificate Configuration for PXCentral Auth (optional)
  # Use these if PXCentral auth server requires custom SSL certificates
  pxcentral:
    validate_certs: false
    ca_cert: "{{ playbook_dir | dirname | dirname }}/certs/new/invalid.pem"         # Custom CA certificate file
    # ca_cert: "{{ playbook_dir | dirname | dirname }}/certs/new/appspwx-ocp-56-241pwxpurestoragecom_include_chain.pem"
    # client_cert: "/path/to/pxcentral-client-cert.pem"
    # client_key: "/path/to/pxcentral-client-key.pem"
```

> **✅ Best Practice**: All playbooks will automatically use these settings, ensuring consistent SSL configuration across your entire deployment.

> **ℹ️ Note**:
>
> - **PX-Backup API SSL** is used for all backup operations (backup, restore, schedule, etc.)
> - **PXCentral Auth SSL** is used only for authentication when obtaining tokens

## 📚 Usage in Playbooks

### 🔒 Using SSL Config in Auth Module

```yaml
- name: Get authentication token with SSL config
  auth:
    auth_url: "{{ pxcentral_auth_url }}"
    client_id: "{{ pxcentral_client_id }}"
    username: "{{ pxcentral_username }}"
    password: "{{ pxcentral_password }}"
    ssl_config: "{{ ssl_config.pxcentral | default({}) }}"
  register: auth_result
```

### 🌐 Using SSL Config in Backup Operations

```yaml
- name: Create backup with SSL config
  backup:
    operation: CREATE
    api_url: "{{ px_backup_api_url }}"
    token: "{{ px_backup_token }}"
    ssl_config: "{{ ssl_config.px_backup | default({}) }}"
    # ... other parameters
### 🏢 Using Custom CA Certificate

```yaml
- name: Create backup with custom CA
  backup:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    ssl_config:
      validate_certs: true
      ca_cert: "/etc/ssl/certs/company-ca.pem"
    # ... other parameters
```

### 🔐 Using Mutual TLS

```yaml
- name: Create backup with mutual TLS
  backup:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    ssl_config:
      validate_certs: true
      ca_cert: "/etc/ssl/certs/company-ca.pem"
      client_cert: "/etc/ssl/certs/client.pem"
      client_key: "/etc/ssl/private/client-key.pem"
    # ... other parameters
```

### ⚠️ Development with Self-Signed Certificates

```yaml
- name: Create backup without SSL validation (dev only)
  backup:
    operation: CREATE
    api_url: "https://px-backup-dev.example.com"
    token: "{{ px_backup_token }}"
    ssl_config:
      validate_certs: false  # Only for development!
    # ... other parameters
```

> **⚠️ Warning**: Only use `ssl_config.validate_certs: false` in development environments. Never disable SSL validation in production!

## 🔧 Troubleshooting SSL Issues

### 🚨 Certificate Validation Errors

- Verify certificate file paths and permissions
- Check certificate validity and expiration
- Ensure CA certificate matches server certificate chain

### 🔑 Mutual TLS Authentication Failures

- Validate client certificate and private key pairing
- Ensure client certificate is trusted by the server
- Check certificate format (must be PEM format)

### 📁 Permission Issues

- Certificate files must be readable by the user running the playbook
- Private key files should have restricted permissions (e.g., `600`)

### 📄 Format Issues

- All certificates must be in PEM format
- Convert other formats using OpenSSL if needed

## 🛡️ Security Best Practices

### 🏭 Production Environments

- ✅ Always use `validate_certs: true`
- ✅ Use proper CA-signed certificates
- ✅ Store certificates securely
- ✅ Use Ansible Vault for sensitive paths

### 📋 Certificate Management

- 🔄 Rotate certificates before expiration
- 🏷️ Use separate certificates for different environments
- ⏰ Monitor certificate expiration dates
- 📦 Implement proper certificate distribution

### 🔐 Private Key Security

- ❌ Never commit private keys to version control
- 🔒 Use appropriate file permissions (`600` or `400`)
- 🏦 Consider using external secret management systems
- 🔐 Encrypt private keys at rest when possible

---

> **💡 Pro Tip**: Use Ansible Vault to encrypt certificate paths and sensitive configuration data:
>
> ```bash
> ansible-vault encrypt group_vars/common/all.yaml
> ```
