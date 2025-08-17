# SSL Certificate Configuration

All PX-Backup modules support comprehensive SSL/TLS certificate management for secure communication with PX-Backup API servers.

## 📋 Parameters

### 🔧 PX-Backup API SSL Parameters

| Parameter                  | Type    | Required | Default | Description                                                                                                    |
|----------------------------|---------|----------|---------|----------------------------------------------------------------------------------------------------------------|
| `px_backup_validate_certs` | boolean | no       | `true`  | Enable SSL certificate validation for PX-Backup API. Set to `false` only for development                     |
| `px_backup_ca_cert`        | path    | no       | -       | Path to custom CA certificate file for validating PX-Backup API server certificates                          |
| `px_backup_client_cert`    | path    | no       | -       | Path to client certificate file for mutual TLS authentication with PX-Backup API                             |
| `px_backup_client_key`     | path    | no       | -       | Path to client private key file for PX-Backup API. Required if `px_backup_client_cert` is provided           |

### 🔐 PXCentral Auth SSL Parameters

| Parameter                   | Type    | Required | Default | Description                                                                                                    |
|-----------------------------|---------|----------|---------|----------------------------------------------------------------------------------------------------------------|
| `pxcentral_validate_certs`      | boolean | no       | `true`  | Enable SSL certificate validation for PXCentral Auth. Set to `false` only for development                    |
| `pxcentral_ca_cert`         | path    | no       | -       | Path to custom CA certificate file for validating PXCentral Auth server certificates                         |
| `pxcentral_client_cert`     | path    | no       | -       | Path to client certificate file for mutual TLS authentication with PXCentral Auth                            |
| `pxcentral_client_key`      | path    | no       | -       | Path to client private key file for PXCentral Auth. Required if `pxcentral_client_cert` is provided          |

## 🔧 SSL Configuration Combinations

### 🔧 PX-Backup API SSL Combinations

| Configuration Type | Parameters | Use Case |
|-------------------|------------|----------|
| **Default Validation** | `px_backup_validate_certs: true` | Uses system's trusted CA certificates |
| **Custom CA Validation** | `px_backup_validate_certs: true` + `px_backup_ca_cert` | Validates against your private CA |
| **Mutual TLS** | `px_backup_client_cert` + `px_backup_client_key` | Provides client authentication to server |
| **No Validation** | `px_backup_validate_certs: false` | ⚠️ Disables validation (development only!) |

### 🔐 PXCentral Auth SSL Combinations

| Configuration Type | Parameters | Use Case |
|-------------------|------------|----------|
| **Default Validation** | `pxcentral_validate_certs: true` | Uses system's trusted CA certificates |
| **Custom CA Validation** | `pxcentral_validate_certs: true` + `pxcentral_ca_cert` | Validates against your private CA |
| **Mutual TLS** | `pxcentral_client_cert` + `pxcentral_client_key` | Provides client authentication to auth server |
| **No Validation** | `pxcentral_validate_certs: false` | ⚠️ Disables validation (development only!) |

## ⚠️ Important Notes

### 🔧 PX-Backup API SSL Notes
- **`px_backup_ca_cert`** is for validating the **PX-Backup API server's** certificate
- **`px_backup_client_cert`/`px_backup_client_key`** are for authenticating **YOUR CLIENT** to the PX-Backup API
- Both `px_backup_client_cert` and `px_backup_client_key` must be provided together for mutual TLS

### 🔐 PXCentral Auth SSL Notes
- **`pxcentral_ca_cert`** is for validating the **PXCentral Auth server's** certificate
- **`pxcentral_client_cert`/`pxcentral_client_key`** are for authenticating **YOUR CLIENT** to the PXCentral Auth server
- Both `pxcentral_client_cert` and `pxcentral_client_key` must be provided together for mutual TLS

### 🚨 General SSL Notes
- These configurations are **independent**: you can have custom CA validation without mutual TLS, or vice versa
- Setting `*_validate_certs: false` or `*_verify_ssl: false` disables **ALL** server certificate validation (insecure!)
- **PX-Backup API SSL** is used for all backup operations (backup, restore, schedule, etc.)
- **PXCentral Auth SSL** is used only for authentication when obtaining tokens

## 🌐 Global Configuration (Recommended)

Configure SSL settings globally in your inventory. There are **two separate SSL configurations** for different services:

### 🔧 PX-Backup API SSL Configuration

```yaml
# inventory/group_vars/common/all.yaml

# SSL Certificate Configuration for PX-Backup API (backup operations)
px_backup_validate_certs: true                      # Enable/disable SSL certificate validation
# px_backup_ca_cert: "/path/to/ca-cert.pem"         # Custom CA certificate file
# px_backup_client_cert: "/path/to/client-cert.pem" # Client certificate for mutual TLS
# px_backup_client_key: "/path/to/client-key.pem"   # Client private key for mutual TLS
```

### 🔐 PXCentral Auth SSL Configuration

```yaml
# SSL Certificate Configuration for PXCentral Auth (authentication)
pxcentral_validate_certs: true                          # Enable/disable SSL certificate validation for auth
# pxcentral_ca_cert: "/path/to/pxcentral-ca-cert.pem"     # Custom CA certificate for auth server
# pxcentral_client_cert: "/path/to/pxcentral-client-cert.pem" # Client certificate for auth mutual TLS
# pxcentral_client_key: "/path/to/pxcentral-client-key.pem"   # Client private key for auth mutual TLS
```

> **✅ Best Practice**: All playbooks will automatically use these settings, ensuring consistent SSL configuration across your entire deployment.

> **ℹ️ Note**:
> - **PX-Backup API SSL** is used for all backup operations (backup, restore, schedule, etc.)
> - **PXCentral Auth SSL** is used only for authentication when obtaining tokens

## 📚 Configuration Examples

### 🔒 Using System CA Certificates (Default)

```yaml
- name: Create backup with system CAs (both services use system CAs)
  backup:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
    # PX-Backup API uses system CAs (default)
    validate_certs: true  # or omit, as true is default
    # ... other parameters
```

### 🌐 Complete SSL Configuration Example

```yaml
# inventory/group_vars/common/all.yaml
# Complete SSL configuration for both services

# PX-Backup API SSL Configuration
px_backup_validate_certs: true
px_backup_ca_cert: "/etc/ssl/certs/px-backup-ca.pem"
px_backup_client_cert: "/etc/ssl/certs/px-backup-client.pem"
px_backup_client_key: "/etc/ssl/private/px-backup-client-key.pem"

# PXCentral Auth SSL Configuration
pxcentral_validate_certs: true
pxcentral_ca_cert: "/etc/ssl/certs/pxcentral-ca.pem"
pxcentral_client_cert: "/etc/ssl/certs/pxcentral-client.pem"
pxcentral_client_key: "/etc/ssl/private/pxcentral-client-key.pem"
```

### 🏢 Using Custom CA Certificate

```yaml
- name: Create backup with custom CA
  backup:
    operation: CREATE
    api_url: "https://px-backup.example.com"
    token: "{{ px_backup_token }}"
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
    validate_certs: false  # Only for development!
    # ... other parameters
```

> **⚠️ Warning**: Only use `validate_certs: false` in development environments. Never disable SSL validation in production!

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
