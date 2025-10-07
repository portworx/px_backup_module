# Cloud Credential Module

The cloud credential module manages cloud provider credentials in PX-Backup, enabling secure storage and management of authentication details for various cloud platforms.

## Synopsis

* Create and manage cloud provider credentials in PX-Backup
* Support for multiple cloud providers (AWS, Azure, Google, IBM, Rancher)
* Secure credential storage and management
* Access control and ownership management
* Comprehensive credential inspection capabilities

## Requirements

* PX-Backup >= 2.9.0
* Stork >= 25.3.0
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation        | Description                          |
| ------------------ | -------------------------------------- |
| CREATE           | Create a new cloud credential        |
| UPDATE           | Modify existing cloud credential     |
| DELETE           | Remove a cloud credential            |
| INSPECT_ONE      | Get details of a specific credential |
| INSPECT_ALL      | List all cloud credentials           |
| UPDATE_OWNERSHIP | Update credential ownership settings |

## Parameters

### Common Parameters


| Parameter       | Type       | Required | Default | Description                  | Choices                                    |
| ----------------- | ------------ | ---------- | --------- | ------------------------------ | -------------------------------------------- |
| api_url         | string     | yes      |         | PX-Backup API URL            |                                            |
| token           | string     | yes      |         | Authentication token         |                                            |
| operation       | string     | yes      | CREATE  | Operation to perform         |                                            |
| name            | string     | varies   |         | Name of the cloud credential |                                            |
| org_id          | string     | yes      |         | Organization ID              |                                            |
| uid             | string     | varies   |         | Unique identifier            |                                            |
| owner           | string     | no       |         | Owner name                   |                                            |
| credential_type | string     | yes      |         | Cloud provider type          | `AWS`, `Azure`, `Google`, `IBM`, `Rancher` |
| aws_config      | dictionary | false    |         | aws config type              |                                            |
| azure_config    | dictionary | false    |         | azure config                 |                                            |
| ibm_config      | dictionary | false    |         | ibm config                   |                                            |
| google_config   | dictionary | false    |         | google config                |                                            |
| rancher_config  | dictionary | false    |         | rancher config               |                                            |

### SSL/TLS Configuration

All modules support comprehensive SSL/TLS certificate management. See [SSL Certificate Configuration](../common/ssl_configuration.md) for:

- SSL parameter reference
- Configuration examples
- Global SSL settings
- Troubleshooting guide
- Security best practices

### AWS Configuration


| Parameter             | Type   | Required | Description    |
| ----------------------- | -------- | ---------- | ---------------- |
| aws_config.access_key | string | yes      | AWS access key |
| aws_config.secret_key | string | yes      | AWS secret key |

### Azure Configuration


| Parameter                    | Type   | Required | Description           |
| ------------------------------ | -------- | ---------- | ----------------------- |
| azure_config.account_name    | string | yes      | Azure account name    |
| azure_config.account_key     | string | yes      | Azure account key     |
| azure_config.client_id       | string | yes      | Azure client ID       |
| azure_config.client_secret   | string | yes      | Azure client secret   |
| azure_config.tenant_id       | string | yes      | Azure tenant ID       |
| azure_config.subscription_id | string | yes      | Azure subscription ID |

### Google Configuration


| Parameter                | Type   | Required | Description                     |
| -------------------------- | -------- | ---------- | --------------------------------- |
| google_config.project_id | string | yes      | Google project ID               |
| google_config.json_key   | string | yes      | Google service account JSON key |

### IBM Configuration


| Parameter          | Type   | Required | Description       |
| -------------------- | -------- | ---------- | ------------------- |
| ibm_config.api_key | string | yes      | IBM Cloud API key |

### Rancher Configuration


| Parameter               | Type   | Required | Description                  |
| ------------------------- | -------- | ---------- | ------------------------------ |
| rancher_config.endpoint | string | yes      | Rancher API endpoint         |
| rancher_config.token    | string | yes      | Rancher authentication token |

### Ownership Parameters


| Parameter                        | Type   | Required | Choices          | Description               |
| ---------------------------------- | -------- | ---------- | ------------------ | --------------------------- |
| ownership.owner                  | string | no       |                  | Owner of the credential   |
| ownership.groups[].id            | string | yes      |                  | Group identifier          |
| ownership.groups[].access        | string | yes      | Read/Write/Admin | Group access level        |
| ownership.collaborators[].id     | string | yes      |                  | Collaborator identifier   |
| ownership.collaborators[].access | string | yes      | Read/Write/Admin | Collaborator access level |
| ownership.public.type            | string | no       | Read/Write/Admin | Public access level       |

## Error Handling

The module implements comprehensive error handling:

1. Parameter Validation

   - Required parameter checks
   - Credential type validation
   - Format validation
   - Reference validation
2. Common Error Scenarios

   - Invalid credentials
   - Missing required configurations
   - Permission issues
   - Network connectivity problems
   - API errors

## Notes

1. **Security Considerations**

   - Secure credential storage
   - Access control configuration
   - Token security
   - SSL certificate validation
   - Secret key protection
2. **Cloud Provider Requirements**

   - Provider-specific configurations
   - Authentication methods
   - Required permissions
   - Access scope considerations
3. **Best Practices**

   - Regular credential rotation
   - Minimal permission scope
   - Access control review
   - Audit logging
   - Encryption at rest
4. **Limitations**

   - Provider-specific restrictions
   - Permission boundaries
   - Update constraints
   - Credential validation

## Troubleshooting

1. **Creation Issues**

   - Verify credentials are correct
   - Check permissions
   - Validate configurations
   - Ensure unique names
2. **Access Problems**

   - Verify ownership settings
   - Check group permissions
   - Validate token access
   - Review public access
3. **Update Failures**

   - Confirm credential exists
   - Check update permissions
   - Validate new configurations
   - Review ownership rights
4. **Common Solutions**

   - Validate credentials
   - Check network connectivity
   - Verify SSL certificates
   - Review error messages
   - Check API endpoints
