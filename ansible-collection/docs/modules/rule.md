# Rule Module

The rule module manages rules in PX-Backup, enabling management of pre-exec and post-exec rules.

## Synopsis

* Create and manage rules in PX-Backup
* Access control and ownership management
* Comprehensive rule inspection capabilities

## Requirements

* PX-Backup >= 2.8.3
* Stork >= 24.3.3
* Python >= 3.9
* The `requests` Python package

## Operations

The module supports the following operations:


| Operation        | Description                          |
| ------------------ | -------------------------------------- |
| CREATE           | Create a new rule        |
| UPDATE           | Modify existing rule     |
| DELETE           | Remove a rule            |
| INSPECT_ONE      | Get details of a specific rule |
| INSPECT_ALL      | List all rules           |
| UPDATE_OWNERSHIP | Update rule ownership settings |

## Parameters

### Common Parameters


| Parameter       | Type       | Required | Default | Description                                    | Choices                                    |
| ----------------- | ------------ | ---------- | --------- | ------------------------------------------------ | -------------------------------------------- |
| api_url         | string     | yes      |         | PX-Backup API URL                              |                                            |
| token           | string     | yes      |         | Authentication token                           |                                            |
| operation       | string     | yes      | CREATE  | Operation to perform                           |                                            |
| name            | string     | varies   |         | Name of the rule                               |                                            |
| org_id          | string     | yes      |         | Organization ID                                |                                            |
| uid             | string     | varies   |         | Unique identifier (required for update/delete) |                                            |
| owner           | string     | no       |         | Owner name                                     |                                            |
| rules           | list       | varies   |         | List of rules                                  |                                            |
| labels          | dictionary | no       |         | Label for the rule                             |                                            |
| validate_certs  | boolean    | no       | `true`  | Whether to validate SSL certificates           |                                            |

### Ownership Parameters


| Parameter                        | Type   | Required | Choices          | Description               |
| ---------------------------------- | -------- | ---------- | ------------------ | --------------------------- |
| ownership.owner                  | string | no       |                  | Owner of the rule   |
| ownership.groups[].id            | string | yes      |                  | Group identifier          |
| ownership.groups[].access        | string | yes      | Read/Write/Admin | Group access level        |
| ownership.collaborators[].id     | string | yes      |                  | Collaborator identifier   |
| ownership.collaborators[].access | string | yes      | Read/Write/Admin | Collaborator access level |
| ownership.public.type            | string | no       | Read/Write/Admin | Public access level       |

### Rules Parameters


| Parameter                        | Type   | Required | Choices          | Description               |
| ---------------------------------- | -------- | ---------- | ------------------ | --------------------------- |
| rules.pod_selector                   | dictionary | yes     |                  | Identify target pods   |
| rules.actions[].background           | string     | no      | true/false       | Indicates if the action runs in the background          |
| rules.actions[].run_in_single_pod    | string     | no      | true/false       | Indicates if the action is limited to a single pod        |
| rules.actions[].value                | string     | yes     |                  | Action to perform   |
| rules.container                      | string     | no      |                  | Container name where the action is applied|

## Error Handling

The module implements comprehensive error handling:

1. Parameter Validation

   - Required parameter checks
   - Format validation
   - Reference validation
2. Common Error Scenarios

   - Missing required configurations
   - Permission issues
   - Network connectivity problems
   - API errors

## Notes

1. **Security Considerations**

   - Access control configuration
   - Token security
   - SSL certificate validation
   - Secret key protection

2. **Best Practices**

   - Regular credential rotation
   - Minimal permission scope
   - Access control review
   - Audit logging
   - Encryption at rest
4. **Limitations**

   - Permission boundaries
   - Update constraints

## Troubleshooting

1. **Creation Issues**

   - Check permissions
   - Validate configurations
   - Ensure unique names
2. **Access Problems**

   - Verify ownership settings
   - Check group permissions
   - Validate token access
   - Review public access
3. **Update Failures**

   - Confirm rule exists
   - Check update permissions
   - Validate new configurations
   - Review ownership rights
4. **Common Solutions**

   - Check network connectivity
   - Verify SSL certificates
   - Review error messages
   - Check API endpoints
