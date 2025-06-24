#!/usr/bin/python

"""
Ansible Module: PX-Backup Output Formatter
A reusable module for formatting and displaying PX-Backup API responses
"""

from ansible.module_utils.basic import AnsibleModule
import json
import csv
import io
from datetime import datetime

DOCUMENTATION = '''
---
module: output_formatter
short_description: Format and display PX-Backup API responses
description:
  - Formats PX-Backup API responses in multiple output formats (YAML, JSON, CSV)
  - Supports both display and file output modes
  - Provides consistent formatting across all PX-Backup modules
version_added: "2.9.1"

options:
  data:
    description: The data to format (usually from a PX-Backup module result)
    required: true
    type: dict
  
  format:
    description: Output format
    required: false
    type: str
    choices: ['yaml', 'json', 'csv']
    default: 'yaml'
  
  mode:
    description: Output mode - display to screen or save to file
    required: false
    type: str
    choices: ['display', 'file']
    default: 'display'
  
  file_prefix:
    description: Prefix for output files (when mode=file)
    required: false
    type: str
    default: 'px_backup_output'
  
  resource_type:
    description: Type of resource being formatted (for better display)
    required: false
    type: str
    default: 'resource'
  
  fields:
    description: Specific fields to include in output (for CSV)
    required: false
    type: list
    elements: str
  
  include_metadata:
    description: Include generation metadata in output
    required: false
    type: bool
    default: true
'''

EXAMPLES = '''
# Format backup locations as YAML and display
- name: Format backup locations
  output_formatter:
    data: "{{ backup_location_result }}"
    format: yaml
    mode: display
    resource_type: "backup_locations"

# Save backup data as JSON file
- name: Save backup data
  output_formatter:
    data: "{{ backup_result }}"
    format: json
    mode: file
    file_prefix: "backup_data"
    resource_type: "backups"

# Create CSV export with specific fields
- name: Export to CSV
  output_formatter:
    data: "{{ cluster_result }}"
    format: csv
    mode: file
    resource_type: "clusters"
    fields: ['name', 'uid', 'status']
'''

RETURN = '''
formatted_output:
    description: The formatted output content
    type: str
    returned: when mode=display
output_file:
    description: Path to created output file
    type: str
    returned: when mode=file
summary:
    description: Summary information about the formatting operation
    type: dict
    returned: always
'''

class OutputFormatter:
    """Main output formatter class"""
    
    def __init__(self, module):
        self.module = module
        self.params = module.params
        
    def get_resource_list(self, data):
        """Extract the list of resources from data based on resource_type"""
        resource_type = self.params['resource_type']
        
        # Common patterns for resource lists
        patterns = [
            f"{resource_type}",           # exact match
            f"{resource_type}s",          # plural
            resource_type.rstrip('s'),    # singular
            "items",                      # generic
            "data",                       # generic
            "results"                     # generic
        ]
        
        for pattern in patterns:
            if pattern in data:
                return data[pattern]
        
        # If no pattern matches, return the data as-is if it's a list
        if isinstance(data, list):
            return data
        
        # Last resort: return empty list
        return []
    
    def format_yaml_simple(self, data):
        """Format data as simple YAML without PyYAML dependency"""
        resources = self.get_resource_list(data)
        
        lines = []
        if self.params['include_metadata']:
            lines.append(f"# Generated: {datetime.utcnow().isoformat()}Z")
            lines.append(f"# Resource Type: {self.params['resource_type']}")
            lines.append(f"# Total Count: {len(resources) if isinstance(resources, list) else 1}")
            lines.append("")
        
        lines.append(f"{self.params['resource_type']}:")
        
        if isinstance(resources, list):
            for item in resources:
                lines.append("  -")  # Start of list item
                lines.extend(self._dict_to_yaml_lines(item, indent=4))
        else:
            lines.extend(self._dict_to_yaml_lines(resources, indent=2))
        
        return '\n'.join(lines)
    
    def _dict_to_yaml_lines(self, data, indent=0):
        """Convert dict to YAML-like format without PyYAML"""
        lines = []
        spaces = ' ' * indent
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict):
                    lines.append(f"{spaces}{key}:")
                    lines.extend(self._dict_to_yaml_lines(value, indent + 2))
                elif isinstance(value, list):
                    lines.append(f"{spaces}{key}:")
                    for item in value:
                        if isinstance(item, dict):
                            lines.append(f"{spaces}  -")
                            lines.extend(self._dict_to_yaml_lines(item, indent + 4))
                        else:
                            lines.append(f"{spaces}  - {self._format_value(item)}")
                else:
                    lines.append(f"{spaces}{key}: {self._format_value(value)}")
        
        return lines
    
    def _format_value(self, value):
        """Format a value for YAML output"""
        if isinstance(value, str):
            # Quote strings that contain special characters
            if any(char in value for char in ['"', "'", ':', '\n', '\r']):
                return f'"{value.replace(chr(34), chr(92) + chr(34))}"'
            return f'"{value}"'
        elif value is None:
            return 'null'
        elif isinstance(value, bool):
            return 'true' if value else 'false'
        else:
            return str(value)
    
    def format_json(self, data):
        """Format data as JSON"""
        resources = self.get_resource_list(data)
        
        output = {}
        if self.params['include_metadata']:
            output['generated'] = datetime.utcnow().isoformat() + 'Z'
            output['total_count'] = len(resources) if isinstance(resources, list) else 1
            output['resource_type'] = self.params['resource_type']
        
        output[self.params['resource_type']] = resources
        
        return json.dumps(output, indent=2, sort_keys=False)
    
    def format_csv(self, data):
        """Format data as CSV"""
        resources = self.get_resource_list(data)
        
        if not resources or not isinstance(resources, list):
            return "No data available for CSV format"
        
        # Get fields to include
        fields = self.params.get('fields', [])
        if not fields:
            # Auto-detect fields from first resource
            if resources and isinstance(resources[0], dict):
                fields = self._get_csv_fields(resources[0])
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(fields)
        
        # Write data rows
        for resource in resources:
            if isinstance(resource, dict):
                row = []
                for field in fields:
                    value = self._get_nested_value(resource, field)
                    row.append(str(value) if value is not None else '')
                writer.writerow(row)
        
        return output.getvalue()
    
    def _get_csv_fields(self, resource):
        """Auto-detect CSV fields from a resource"""
        fields = []
        
        # Check for metadata fields first
        if 'metadata' in resource and isinstance(resource['metadata'], dict):
            for key in ['name', 'uid']:
                if key in resource['metadata']:
                    fields.append(f"metadata.{key}")
        
        # Check for common info fields
        info_keys = [k for k in resource.keys() if k.endswith('_info')]
        for info_key in info_keys:
            if isinstance(resource[info_key], dict):
                for key in ['type', 'status']:
                    if key in resource[info_key]:
                        fields.append(f"{info_key}.{key}")
                
                # Check for nested status
                if 'status' in resource[info_key] and isinstance(resource[info_key]['status'], dict):
                    if 'status' in resource[info_key]['status']:
                        fields.append(f"{info_key}.status.status")
        
        return fields[:10]  # Limit to 10 fields for readability
    
    def _get_nested_value(self, data, field_path):
        """Get value from nested dict using dot notation"""
        keys = field_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    def get_timestamp(self):
        """Get timestamp for file naming"""
        return datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    def save_to_file(self, content, format_type):
        """Save content to file"""
        timestamp = self.get_timestamp()
        filename = f"{self.params['file_prefix']}_{timestamp}.{format_type}"
        
        try:
            with open(filename, 'w') as f:
                f.write(content)
            return filename
        except Exception as e:
            self.module.fail_json(msg=f"Failed to save file {filename}: {str(e)}")
    
    def run(self):
        """Main execution method"""
        data = self.params['data']
        format_type = self.params['format']
        mode = self.params['mode']
        
        # Format the data
        if format_type == 'yaml':
            formatted_content = self.format_yaml_simple(data)
        elif format_type == 'json':
            formatted_content = self.format_json(data)
        elif format_type == 'csv':
            formatted_content = self.format_csv(data)
        else:
            self.module.fail_json(msg=f"Unsupported format: {format_type}")
        
        # Prepare result
        result = {
            'changed': False,
            'summary': {
                'format': format_type,
                'mode': mode,
                'resource_type': self.params['resource_type'],
                'total_items': len(self.get_resource_list(data))
            }
        }
        
        if mode == 'display':
            result['formatted_output'] = formatted_content
        elif mode == 'file':
            filename = self.save_to_file(formatted_content, format_type)
            result['output_file'] = filename
            result['summary']['file_created'] = filename
        
        return result

def main():
    """Main module function"""
    module_args = dict(
        data=dict(type='dict', required=True),
        format=dict(type='str', choices=['yaml', 'json', 'csv'], default='yaml'),
        mode=dict(type='str', choices=['display', 'file'], default='display'),
        file_prefix=dict(type='str', default='px_backup_output'),
        resource_type=dict(type='str', default='resource'),
        fields=dict(type='list', elements='str', required=False),
        include_metadata=dict(type='bool', default=True)
    )
    
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    
    formatter = OutputFormatter(module)
    result = formatter.run()
    
    module.exit_json(**result)

if __name__ == '__main__':
    main()