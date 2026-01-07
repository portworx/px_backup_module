#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suspend/Resume Backup Schedules Tool

This script allows you to suspend or resume backup schedules in PX-Backup.
It can operate on:
- All available backup schedules
- Schedules associated with specific schedule policies
- Specific schedules by name
- Dry-run mode to report schedule status without making changes

The script includes all necessary functions to enumerate and update backup schedules
and filters them based on the provided criteria.

Key Features:
1. Suspend or resume all backup schedules
2. Filter by schedule policy names
3. Filter by exact schedule names
4. Dry-run mode to see current status without making changes
5. Validation of policy names and schedule names before execution
6. Detailed logging and reporting

Prerequisites:
- Ansible must be configured and accessible
- PX-Backup cluster credentials must be set up
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

import yaml

# Configure logging
timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
LOG_FILE = f"suspend_resume_schedules_{timestamp}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ]
)


def extract_json_from_console(cleaned_output):
    """
    Extracts JSON data from the Ansible output. First tries to read from a JSON file
    if file output is enabled, otherwise extracts from console output.

    Args:
        cleaned_output (str): The cleaned Ansible output (ANSI codes removed).

    Returns:
        dict: Parsed JSON data, or None if extraction fails.
    """
    # First try to find JSON file path if file output is enabled
    json_file_pattern = r"JSON file saved to:\s*(.+\.json)"
    json_file_match = re.search(json_file_pattern, cleaned_output)
    if json_file_match:
        json_file_path = json_file_match.group(1).strip()
        if os.path.exists(json_file_path):
            try:
                with open(json_file_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                logging.warning(f"Failed to parse JSON from file: {str(e)}")

    # Fall back to extracting from console output
    task_pattern = (
        r"TASK \[Display as JSON\][\s\S]*?"
        r"msg:\s*\|-?\s*\n([\s\S]*?)"
        r"(?=Read `vars_file`|Read vars_file|\nTASK \[|\nPLAY RECAP|\Z)"
    )
    task_match = re.search(task_pattern, cleaned_output)
    if task_match:
        raw_json_lines = task_match.group(1).split('\n')
        raw_json = '\n'.join(line.strip() for line in raw_json_lines if line.strip())
        try:
            return json.loads(raw_json)
        except json.JSONDecodeError as e:
            logging.warning(f"Failed to parse JSON from console output: {str(e)}")
    return None


def enumerate_backup_schedules(cluster_name: str = None, cluster_uid: str = None, org_id: str = "default") -> List[Dict[str, Any]]:
    """
    Enumerate backup schedules in PX-Backup using Ansible

    Args:
        cluster_name: Optional cluster name filter
        cluster_uid: Optional cluster UID filter
        org_id: Organization ID

    Returns:
        List of backup schedules as dictionaries
    """
    logging.info(f"Enumerating backup schedules for cluster: {cluster_name}")

    # Prepare extra vars for the Ansible command
    extra_vars = {
        "org_id": org_id,
        "enumerate_options": {}
    }

    if cluster_name:
        extra_vars["enumerate_options"]["cluster_name_filter"] = cluster_name

    if cluster_uid:
        extra_vars["enumerate_options"]["cluster_uid_filter"] = cluster_uid

    # Set backup_object_type to VirtualMachine to filter for VM schedules only
    extra_vars["enumerate_options"]["backup_object_type"] = "VirtualMachine"

    # Convert to JSON string
    extra_vars_json = json.dumps(extra_vars)

    # Run the Ansible command
    cmd = [
        "ansible-playbook", "examples/backup_schedule/enumerate.yaml", "-vvvv",
        "--extra-vars", extra_vars_json
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Ansible command completed with return code: {result.returncode}")

    if result.returncode != 0:
        logging.error(f"Failed to enumerate backup schedules")
        return []

    # Extract schedules from output
    stdout_text = result.stdout

    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', stdout_text)

    # Extract JSON from console output
    parsed_data = extract_json_from_console(cleaned_output)

    if parsed_data is None:
        logging.error("Could not extract JSON from Ansible output")
        return []

    return parsed_data.get("backup_schedules", [])


def update_schedules(matching_schedules, suspend=False):
    """
    Update backup schedules to suspend or resume them

    Args:
        matching_schedules: List of schedule dictionaries to update
        suspend: Boolean flag to suspend (True) or resume (False) schedules
    """
    logging.info("Updating backup schedules")
    for schedule in matching_schedules:
        backup_schedule_name = schedule["metadata"].get("name", "")

        vm_namespaces = schedule["backup_schedule_info"].get("namespaces", [])
        include_resources = schedule["backup_schedule_info"].get("include_resources", [])
        # print all the values extracted above
        logging.info(f"Updating schedule: {backup_schedule_name}")
        logging.info(f"  Namespaces: {vm_namespaces}")
        logging.info(f"  Include Resources: {include_resources}")

        # Extract and preserve the original volume_snapshot_class_mapping
        volume_snapshot_class_mapping = schedule["backup_schedule_info"].get("volume_snapshot_class_mapping", {})
        if volume_snapshot_class_mapping:
            logging.info(f"Preserving original volume_snapshot_class_mapping for schedule {backup_schedule_name}: {volume_snapshot_class_mapping}")
        else:
            logging.info(f"No volume_snapshot_class_mapping found in original schedule {backup_schedule_name}")

        # Define backup config - use the same format as the working version
        backup_object_type = {
            "type": "VM"
        }

        playbook_data = [{
            "name": "Update VM Backup Schedule",
            "hosts": "localhost",
            "gather_facts": False,
            "vars": {
                "backup_schedules": [{
                    "name": backup_schedule_name,
                    "suspend": suspend,
                    "volume_snapshot_class_mapping": volume_snapshot_class_mapping,
                    "backup_location_ref": schedule["backup_schedule_info"].get("backup_location_ref", {}),
                    "schedule_policy_ref": schedule["backup_schedule_info"].get("schedule_policy_ref", {}),
                    "cluster_ref": schedule["backup_schedule_info"].get("cluster_ref", {}),
                    "backup_type": "Normal",
                    "backup_object_type": backup_object_type,
                    "skip_vm_auto_exec_rules": True,
                    "labels": schedule["metadata"].get("labels", {}),
                }],
                "vm_namespaces": vm_namespaces,
                "include_resources": include_resources
            },
            "tasks": [
                {
                    "name": "Create Backup Schedule",
                    "include_tasks": "examples/backup_schedule/update_skip_vm_auto_exec.yaml"
                }
            ]
        }]

        # Save generated playbook
        timestamp = int(time.time())
        playbook_file = f"update_backup_{backup_schedule_name}_{timestamp}.yaml"
        with open(playbook_file, "w") as f:
            yaml.safe_dump(playbook_data, f, default_flow_style=False)

        logging.info(f"Updating backup schedule for {backup_schedule_name}")

        # Invoke the Ansible playbook
        combined_vars = json.dumps({
            "vm_namespaces": vm_namespaces,
            "include_resources": include_resources
        })

        ansible_cmd = [
            "ansible-playbook", playbook_file, "-vvvv",
            "--extra-vars", combined_vars
        ]

        result = subprocess.run(ansible_cmd, capture_output=True, text=True)
        stdout_text = result.stdout

        if result.returncode != 0:
            logging.error(f"Failed to update backup schedule for {backup_schedule_name}")
            logging.error(f"Ansible stdout: {stdout_text}")
            logging.error(f"Ansible stderr: {result.stderr}")
            return False, backup_schedule_name

        # Locate the "Create Backup Schedule" task output
        task_match = re.search(r"TASK \[Update Backup Schedule].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
        if not task_match:
            logging.error(f"Could not find 'Update Backup Schedule' task output.")
            return False, backup_schedule_name

        # Success
        logging.info(f"Updated backup schedule for - {backup_schedule_name}")
    return


def enumerate_schedule_policies(name_filter=None):
    """
    Enumerate schedule policies in PX-Backup using Ansible with improved error handling

    Args:
        name_filter (str, optional): Filter schedule policies by name

    Returns:
        list: List of matching schedule policies
    """
    logging.info(f"Enumerating schedule policies with filter: {name_filter}")

    # Prepare extra vars for the Ansible command
    extra_vars = {}
    if name_filter:
        extra_vars["name_filter"] = name_filter

    # Convert to JSON string
    extra_vars_json = json.dumps(extra_vars)

    # Run the Ansible command
    cmd = [
        "ansible-playbook", "examples/schedule_policy/enumerate.yaml", "-vvvv",
        "--extra-vars", extra_vars_json
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Ansible command completed with return code: {result.returncode}")

    if result.returncode != 0:
        logging.error(f"Failed to enumerate schedule policies")
        return []

    # Extract schedule policies from output
    stdout_text = result.stdout

    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', stdout_text)

    # Extract JSON from console output
    parsed_data = extract_json_from_console(cleaned_output)

    if parsed_data is None:
        logging.error("Could not extract JSON from Ansible output")
        return []

    return parsed_data.get('schedule_policies', [])


def filter_schedules_by_policy(schedules: List[Dict], policy_names: List[str]) -> List[Dict]:
    """
    Filter schedules by schedule policy names
    
    Args:
        schedules: List of backup schedule dictionaries
        policy_names: List of policy names to filter by
        
    Returns:
        List of schedules that match the specified policies
    """
    filtered_schedules = []
    
    for schedule in schedules:
        backup_info = schedule.get("backup_schedule_info", {})
        schedule_policy_ref = backup_info.get("schedule_policy_ref", {})
        policy_name = schedule_policy_ref.get("name", "")
        
        if policy_name in policy_names:
            filtered_schedules.append(schedule)
    
    return filtered_schedules


def filter_schedules_by_names(schedules: List[Dict], schedule_names: List[str]) -> List[Dict]:
    """
    Filter schedules by exact schedule names
    
    Args:
        schedules: List of backup schedule dictionaries
        schedule_names: List of schedule names to filter by
        
    Returns:
        List of schedules that match the specified names
    """
    filtered_schedules = []
    
    for schedule in schedules:
        metadata = schedule.get("metadata", {})
        schedule_name = metadata.get("name", "")
        
        if schedule_name in schedule_names:
            filtered_schedules.append(schedule)
    
    return filtered_schedules


def print_schedule_report(schedules: List[Dict], title: str):
    """
    Print a report of schedules with their status
    
    Args:
        schedules: List of backup schedule dictionaries
        title: Title for the report section
    """
    print(f"\n{title}")
    print("=" * len(title))
    
    if not schedules:
        print("No schedules found.")
        return
    
    for schedule in schedules:
        metadata = schedule.get("metadata", {})
        backup_info = schedule.get("backup_schedule_info", {})
        
        schedule_name = metadata.get("name", "Unknown")
        is_suspended = backup_info.get("suspend", False)
        status = "SUSPENDED" if is_suspended else "ACTIVE"
        
        # Get policy name
        schedule_policy_ref = backup_info.get("schedule_policy_ref", {})
        policy_name = schedule_policy_ref.get("name", "Unknown")
        
        # Get cluster name
        cluster_ref = backup_info.get("cluster_ref", {})
        cluster_name = cluster_ref.get("name", "Unknown")
        
        print(f"  {schedule_name:<50} | {status:<10} | Policy: {policy_name:<20} | Cluster: {cluster_name}")


def validate_schedule_policies(policy_names: List[str]) -> bool:
    """
    Validate that the specified schedule policies exist
    
    Args:
        policy_names: List of policy names to validate
        
    Returns:
        True if all policies exist, False otherwise
    """
    existing_policies = enumerate_schedule_policies()
    existing_policy_names = [policy.get("metadata", {}).get("name", "") for policy in existing_policies]
    
    missing_policies = [name for name in policy_names if name not in existing_policy_names]
    
    if missing_policies:
        logging.error(f"The following schedule policies do not exist: {missing_policies}")
        logging.info(f"Available policies: {existing_policy_names}")
        return False
    
    return True


def validate_schedule_names(schedule_names: List[str], all_schedules: List[Dict]) -> bool:
    """
    Validate that the specified schedule names exist
    
    Args:
        schedule_names: List of schedule names to validate
        all_schedules: List of all available schedules
        
    Returns:
        True if all schedule names exist, False otherwise
    """
    existing_schedule_names = [schedule.get("metadata", {}).get("name", "") for schedule in all_schedules]
    missing_schedules = [name for name in schedule_names if name not in existing_schedule_names]
    
    if missing_schedules:
        logging.error(f"The following schedules do not exist: {missing_schedules}")
        logging.info(f"Available schedules: {existing_schedule_names}")
        return False
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Suspend or resume backup schedules in PX-Backup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run to see all schedules and their status
  python suspend_resume_schedules.py --cluster-name my-cluster --cluster-uid abc123 --dry-run

  # Suspend all schedules
  python suspend_resume_schedules.py --cluster-name my-cluster --cluster-uid abc123 --action suspend

  # Resume all schedules
  python suspend_resume_schedules.py --cluster-name my-cluster --cluster-uid abc123 --action resume

  # Suspend schedules for specific policies
  python suspend_resume_schedules.py --cluster-name my-cluster --cluster-uid abc123 --action suspend --policies policy1,policy2

  # Resume specific schedules by name
  python suspend_resume_schedules.py --cluster-name my-cluster --cluster-uid abc123 --action resume --schedules schedule1,schedule2

  # Dry run for specific policies
  python suspend_resume_schedules.py --cluster-name my-cluster --cluster-uid abc123 --dry-run --policies policy1,policy2

Note: To get cluster name and UID, you can check your PX-Backup UI for cluster information
or use the PX-Backup CLI/API to list available clusters.
        """
    )
    
    parser.add_argument("--cluster-name", required=True, help="Name of the cluster")
    parser.add_argument("--cluster-uid", required=True, help="UID of the cluster")
    parser.add_argument("--action", choices=["suspend", "resume"], 
                       help="Action to perform: suspend or resume schedules (not required for dry-run)")
    parser.add_argument("--policies", help="Comma-separated list of schedule policy names to filter by")
    parser.add_argument("--schedules", help="Comma-separated list of exact schedule names to operate on")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Show schedule status without making any changes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate arguments
    if not args.dry_run and not args.action:
        parser.error("--action is required unless --dry-run is specified")
    
    if args.policies and args.schedules:
        parser.error("Cannot specify both --policies and --schedules. Choose one filtering method.")
    
    print(f"Logs are being captured at {LOG_FILE}")
    
    try:
        cluster_name = args.cluster_name
        cluster_uid = args.cluster_uid
        
        logging.info(f"Using cluster: {cluster_name} (UID: {cluster_uid})")
        
        # Get all backup schedules
        logging.info("Enumerating backup schedules...")
        all_schedules = enumerate_backup_schedules(cluster_name, cluster_uid)

        if not all_schedules:
            logging.warning("No backup schedules found for the specified cluster")
            print("No backup schedules found. This could mean:")
            print("  - The cluster has no VM backup schedules")
            print("  - The cluster name/UID is incorrect")
            print("  - There are connectivity issues with PX-Backup")
            return
        
        logging.info(f"Found {len(all_schedules)} total backup schedules")
        
        # Filter schedules based on arguments
        target_schedules = all_schedules
        filter_description = "all schedules"
        
        if args.policies:
            policy_names = [name.strip() for name in args.policies.split(",")]
            logging.info(f"Filtering by policies: {policy_names}")
            
            if not validate_schedule_policies(policy_names):
                return
            
            target_schedules = filter_schedules_by_policy(all_schedules, policy_names)
            filter_description = f"schedules with policies: {', '.join(policy_names)}"
            
        elif args.schedules:
            schedule_names = [name.strip() for name in args.schedules.split(",")]
            logging.info(f"Filtering by schedule names: {schedule_names}")
            
            if not validate_schedule_names(schedule_names, all_schedules):
                return
            
            target_schedules = filter_schedules_by_names(all_schedules, schedule_names)
            filter_description = f"schedules: {', '.join(schedule_names)}"
        
        logging.info(f"Found {len(target_schedules)} schedules matching criteria")
        
        if args.dry_run:
            # Dry run mode - just report status
            print_schedule_report(target_schedules, f"Schedule Status Report for {filter_description}")
            
            # Separate active and suspended schedules for summary
            active_schedules = [s for s in target_schedules if not s.get("backup_schedule_info", {}).get("suspend", False)]
            suspended_schedules = [s for s in target_schedules if s.get("backup_schedule_info", {}).get("suspend", False)]
            
            print(f"\nSummary:")
            print(f"  Total schedules: {len(target_schedules)}")
            print(f"  Active schedules: {len(active_schedules)}")
            print(f"  Suspended schedules: {len(suspended_schedules)}")
            
        else:
            # Perform the action
            action = args.action
            suspend_flag = (action == "suspend")
            action_verb = "Suspending" if suspend_flag else "Resuming"
            
            # Filter schedules that need the action
            if suspend_flag:
                # Only suspend active schedules
                schedules_to_update = [s for s in target_schedules if not s.get("backup_schedule_info", {}).get("suspend", False)]
            else:
                # Only resume suspended schedules
                schedules_to_update = [s for s in target_schedules if s.get("backup_schedule_info", {}).get("suspend", False)]
            
            if not schedules_to_update:
                status_word = "suspended" if suspend_flag else "active"
                logging.info(f"No schedules need to {action} - all matching schedules are already {status_word}")
                return
            
            logging.info(f"{action_verb} {len(schedules_to_update)} schedules...")
            
            # Print what will be updated
            print_schedule_report(schedules_to_update, f"Schedules to {action}")
            
            # Perform the update
            update_schedules(schedules_to_update, suspend=suspend_flag)
            
            logging.info(f"Successful {action} operation completed on {len(schedules_to_update)} schedules")
            
    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()