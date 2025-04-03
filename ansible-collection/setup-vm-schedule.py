#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VM Backup Schedule Management Tool

This script automates the creation of backup schedules for KubeVirt VMs in PX-Backup.
It allows users to specify time series for schedule policies and distributes VMs across them.
"""

# Standard library imports
import argparse
import base64
import json
import logging
import math
import os
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime, timedelta

# Third-party imports
import yaml
from kubernetes import client, config

# Set up logging
LOG_FILE = "setup-vm-schedule.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ]
)


def generate_report(args, results=None, error=None, policy_result=None, vm_map=None):
    """
    Generate a report of the script execution
    
    Args:
        args: Command line arguments
        results: Results of backup schedule creation
        error: Error message if any
        policy_result: Results of policy creation
        vm_map: Dictionary mapping namespaces to lists of VM names
    
    Returns:
        str: Report content
    """
    report = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Title with timestamp
    report.append("=" * 80)
    report.append(f"VM BACKUP SCHEDULE EXECUTION REPORT - {timestamp}")
    report.append("=" * 80)
    
    # Command line arguments
    report.append("COMMAND LINE ARGUMENTS:")
    report.append(f"  Cluster: {args.cluster_name}")
    report.append(f"  Backup Location: {args.backup_location}")
    report.append(f"  Time Series: {args.time_series}")
    report.append(f"  Namespaces: {args.namespaces if args.namespaces else 'All namespaces'}")
    report.append(f"  Dry Run: {args.dry_run}")
    report.append("")
    
    # Policy information
    if policy_result:
        report.append("SCHEDULE POLICY INFORMATION:")
        if policy_result['status'] == 'error':
            report.append(f"  Status: ERROR - {policy_result['message']}")
            report.append("")
            report.append("  Existing Policies:")
            for policy_name in policy_result.get('existing_policies', []):
                report.append(f"    - {policy_name}")
            
            report.append("")
            report.append("  Requested Policies:")
            for policy_name in policy_result.get('all_policy_names', []):
                report.append(f"    - {policy_name}")
                
            # Add cleanup instructions
            if 'cleanup_help' in policy_result:
                report.append("")
                report.append("  CLEANUP INSTRUCTIONS:")
                report.append("  " + policy_result['cleanup_help'].replace("\n", "\n  "))
        else:
            report.append(f"  Status: Success")
            report.append("")
            report.append("  Created Policies:")
            for policy_name, policy_uid in policy_result.get('policies', []):
                report.append(f"    - {policy_name} (UID: {policy_uid})")
        report.append("")
    
    # VM inventory information
    if vm_map:
        report.append("VM INVENTORY:")
        total_vms = sum(len(vms) for vms in vm_map.values())
        report.append(f"  Total VMs Found: {total_vms}")
        report.append(f"  Total Namespaces with VMs: {len(vm_map)}")
        report.append("")
        
        # Detailed VM list by namespace with comma-separated VM names
        for namespace, vms in sorted(vm_map.items()):
            report.append(f"  Namespace: {namespace}")
            report.append(f"    VM Count: {len(vms)}")
            vm_list = ", ".join(sorted(vms))
            report.append(f"    VMs: {vm_list}")
            report.append("")
    
    # Results of backup schedule creation
    if results:
        report.append("BACKUP SCHEDULE RESULTS:")
        report.append(f"  Total VMs Processed: {results['total_vms']}")
        report.append(f"  Total Policies Used: {results['total_policies']}")
        report.append(f"  Successful Schedules: {results['success_count']}")
        report.append(f"  Failed Schedules: {results['failed_count']}")
        report.append("")
        
        # Add a section listing successful backup schedules with their policies
        if results['success_count'] > 0:
            report.append("  SUCCESSFUL BACKUP SCHEDULES:")
            report.append("  " + "=" * 26)
            report.append("  Backup Schedule Name (Schedule Policy Name)")
            report.append("  " + "-" * 50)
            
            for schedule in sorted(results['successful_schedules'], key=lambda x: (x['namespace'], x['vm'])):
                report.append(f"  {schedule['backup_name']} ({schedule['policy_name']})")
            report.append("")
        
        # Add a section listing failed backup schedules with their policies
        if results['failed_count'] > 0:
            report.append("  FAILED BACKUP SCHEDULES:")
            report.append("  " + "=" * 23)
            report.append("  Backup Schedule Name (Schedule Policy Name)")
            report.append("  " + "-" * 50)
            
            for schedule in sorted(results['failed_schedules'], key=lambda x: (x['namespace'], x['vm'])):
                report.append(f"  {schedule['backup_name']} ({schedule['policy_name']})")
            report.append("")
        
        # More detailed information about successful schedules
        if results['success_count'] > 0:
            report.append("  SUCCESSFUL SCHEDULES DETAILS:")
            for schedule in sorted(results['successful_schedules'], key=lambda x: (x['namespace'], x['vm'])):
                report.append(f"    - {schedule['backup_name']}")
                report.append(f"      VM: {schedule['vm']}")
                report.append(f"      Namespace: {schedule['namespace']}")
                report.append(f"      Policy: {schedule['policy_name']}")
                report.append("")
        
        # More detailed information about failed schedules
        if results['failed_count'] > 0:
            report.append("  FAILED SCHEDULES DETAILS:")
            for schedule in sorted(results['failed_schedules'], key=lambda x: (x['namespace'], x['vm'])):
                report.append(f"    - {schedule['backup_name']}")
                report.append(f"      VM: {schedule['vm']}")
                report.append(f"      Namespace: {schedule['namespace']}")
                report.append(f"      Policy: {schedule['policy_name']}")
                report.append("")
    
    # Error information
    if error:
        report.append("ERROR INFORMATION:")
        report.append(f"  {error}")
        report.append("")
    
    # Execution status
    if error:
        report.append("EXECUTION STATUS: FAILED")
    elif policy_result and policy_result['status'] == 'error':
        report.append("EXECUTION STATUS: FAILED - DUPLICATE POLICIES DETECTED")
    elif results:
        if results['failed_count'] > 0:
            report.append("EXECUTION STATUS: PARTIALLY SUCCESSFUL")
        else:
            report.append("EXECUTION STATUS: SUCCESSFUL")
    else:
        report.append("EXECUTION STATUS: UNKNOWN")
    
    report.append("=" * 80)
    report.append("")
    return "\n".join(report)

def save_report(report_content, filename="vm_backup_schedule_report.log"):
    """
    Append report content to a report file
    
    Args:
        report_content: Content to append
        filename: Name of the report file
    """
    try:
        with open(filename, "a") as f:
            f.write(report_content)
        logging.info(f"Report appended to {filename}")
    except Exception as e:
        logging.error(f"Failed to write report: {e}")


def print_summary(args, results=None, policy_result=None, vm_map=None):
    """
    Print a professional summary of the script execution
    
    Args:
        args: Command line arguments
        results: Results of backup schedule creation
        policy_result: Results of policy creation
        vm_map: Dictionary mapping namespaces to lists of VM names
    """
    # Clear formatting for better presentation
    print("\n" + "=" * 80)
    print(f"{'VM BACKUP SCHEDULE SUMMARY':^80}")
    print("=" * 80)
    
    # Input parameters
    print(f"\n{'INPUT PARAMETERS':^80}")
    print(f"{'=' * 16:^80}")
    print(f"Cluster:         {args.cluster_name}")
    print(f"Backup Location: {args.backup_location}")
    print(f"Time Series:     {args.time_series}")
    print(f"Dry Run:         {'Yes' if args.dry_run else 'No'}")
    
    # Policy information
    if policy_result:
        print(f"\n{'SCHEDULE POLICY INFORMATION':^80}")
        print(f"{'=' * 27:^80}")
        
        if policy_result['status'] == 'error':
            print(f"Status: \033[91mERROR - DUPLICATE POLICIES DETECTED\033[0m")
            print(f"Found {len(policy_result.get('existing_policies', []))} existing policies with the same names.")
            
            if len(policy_result.get('existing_policies', [])) > 0:
                print("\nExisting Policies:")
                for policy in policy_result.get('existing_policies', []):
                    print(f"  - {policy}")
            
            print("\nTo proceed with the script:")
            print("1. Delete the existing policies")
            print("2. Run the script again with the same parameters")
        else:
            print(f"Status: \033[92mSuccess\033[0m")
            print(f"Created {len(policy_result.get('policies', []))} schedule policies:")
            for i, (policy_name, policy_uid) in enumerate(policy_result.get('policies', []), 1):
                if i <= 5:  # Limit to showing first 5 policies if there are many
                    print(f"  - {policy_name}")
                elif i == 6:
                    print(f"  - ... and {len(policy_result.get('policies', [])) - 5} more")
                    break
    
    # VM information
    if vm_map:
        print(f"\n{'VM INVENTORY':^80}")
        print(f"{'=' * 12:^80}")
        
        total_vms = sum(len(vms) for vms in vm_map.values())
        print(f"Found {total_vms} VMs across {len(vm_map)} namespaces")
        
        # Show namespace breakdown with VM names
        if len(vm_map) <= 10:  # Show details for up to 10 namespaces
            for namespace, vms in sorted(vm_map.items()):
                vm_list = ", ".join(sorted(vms))
                # Truncate the list if it's too long for display
                if len(vm_list) > 60:
                    vm_list = vm_list[:57] + "..."
                print(f"  - Namespace: {namespace} - VMs: {vm_list}")
        else:
            # Just show a summary for larger clusters
            print(f"  Top 5 namespaces by VM count:")
            sorted_namespaces = sorted(vm_map.items(), key=lambda x: len(x[1]), reverse=True)
            for i, (namespace, vms) in enumerate(sorted_namespaces[:5], 1):
                vm_sample = ", ".join(sorted(vms)[:3])
                if len(vms) > 3:
                    vm_sample += f", ... ({len(vms)-3} more)"
                print(f"  {i}. {namespace}: {vm_sample}")
    
    # Backup schedule results
    if results:
        print(f"\n{'BACKUP SCHEDULE RESULTS':^80}")
        print(f"{'=' * 23:^80}")
        
        print(f"Total VMs:            {results['total_vms']}")
        print(f"Total Policies:       {results['total_policies']}")
        print(f"Successful Schedules: {results['success_count']}")
        print(f"Failed Schedules:     {results['failed_count']}")
        
        if results['success_count'] > 0 and results['failed_count'] == 0:
            print(f"\n\033[92mAll backup schedules created successfully!\033[0m")
        elif results['success_count'] > 0 and results['failed_count'] > 0:
            print(f"\n\033[93mPartially successful: {results['success_count']}/{results['total_vms']} schedules created\033[0m")
            print("See the detailed report for information about failed schedules.")
        elif results['success_count'] == 0 and results['failed_count'] > 0:
            print(f"\n\033[91mFailed: No schedules created successfully.\033[0m")
            
        # Add section listing backup schedules with their policies
        if results['success_count'] > 0:
            print(f"\n{'BACKUP SCHEDULES CREATED':^80}")
            print(f"{'=' * 24:^80}")
            print("Backup Schedule Name (Schedule Policy Name)")
            print("-" * 50)
            
            # Sort schedules by namespace and VM name for better readability
            for schedule in sorted(results['successful_schedules'], key=lambda x: (x['namespace'], x['vm'])):
                schedule_name = schedule['backup_name']
                policy_name = schedule['policy_name']
                print(f"{schedule_name} ({policy_name})")
    
    # Summary footer
    print("\n" + "=" * 80)
    if policy_result and policy_result['status'] == 'error':
        status = "\033[91mFAILED - DUPLICATE POLICIES\033[0m"
        print(f"{'EXECUTION STATUS: ' + status:^80}")
    elif results:
        if results['failed_count'] > 0 and results['success_count'] == 0:
            status = "\033[91mFAILED\033[0m"
        elif results['failed_count'] > 0:
            status = "\033[93mPARTIALLY SUCCESSFUL\033[0m"
        else:
            status = "\033[92mSUCCESSFUL\033[0m"
        print(f"{'EXECUTION STATUS: ' + status:^80}")
    else:
        status = "\033[91mFAILED\033[0m"
        print(f"{'EXECUTION STATUS: ' + status:^80}")
    print("=" * 80 + "\n")


def log_summary(args, results=None, policy_result=None, vm_map=None):
    """
    Log a professional summary of the script execution
    """

    logging.info("\n" + "=" * 80)
    logging.info(f"{'VM BACKUP SCHEDULE SUMMARY':^80}")
    logging.info("=" * 80)

    logging.info(f"\n{'INPUT PARAMETERS':^80}")
    logging.info(f"{'=' * 16:^80}")
    logging.info(f"Cluster:         {args.cluster_name}")
    logging.info(f"Backup Location: {args.backup_location}")
    logging.info(f"Time Series:     {args.time_series}")
    logging.info(f"Dry Run:         {'Yes' if args.dry_run else 'No'}")

    if policy_result:
        logging.info(f"\n{'SCHEDULE POLICY INFORMATION':^80}")
        logging.info(f"{'=' * 27:^80}")

        if policy_result['status'] == 'error':
            logging.info("Status: ERROR - DUPLICATE POLICIES DETECTED")
            logging.info(f"Found {len(policy_result.get('existing_policies', []))} existing policies with the same names.")

            if policy_result.get('existing_policies'):
                logging.info("\nExisting Policies:")
                for policy in policy_result['existing_policies']:
                    logging.info(f"  - {policy}")

            logging.info("\nTo proceed with the script:")
            logging.info("1. Delete the existing policies (see detailed report for commands)")
            logging.info("2. Run the script again with the same parameters")

            if 'cleanup_help' in policy_result:
                logging.info("\nExample cleanup command for the first policy:")
                for line in policy_result['cleanup_help'].split('\n'):
                    if line.startswith('ansible-playbook'):
                        logging.info(f"  {line}")
                        break
                logging.info("See the detailed report for all cleanup commands.")
        else:
            logging.info("Status: Success")
            logging.info(f"Created {len(policy_result.get('policies', []))} schedule policies:")
            for i, (policy_name, policy_uid) in enumerate(policy_result.get('policies', []), 1):
                if i <= 5:
                    logging.info(f"  - {policy_name}")
                elif i == 6:
                    logging.info(f"  - ... and {len(policy_result['policies']) - 5} more")
                    break

    if vm_map:
        logging.info(f"\n{'VM INVENTORY':^80}")
        logging.info(f"{'=' * 12:^80}")
        total_vms = sum(len(vms) for vms in vm_map.values())
        logging.info(f"Found {total_vms} VMs across {len(vm_map)} namespaces")

        if len(vm_map) <= 10:
            for namespace, vms in sorted(vm_map.items()):
                vm_list = ", ".join(sorted(vms))
                if len(vm_list) > 60:
                    vm_list = vm_list[:57] + "..."
                logging.info(f"  - Namespace: {namespace} - VMs: {vm_list}")
        else:
            logging.info("  Top 5 namespaces by VM count:")
            sorted_namespaces = sorted(vm_map.items(), key=lambda x: len(x[1]), reverse=True)
            for i, (namespace, vms) in enumerate(sorted_namespaces[:5], 1):
                vm_sample = ", ".join(sorted(vms)[:3])
                if len(vms) > 3:
                    vm_sample += f", ... ({len(vms) - 3} more)"
                logging.info(f"  {i}. {namespace}: {vm_sample}")

    if results:
        logging.info(f"\n{'BACKUP SCHEDULE RESULTS':^80}")
        logging.info(f"{'=' * 23:^80}")
        logging.info(f"Total VMs:            {results['total_vms']}")
        logging.info(f"Total Policies:       {results['total_policies']}")
        logging.info(f"Successful Schedules: {results['success_count']}")
        logging.info(f"Failed Schedules:     {results['failed_count']}")

        if results['success_count'] > 0 and results['failed_count'] == 0:
            logging.info("All backup schedules created successfully!")
        elif results['success_count'] > 0 and results['failed_count'] > 0:
            logging.info(f"Partially successful: {results['success_count']}/{results['total_vms']} schedules created")
            logging.info("See the detailed report for information about failed schedules.")
        elif results['success_count'] == 0 and results['failed_count'] > 0:
            logging.info("Failed: No schedules created successfully.")

        if results['success_count'] > 0:
            logging.info(f"\n{'BACKUP SCHEDULES CREATED':^80}")
            logging.info(f"{'=' * 24:^80}")
            logging.info("Backup Schedule Name (Schedule Policy Name)")
            logging.info("-" * 50)
            for schedule in sorted(results['successful_schedules'], key=lambda x: (x['namespace'], x['vm'])):
                logging.info(f"{schedule['backup_name']} ({schedule['policy_name']})")

    logging.info("\n" + "=" * 80)
    if policy_result and policy_result['status'] == 'error':
        status = "FAILED - DUPLICATE POLICIES"
    elif results:
        if results['failed_count'] > 0 and results['success_count'] == 0:
            status = "FAILED"
        elif results['failed_count'] > 0:
            status = "PARTIALLY SUCCESSFUL"
        else:
            status = "SUCCESSFUL"
    else:
        status = "FAILED"
    logging.info(f"{'EXECUTION STATUS: ' + status:^80}")
    logging.info("=" * 80 + "\n")

def enumerate_clusters(name_filter=None, dry_run=False):
    """
    Enumerate clusters in PX-Backup using Ansible
    
    Args:
        name_filter (str, optional): Filter clusters by name
        dry_run (bool, optional): If True, don't actually run the command
    
    Returns:
        list: List of matching clusters
    """
    logging.info(f"Enumerating clusters with filter: {name_filter}")
    
    if dry_run:
        logging.debug("[DRY RUN] Would enumerate clusters")
        return []
    
    # Prepare extra vars for the Ansible command
    extra_vars = {}
    if name_filter:
        extra_vars["name_filter"] = name_filter
    
    # Convert to JSON string
    extra_vars_json = json.dumps(extra_vars)
    
    # Run the Ansible command
    cmd = [
        "ansible-playbook", "examples/cluster/enumerate.yaml", "-vvvv",
        "--extra-vars", extra_vars_json
    ]
    
    logging.debug(f"Executing command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        logging.debug(f"Command completed with return code: {result.returncode}")
        
        if result.returncode != 0:
            logging.error(f"Failed to enumerate clusters")
            return []
        
        # Extract clusters from output
        stdout_text = result.stdout
        
        # Look for the cluster enumeration task output - match various possible task names
        task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call)].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
        if not task_match:
            # Try looking for it at the end of the output (last task)
            task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call)].*?\n(.*?)$", stdout_text, re.DOTALL)
            if not task_match:
                logging.error("Could not find cluster enumeration task output")
                # Print the first 200 chars of stdout for debugging
                logging.debug(f"First 200 chars of stdout: {stdout_text[:200]}")
                return []
        
        task_output = task_match.group(2)
        
        # Try to extract JSON
        json_match = re.search(r'"clusters"\s*:\s*(\[.*?\])', task_output, re.DOTALL)
        if not json_match:
            # Try to find the clusters JSON in the entire output as a fallback
            json_match = re.search(r'"clusters"\s*:\s*(\[.*?\])', stdout_text, re.DOTALL)
            if not json_match:
                logging.error("Could not extract clusters list from task output")
                # Print part of the task output for debugging
                logging.debug(f"Task output snippet: {task_output[:200]}")
                return []
        
        try:
            clusters_json = json_match.group(1)
            clusters = json.loads(clusters_json)
            return clusters
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse clusters JSON: {e}")
            return []
    except Exception as e:
        logging.error(f"Error executing enumerate clusters command: {e}")
        return []


def get_cluster_by_name(cluster_name, dry_run=False):
    """
    Get cluster information by name
    
    Args:
        cluster_name (str): Name of the cluster to find
        dry_run (bool, optional): If True, don't actually run the command
    
    Returns:
        tuple: (cluster_name, cluster_uid) if found, otherwise (None, None)
    """
    if dry_run:
        logging.debug(f"[DRY RUN] Would get cluster info for: {cluster_name}")
        return cluster_name, "dry-run-cluster-uid"
    
    # First enumerate clusters with the name filter
    clusters = enumerate_clusters(name_filter=cluster_name)
    
    if not clusters:
        logging.error(f"No clusters found with name: {cluster_name}")
        return None, None
    
    # Find exact match
    for cluster in clusters:
        if cluster.get("metadata", {}).get("name") == cluster_name:
            cluster_uid = cluster.get("metadata", {}).get("uid")
            return cluster_name, cluster_uid
    
    # If no exact match, use the first one with partial match
    if clusters:
        cluster = clusters[0]
        cluster_name = cluster.get("metadata", {}).get("name")
        cluster_uid = cluster.get("metadata", {}).get("uid")
        logging.info(f"Using cluster: {cluster_name} with UID: {cluster_uid}")
        return cluster_name, cluster_uid
    
    return None, None


def enumerate_backup_locations(name_filter=None, dry_run=False):
    """
    Enumerate backup locations in PX-Backup using Ansible
    
    Args:
        name_filter (str, optional): Filter backup locations by name
        dry_run (bool, optional): If True, don't actually run the command
    
    Returns:
        list: List of matching backup locations
    """
    logging.info(f"Enumerating backup locations with filter: {name_filter}")
    
    if dry_run:
        logging.debug(f"[DRY RUN] Would enumerate backup locations")
        return []
    
    # Prepare extra vars for the Ansible command
    extra_vars = {}
    if name_filter:
        extra_vars["name_filter"] = name_filter
    
    # Convert to JSON string
    extra_vars_json = json.dumps(extra_vars)
    
    # Run the Ansible command
    cmd = [
        "ansible-playbook", "examples/backup_location/enumerate.yaml", "-vvvv",
        "--extra-vars", extra_vars_json
    ]
    
    logging.debug(f"Executing command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        logging.error(f"Failed to enumerate backup locations")
        return []
    
    # Extract backup locations from output
    stdout_text = result.stdout
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', stdout_text)

    task_pattern = (
        r"(TASK \[Backup Location Enumerate call\][\s\S]*?)"
        r"(?=TASK \[|PLAY RECAP|$)"
    )
    task_match = re.search(task_pattern, cleaned_output)
    if not task_match:
        logging.error("Could not find 'TASK [Backup Location Enumerate call]' block in the output.")
        return {}

    task_block = task_match.group(1)

    start_pattern = r'"backup_locations"\s*:\s*\['
    start_match = re.search(start_pattern, task_block)
    if not start_match:
        logging.error("No 'backup_locations' array found in 'TASK [Backup Location Enumerate call]' block.")
        return {}

    start_index = task_block.find('[', start_match.start())
    if start_index == -1:
        logging.error("Could not find '[' after 'backup_locations':")
        return {}

    bracket_depth = 0
    i = start_index
    while i < len(task_block):
        if task_block[i] == '[':
            bracket_depth += 1
        elif task_block[i] == ']':
            bracket_depth -= 1
            if bracket_depth == 0:
                break
        i += 1

    if bracket_depth != 0:
        logging.error("Mismatched brackets in 'backup_locations' JSON array.")
        return {}

    array_snippet = task_block[start_index: i + 1]
    wrapped_json = '{ "backup_locations": ' + array_snippet + ' }'

    try:
        parsed = json.loads(wrapped_json)
        return parsed
    except json.JSONDecodeError as exc:
        logging.error(f"Failed to parse 'backup_locations' JSON: {exc}")
        return {}


def get_backup_location_by_name(location_name, dry_run=False):
    """
    Get backup location information by name
    
    Args:
        location_name (str): Name of the backup location to find
        dry_run (bool, optional): If True, don't actually run the command
    
    Returns:
        tuple: (location_name, location_uid) if found, otherwise (None, None)
    """
    if dry_run:
        logging.debug(f"[DRY RUN] Would get backup location info for: {location_name}")
        return location_name, "dry-run-location-uid"
    
    # First enumerate backup locations with the name filter
    enumerate_response = enumerate_backup_locations(name_filter=location_name)

    locations = enumerate_response.get("backup_locations", [])

    # Find exact match
    for location in locations:
        if location.get("metadata", {}).get("name") == location_name:
            location_uid = location.get("metadata", {}).get("uid")
            return location_name, location_uid

    if locations:
        location = locations[0]
        location_name = location.get("metadata", {}).get("name")
        location_uid = location.get("metadata", {}).get("uid")
        logging.info(f"Using backup location: {location_name} with UID: {location_uid}")
        return location_name, location_uid
    
    return None, None


def enumerate_schedule_policies(name_filter=None, dry_run=False):
    """
    Enumerate schedule policies in PX-Backup using Ansible with improved error handling
    
    Args:
        name_filter (str, optional): Filter schedule policies by name
        dry_run (bool, optional): If True, don't actually run the command
    
    Returns:
        list: List of matching schedule policies
    """
    logging.info(f"Enumerating schedule policies with filter: {name_filter}")
    
    if dry_run:
        logging.debug(f"[DRY RUN] Would enumerate schedule policies")
        return []
    
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
    
    logging.debug(f"Executing command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        logging.error(f"Failed to enumerate schedule policies")
        return []
    
    # Extract schedule policies from output
    stdout_text = result.stdout
    
    # Look for the schedule policies task output - match various possible task names
    task_match = re.search(r"TASK \[(Enumerate schedule policies|Schedule Policy Enumerate call)].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate schedule policies|Schedule Policy Enumerate call)].*?\n(.*?)$", stdout_text, re.DOTALL)
        if not task_match:
            logging.warning("Could not find schedule policies task output, trying alternative pattern")
            # Try another pattern - look for schedule_policies in the output anywhere
            json_match = re.search(r'"schedule_policies"\s*:\s*(\[.*?\])', stdout_text, re.DOTALL)
            if json_match:
                try:
                    policies_json = json_match.group(1)
                    policies = json.loads(policies_json)
                    return policies
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to parse schedule policies JSON: {e}")
                    return []
            logging.error("Could not extract schedule policies from output")
            return []
    
    task_output = task_match.group(2)
    
    # Try to extract JSON
    json_match = re.search(r'"schedule_policies"\s*:\s*(\[.*?\])', task_output, re.DOTALL)
    if not json_match:
        # Try to find the schedule_policies JSON in the entire output as a fallback
        json_match = re.search(r'"schedule_policies"\s*:\s*(\[.*?\])', stdout_text, re.DOTALL)
        if not json_match:
            logging.error("Could not extract schedule policies list from task output")
            return []
    
    try:
        policies_json = json_match.group(1)
        policies = json.loads(policies_json)
        return policies
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse schedule policies JSON: {e}")
        return []


def check_policy_exists(policy_name, dry_run=False):
    """
    Check if a policy with the given name already exists
    
    Args:
        policy_name (str): The policy name to check
        dry_run (bool, optional): If True, don't actually run the command
        
    Returns:
        tuple: (exists, uid) where exists is a boolean indicating if the policy exists,
               and uid is the policy UID (or None if it doesn't exist or dry_run is True)
    """
    if dry_run:
        logging.debug(f"[DRY RUN] Would check if policy exists: {policy_name}")
        return False, None
        
    logging.info(f"Checking if policy exists: {policy_name}")
    policies = enumerate_schedule_policies(name_filter=policy_name)
    
    for policy in policies:
        metadata = policy.get("metadata", {})
        if metadata.get("name") == policy_name:
            policy_uid = metadata.get("uid")
            logging.info(f"Policy found: {policy_name} with UID: {policy_uid}")
            return True, policy_uid
    
    logging.info(f"Policy not found: {policy_name}")
    return False, None


def create_schedule_policy(policy_name, policy_time, dry_run=False):
    """
    Creates a schedule policy with the given name and time
    
    Args:
        policy_name (str): The policy name to create
        policy_time (datetime): Time for the policy
        dry_run (bool, optional): If True, don't actually run the command
        
    Returns:
        tuple: (policy_name, policy_uid) if created/found successfully, otherwise (None, None)
    """
    if dry_run:
        logging.debug(f"[DRY RUN] Would create schedule policy: {policy_name} at time {policy_time.strftime('%H:%M')}")
        return policy_name, "dry-run-policy-uid"
    
    # Format the time for the policy (e.g., "06:00PM")
    formatted_time = policy_time.strftime("%I:%M%p").lstrip("0")
    
    # Construct extra-vars JSON object
    extra_vars = json.dumps({
        "schedule_policies": [
            {
                "name": policy_name,
                "validate_certs": True,
                "labels": {
                    "policy-type": "vm-backup",
                    "created": datetime.now().strftime("%Y-%m-%d")
                },
                "schedule_policy": {
                    "daily": {
                        "time": formatted_time,
                        "retain": 14,
                        "incremental_count": {
                            "count": 6
                        }
                    }
                }
            }
        ]
    })

    logging.info(f"Creating schedule policy: {policy_name} with time {formatted_time}")
    cmd = [
        "ansible-playbook", "examples/schedule_policy/create.yaml", "-vvvv",
        "--extra-vars", extra_vars
    ]
    
    logging.debug(f"Executing command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        # Check if the error is due to policy already existing
        if "already exists" in result.stderr or "already exists" in result.stdout:
            logging.info(f"Policy {policy_name} appears to already exist. Trying to fetch it directly.")
            # Try to get the policy details again
            exists, policy_uid = check_policy_exists(policy_name)
            if exists and policy_uid:
                logging.info(f"Successfully retrieved existing policy: {policy_name}")
                return policy_name, policy_uid
        
        logging.error(f"Failed to create schedule policy: {policy_name}")
        return None, None
        
    stdout_text = result.stdout
    if not stdout_text:
        logging.error(f"No output from Ansible playbook for policy {policy_name}.")
        return None, None

    # Locate the "Create schedule policy" task output
    task_match = re.search(r"TASK \[Create schedule policy].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        logging.error(f"Could not find 'Create schedule policy' task output for policy {policy_name}.")
        return None, None
    task_output = task_match.group(1)

    # Extract JSON from the task output
    json_match = re.search(r'(\{.*\})', task_output, re.DOTALL)
    if not json_match:
        logging.error(f"Could not extract JSON from 'Create schedule policy' task output for policy {policy_name}.")
        return None, None
    raw_json = json_match.group(1).strip()

    try:
        decoder = json.JSONDecoder()
        parsed_json, idx = decoder.raw_decode(raw_json)
        logging.info(f"Created schedule policy successfully - {policy_name}")
        policy_uid = parsed_json.get("schedule_policy", {}).get("metadata", {}).get("uid")
        return policy_name, policy_uid
    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing failed for policy {policy_name}: {str(e)}")
        return None, None


def create_vm_backup_schedule(vm, namespace, policy_name, policy_uid, backup_location_ref, cluster_ref, csi_driver_map,  dry_run=False):
    """
    Create a backup schedule for a single VM
    
    Args:
        vm (str): VM name
        namespace (str): VM namespace
        policy_name (str): Policy name
        policy_uid (str): Policy UID
        backup_location_ref (dict): Backup location reference
        cluster_ref (dict): Cluster reference
        dry_run (bool, optional): If True, don't actually run the command
        
    Returns:
        tuple: (success, backup_name) where success is a boolean indicating if the operation succeeded
    """
    # Extract time from policy name
    time_str = policy_name.replace("pxb-", "")
    
    # Create backup schedule name
    backup_name = f"pxb-{namespace}-{vm}-{policy_name}"
    
    if dry_run:
        logging.debug(f"[DRY RUN] Would create backup schedule: {backup_name} for VM {vm} in namespace {namespace} using policy {policy_name}")
        return True, backup_name
    
    schedule_policy_ref = {
        "name": policy_name,
        "uid": policy_uid
    }
    
    vm_namespaces = [namespace]
    include_resources = [{
        "group": "kubevirt.io",
        "kind": "VirtualMachine",
        "version": "v1",
        "name": vm,
        "namespace": namespace
    }]

    # Define backup config
    backup_object_type = {
        "type": "VirtualMachine"
    }
    
    playbook_data = [{
        "name": "Configure VM Backup Schedule",
        "hosts": "localhost",
        "gather_facts": False,
        "vars": {
            "backup_schedules": [{
                "name": backup_name,
                "volume_snapshot_class_mapping": csi_driver_map,
                "backup_location_ref": backup_location_ref,
                "schedule_policy_ref": schedule_policy_ref,
                "cluster_ref": cluster_ref,
                "backup_type": "Normal",
                "backup_object_type": backup_object_type,
                "skip_vm_auto_exec_rules": True,
                "validate_certs": True,
                "labels": {
                    "vm-name": vm,
                    "vm-namespace": namespace,
                    "policy-name": policy_name,
                    "created": datetime.now().strftime("%Y-%m-%d")
                }
            }],
            "vm_namespaces": vm_namespaces,
            "include_resources": include_resources
        },
        "tasks": [
            {
                "name": "Create Backup Schedule",
                "include_tasks": "examples/backup_schedule/create_vm_schedule.yaml"
            }
        ]
    }]

    # Save generated playbook
    timestamp = int(time.time())
    playbook_file = f"create_backup_{namespace}_{vm}_{timestamp}.yaml"
    with open(playbook_file, "w") as f:
        yaml.safe_dump(playbook_data, f, default_flow_style=False)

    logging.info(f"Creating backup schedule for VM: {vm} in namespace: {namespace} using policy: {policy_name}")

    # Invoke the Ansible playbook
    combined_vars = json.dumps({
        "vm_namespaces": vm_namespaces,
        "include_resources": include_resources
    })
    
    ansible_cmd = [
        "ansible-playbook", playbook_file, "-vvvv",
        "--extra-vars", combined_vars
    ]

    logging.debug(f"Executing command: {' '.join(ansible_cmd)}")
    result = subprocess.run(ansible_cmd, capture_output=True, text=True)
    logging.debug(f"Command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        logging.error(f"Failed to create backup schedule for VM: {vm} in namespace: {namespace}")
        return False, backup_name

    # Check for success in output
    stdout_text = result.stdout
    
    # Locate the "Create Backup Schedule" task output
    task_match = re.search(r"TASK \[Create Backup Schedule].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        logging.error(f"Could not find 'Create Backup Schedule' task output for VM {vm} in namespace {namespace}.")
        return False, backup_name
    
    # Success
    logging.info(f"Created backup schedule for VM: {vm} in namespace: {namespace} - {backup_name}")
    return True, backup_name


def get_cluster_info(cluster_name, dry_run=False):
    """
    Get cluster information for the specified cluster name
    
    Args:
        cluster_name (str): Name of the cluster to find
        dry_run (bool, optional): If True, don't actually run the command
    
    Returns:
        tuple: (cluster_name, cluster_uid)
        
    Raises:
        ValueError: If cluster name is not provided or cluster is not found
    """
    if not cluster_name:
        raise ValueError("Cluster name must be provided")
        
    # Dynamically get cluster info by name
    cluster_name, cluster_uid = get_cluster_by_name(cluster_name, dry_run=dry_run)
    if not cluster_name or not cluster_uid:
        raise ValueError(f"Cluster '{cluster_name}' not found")
        
    return cluster_name, cluster_uid


def inspect_cluster(cluster_name, cluster_uid, dry_run=False):
    """
    Inspect a cluster and extract its configuration
    
    Args:
        cluster_name (str): The name of the cluster
        cluster_uid (str): The UID of the cluster
        dry_run (bool, optional): If True, don't actually run the command
        
    Returns:
        str or None: Path to the output file containing cluster data, or None if inspection failed
        
    Raises:
        ValueError: If inspection fails
    """
    logging.info(f"Running Ansible playbook for cluster: {cluster_name}, UID: {cluster_uid}")

    if dry_run:
        logging.debug(f"[DRY RUN] Would inspect cluster: {cluster_name}")
        output_file = f"cluster_data_{cluster_name}.json"
        # Create a dummy file for dry run
        with open(output_file, "w") as json_file:
            json.dump({"cluster": {"metadata": {"name": cluster_name}}}, json_file, indent=4)
        return output_file

    # Construct extra-vars as a JSON object
    extra_vars = json.dumps({
        "clusters_inspect": [{
            "name": cluster_name,
            "uid": cluster_uid,
            "include_secrets": True
        }]
    })

    cmd = [
        "ansible-playbook", "examples/cluster/inspect.yaml", "-vvvv",
        "--extra-vars", extra_vars
    ]

    logging.debug(f"Executing command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Command completed with return code: {result.returncode}")

    if result.returncode != 0:
        raise ValueError(f"Cluster inspection failed with return code {result.returncode}")

    stdout_text = result.stdout
    if not stdout_text:
        raise ValueError("No output from Ansible playbook")

    # Step 1: Locate the "Get cluster details" task output
    task_match = re.search(r"TASK \[Get cluster details].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        raise ValueError("Could not find 'Get cluster details' task output")

    task_output = task_match.group(1)

    # Step 2: Extract JSON between "cluster" and "clusters"
    json_match = re.search(r'"cluster"\s*:\s*({.*?})\s*,\s*"clusters"', task_output, re.DOTALL)
    if not json_match:
        raise ValueError("Could not extract JSON between 'cluster' and 'clusters'")

    raw_json = json_match.group(1)

    # Step 3: Parse JSON and save to file
    try:
        parsed_json = json.loads(raw_json)
        output_file = f"cluster_data_{cluster_name}.json"
        with open(output_file, "w") as json_file:
            json.dump(parsed_json, json_file, indent=4)
        logging.info(f"Extracted cluster data successfully.")
        return output_file

    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parsing failed: {str(e)}")


def create_kubeconfig(cluster_file, dry_run=False):
    """
    Create a kubeconfig file from cluster data
    
    Args:
        cluster_file (str): Path to the cluster data file
        dry_run (bool, optional): If True, don't actually create the file
        
    Returns:
        str: Path to the created kubeconfig file
        
    Raises:
        ValueError: If kubeconfig cannot be created
    """
    if not cluster_file:
        raise ValueError("No cluster file provided")
    
    if dry_run:
        logging.debug(f"[DRY RUN] Would create kubeconfig from cluster file: {cluster_file}")
        # Just return a filename that would be created
        cluster_name = "dryrun"
        try:
            with open(cluster_file, 'r') as f:
                data = json.load(f)
                cluster_name = data.get("cluster", {}).get("metadata", {}).get("name", "dryrun")
        except:
            pass
        return f"{cluster_name}_kubeconfig"
        
    try:
        # Load the JSON data from the file
        with open(cluster_file, 'r') as f:
            data = json.load(f)

        # Extract the cluster name from metadata; default to "unknown" if not present
        cluster_name = data.get("cluster", {}).get("metadata", {}).get("name", "unknown")

        # Extract the base64 encoded kubeconfig text from the clusterinfo section
        kubeconfig_b64 = data.get("cluster", {}).get("clusterInfo", {}).get("kubeconfig", "")

        if not kubeconfig_b64:
            raise ValueError("No kubeconfig data found in the cluster file")

        # Decode the base64 encoded kubeconfig
        try:
            kubeconfig_text = base64.b64decode(kubeconfig_b64).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to decode kubeconfig: {e}")

        # Define the output filename based on the cluster name
        filename = f"{cluster_name}_kubeconfig"

        # Write the decoded kubeconfig text to the file
        with open(filename, "w") as f:
            f.write(kubeconfig_text)

        logging.info(f"Created kubeconfig file: {filename}")
        return filename
        
    except (IOError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to process cluster file: {e}")


def get_inventory(ns_list, kubeconfig_file, dry_run=False):
    """
    Get inventory of all VirtualMachine resources in the cluster
    
    Args:
        ns_list (list): List of namespaces to check
        kubeconfig_file (str): Path to the kubeconfig file
        dry_run (bool, optional): If True, don't make any changes but still get real data
        
    Returns:
        dict: Dictionary mapping namespaces to lists of VM names
        
    Raises:
        ValueError: If there's an error accessing the cluster
    """
    logging.info(f"Getting VM inventory from {len(ns_list)} namespaces")
    
    vm_map = {}
    try:
        # Always load the actual inventory
        config.load_kube_config(kubeconfig_file)
        # Setup the cert
        configuration = client.Configuration.get_default_copy()
        configuration.ssl_ca_cert = "ca.crt"
        api_client = client.ApiClient(configuration)
        custom_api = client.CustomObjectsApi(api_client)

        group = "kubevirt.io"
        version = "v1"
        plural = "virtualmachines"
        
        for ns in ns_list:
            try:
                # List all VirtualMachine custom objects in the namespace
                result = custom_api.list_namespaced_custom_object(
                    group=group,
                    version=version,
                    plural=plural,
                    namespace=ns,
                )
                # Iterate over each VirtualMachine and add to the map
                vm_list = []
                for item in result.get("items", []):
                    metadata = item.get("metadata", {})
                    name = metadata.get("name")
                    if name:
                        vm_list.append(name)
                
                if vm_list:  # Only add namespace if it has VMs
                    vm_map[ns] = vm_list
                    logging.info(f"Found {len(vm_list)} VMs in namespace {ns}")
                
            except Exception as e:
                logging.error(f"Error listing VirtualMachines in namespace {ns}: {e}")
                raise ValueError(f"Failed to access namespace {ns}: {e}")
    except Exception as e:
        logging.error(f"Error loading kubeconfig or accessing cluster: {e}")
        raise ValueError(f"Failed to access cluster: {e}")
    
    return vm_map


def parse_time_series(time_series):
    """
    Parse a comma-separated list of times in 24-hour format
    
    Args:
        time_series (str): Comma-separated list of times (e.g., "0100,0245,0350")
        
    Returns:
        list: List of datetime objects representing the specified times
    """
    times = []
    
    if not time_series:
        return times
        
    time_strings = time_series.split(',')
    
    for time_str in time_strings:
        time_str = time_str.strip()
        
        # Check if the time is in the expected format (24-hour format like "0100" or "2345")
        if not re.match(r'^([01][0-9]|2[0-3])([0-5][0-9])$', time_str):
            logging.error(f"Invalid time format: {time_str}. Expected format is HHMM in 24-hour format (e.g., 0100, 2345)")
            continue
        
        # Extract hours and minutes
        hours = int(time_str[:2])
        minutes = int(time_str[2:])
        
        # Create datetime object with today's date and the specified time
        time_obj = datetime.now().replace(hour=hours, minute=minutes, second=0, microsecond=0)
        times.append(time_obj)
    
    return times


def create_policies_for_time_series(time_series, dry_run=False):
    """
    Create schedule policies for each time in the time series
    
    Args:
        time_series (list): List of datetime objects representing times
        dry_run (bool, optional): If True, don't actually create policies
        
    Returns:
        dict: Dictionary with keys:
            - 'status': 'success' or 'error'
            - 'policies': List of tuples (policy_name, policy_uid) for created policies
            - 'existing_policies': List of existing policy names that caused failure
            - 'message': Error message if status is 'error'
    """
    # First check if any of the policies already exist
    existing_policies = []
    existing_policies_details = []
    all_policy_names = []
    
    for time_obj in time_series:
        time_str = time_obj.strftime("%H%M")
        policy_name = f"pxb-{time_str}"
        all_policy_names.append(policy_name)
        
        exists, uid = check_policy_exists(policy_name, dry_run=dry_run)
        if exists:
            existing_policies.append(policy_name)
            existing_policies_details.append((policy_name, uid))
    
    if existing_policies:
        error_msg = f"The following schedule policies already exist: {', '.join(existing_policies)}"
        logging.error(error_msg)
        logging.error("Please delete these policies before proceeding.")
        
        # Construct a command example for deleting these policies
        cleanup_commands = []
        cleanup_commands.append("# To clean up existing policies, use these commands:")
        cleanup_commands.append("")
        
        # Add specific delete commands for each existing policy
        for policy_name, policy_uid in existing_policies_details:
            delete_cmd = f"ansible-playbook examples/schedule_policy/delete.yaml --extra-vars '{{\"schedule_policies\": [{{\"name\": \"{policy_name}\", \"uid\": \"{policy_uid}\"}}]}}'"
            cleanup_commands.append(delete_cmd)
        
        cleanup_cmd = "\n".join(cleanup_commands)
        logging.error(f"\n{cleanup_cmd}")
        
        return {
            'status': 'error',
            'policies': [],
            'existing_policies': existing_policies,
            'existing_policies_details': existing_policies_details,
            'all_policy_names': all_policy_names,
            'message': error_msg,
            'cleanup_help': cleanup_cmd
        }
    
    # No existing policies found, proceed with creation
    created_policies = []
    for time_obj in time_series:
        time_str = time_obj.strftime("%H%M")
        policy_name = f"pxb-{time_str}"
        
        policy_name, policy_uid = create_schedule_policy(policy_name, time_obj, dry_run=dry_run)
        if policy_name and policy_uid:
            created_policies.append((policy_name, policy_uid))
        else:
            logging.error(f"Failed to create policy: {policy_name}")
    
    return {
        'status': 'success',
        'policies': created_policies,
        'existing_policies': [],
        'all_policy_names': all_policy_names,
        'message': f"Successfully created {len(created_policies)} policies"
    }

def distribute_vms_to_policies(vm_map, policies):
    """
    Distribute VMs across policies
    
    Args:
        vm_map (dict): Dictionary mapping namespaces to lists of VM names
        policies (list): List of tuples (policy_name, policy_uid)
        
    Returns:
        list: List of tuples (vm, namespace, policy_name, policy_uid)
    """
    # Flatten VM map into a list of (vm, namespace) tuples
    vms = []
    for namespace, vm_list in vm_map.items():
        for vm in vm_list:
            vms.append((vm, namespace))
    
    # Calculate how many VMs to assign to each policy
    total_vms = len(vms)
    policy_count = len(policies)
    
    if total_vms == 0 or policy_count == 0:
        return []
    
    assignments = []
    
    # Distribute VMs evenly across policies
    for i, (vm, namespace) in enumerate(vms):
        policy_index = i % policy_count
        policy_name, policy_uid = policies[policy_index]
        assignments.append((vm, namespace, policy_name, policy_uid))
    
    return assignments

def parse_input_map(map_str):
    result = {}
    if map_str:
        for pair in map_str.split(','):
            if ':' not in pair:
                raise ValueError(f"Invalid pair format: {pair}")
            key, value = pair.split(':', 1)
            result[key.strip()] = value.strip()
    return result

def main():
    parser = argparse.ArgumentParser(description="Create backup schedules for virtual machines")
    parser.add_argument("--cluster-name", required=True, help="Name of the cluster to use (required)")
    parser.add_argument("--cluster-uid", required=True, help="UID of the cluster to use (required)")
    parser.add_argument("--backup-location", required=True, help="Name of the backup location to use (required)")
    parser.add_argument("--namespaces", nargs="+", help="List of namespaces to check (e.g., 'ns1' 'ns2')")
    parser.add_argument("--time-series", required=True, help="Comma-separated list of times in 24-hour format (e.g., '0100,0245,0350')")
    parser.add_argument("--output", type=str, default="vm_schedule_result.json", help="Output file for backup results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument('--csiDriver_map',"-d", type=str, help='Map input in the form csiDriver1:VSC1,csiDriver2:VSC2')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # removing dry run option
    args.dry_run = False
    if args.dry_run:
        logging.info("Running in DRY RUN mode. No changes will be made.")
    print(f"Logs are getting captured at {LOG_FILE}")

    try:
        # Parse time series
        time_series_str = args.time_series
        time_series = parse_time_series(time_series_str)
        
        if not time_series:
            raise ValueError("No valid times provided in time-series. Expected format is HHMM in 24-hour format (e.g., 0100,2345)")
            
        logging.info(f"Using time series: {', '.join(t.strftime('%H:%M') for t in time_series)}")
        
        # Get cluster info
        cluster_name = args.cluster_name
        cluster_uid = args.cluster_uid
        logging.info(f"Backing up cluster: {cluster_name} with uid {cluster_uid}")
        
        # Get backup location info
        bl_name, bl_uid = get_backup_location_by_name(args.backup_location, dry_run=args.dry_run)
        if not bl_name or not bl_uid:
            raise ValueError(f"Backup location '{args.backup_location}' not found")
            
        backup_location_ref = {
            "name": bl_name,
            "uid": bl_uid
        }
        
        cluster_ref = {
            "name": cluster_name,
            "uid": cluster_uid
        }
        
        # Inspect cluster and create kubeconfig
        cluster_file = inspect_cluster(cluster_name, cluster_uid, dry_run=args.dry_run)
        if not cluster_file:
            raise ValueError("Failed to inspect cluster")
            
        kubeconfig_file = create_kubeconfig(cluster_file, dry_run=args.dry_run)
        if not kubeconfig_file:
            raise ValueError("Failed to create kubeconfig")
        
        # Get VM inventory
        ns_list = args.namespaces
        if not ns_list:
            logging.info("No namespaces specified, will check all namespaces with VirtualMachines")
            # Get all namespaces if none specified
            if not args.dry_run:
                try:
                    # Load the kubeconfig
                    config.load_kube_config(kubeconfig_file)
                    # Create the API client
                    v1 = client.CoreV1Api()
                    # List all namespaces
                    namespaces = v1.list_namespace()
                    ns_list = [ns.metadata.name for ns in namespaces.items]
                    logging.info(f"Found {len(ns_list)} namespaces in the cluster")
                except Exception as e:
                    logging.error(f"Error listing namespaces: {e}")
                    # Provide a default namespace as fallback
                    ns_list = ["default"]
            else:
                # For dry run, just use some example namespaces
                ns_list = ["default", "kube-system"]
                
        vm_map = get_inventory(ns_list, kubeconfig_file, dry_run=args.dry_run)
        
        # Count total VMs
        total_vm_count = sum(len(vms) for vms in vm_map.values())
        logging.info(f"Found {total_vm_count} VMs across namespaces")
        
        if total_vm_count == 0:
            raise ValueError(f"No VMs found in the specified namespaces. [{','.join(ns_list)}] Please verify the cluster has virtual machines.")
        
        # Create policies for time series
        policy_result = create_policies_for_time_series(time_series, dry_run=args.dry_run)
        
        # Handle the case where duplicate policies are found
        if policy_result['status'] == 'error':
            logging.error("Found duplicate schedule policies. Cannot proceed.")
            
            # Generate a report about the duplicate policies
            report = generate_report(args, error=policy_result['message'], policy_result=policy_result)
            
            # Save the report to a file with timestamp to avoid overwriting
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"duplicate_policies_report_{timestamp}.txt"
            
            try:
                with open(report_filename, "w") as f:
                    f.write(report)
                logging.info(f"Report saved to {report_filename}")
            except Exception as e:
                logging.error(f"Failed to write report: {e}")
            
            # Print a summary of the error
            print_summary(args, policy_result=policy_result)
            log_summary(args, policy_result=policy_result)
            
            # Exit with error since we can't proceed
            return 1
            
        # Proceed with successful policy creation
        policies = policy_result['policies']
        logging.info(f"Created/Found {len(policies)} schedule policies")
        
        # Distribute VMs across policies
        vm_assignments = distribute_vms_to_policies(vm_map, policies)
        
        # Create backup schedules
        results = {
            "total_vms": total_vm_count,
            "total_policies": len(policies),
            "success_count": 0,
            "failed_count": 0,
            "successful_schedules": [],
            "failed_schedules": []
        }
        
        for vm, namespace, policy_name, policy_uid in vm_assignments:
            success, backup_name = create_vm_backup_schedule(
                vm, namespace, policy_name, policy_uid, 
                backup_location_ref, cluster_ref,
                parse_input_map(args.csiDriver_map),
                dry_run=args.dry_run,
            )
            
            if success:
                results["success_count"] += 1
                results["successful_schedules"].append({
                    "vm": vm,
                    "namespace": namespace,
                    "backup_name": backup_name,
                    "policy_name": policy_name
                })
            else:
                results["failed_count"] += 1
                results["failed_schedules"].append({
                    "vm": vm,
                    "namespace": namespace,
                    "backup_name": backup_name,
                    "policy_name": policy_name
                })
        
        # Save results to file
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
            
        logging.info(f"Results saved to {args.output}")
        
        # Generate a full report
        report = generate_report(args, results=results, policy_result=policy_result, vm_map=vm_map)
        report_filename = f"vm_backup_schedule_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(report_filename, "w") as f:
                f.write(report)
            logging.info(f"Detailed report saved to {report_filename}")
        except Exception as e:
            logging.error(f"Failed to write detailed report: {e}")
        
        # Print summary
        print_summary(args, results=results, policy_result=policy_result, vm_map=vm_map)
        log_summary(args, results=results, policy_result=policy_result, vm_map=vm_map)
        
        if results["failed_count"] > 0:
            logging.warning("\nSome backup schedules failed to be created. See result file for details.")
            return 1
        
        logging.info("\nAll backup schedules created successfully!")
        return 0
            
    except ValueError as e:
        logging.error(f"{str(e)}")
        
        # Generate a report for the error
        report = generate_report(args, error=str(e))
        error_report_filename = f"error_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(error_report_filename, "w") as f:
                f.write(report)
            logging.info(f"Error report saved to {error_report_filename}")
        except Exception as report_error:
            logging.error(f"Failed to write error report: {report_error}")
            
        return 1
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        if args.verbose:
            import traceback
            logging.debug(traceback.format_exc())
            
        # Generate a report for the unexpected error
        error_details = traceback.format_exc() if args.verbose else str(e)
        report = generate_report(args, error=f"Unexpected error: {error_details}")
        error_report_filename = f"unexpected_error_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(error_report_filename, "w") as f:
                f.write(report)
            logging.info(f"Error report saved to {error_report_filename}")
        except Exception as report_error:
            logging.error(f"Failed to write error report: {report_error}")
            
        return 1

if __name__ == "__main__":
    sys.exit(main())