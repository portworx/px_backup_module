import base64
from datetime import datetime, timedelta
import json, subprocess, re, time, os
import argparse
import math

import yaml
from kubernetes import client, config

DEFAULT_START_TIME = '1800'
GAP_MINUTES = 2

def enumerate_clusters(name_filter=None):
    """
    Enumerate clusters in PX-Backup using Ansible
    
    Args:
        name_filter (str, optional): Filter clusters by name
    
    Returns:
        list: List of matching clusters
    """
    print(f"[INFO] Enumerating clusters with filter: {name_filter}")
    
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
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[DEBUG] Ansible command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        print(f"[ERROR] Failed to enumerate clusters")
        return []
    
    # Extract clusters from output
    stdout_text = result.stdout
    
    # Look for the cluster enumeration task output - match various possible task names
    task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call)].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call)].*?\n(.*?)$", stdout_text, re.DOTALL)
        if not task_match:
            print("[ERROR] Could not find cluster enumeration task output")
            # Print the first 200 chars of stdout for debugging
            print(f"[DEBUG] First 200 chars of stdout: {stdout_text[:200]}")
            return []
    
    task_output = task_match.group(2)
    
    # Try to extract JSON
    json_match = re.search(r'"clusters"\s*:\s*(\[.*?\])', task_output, re.DOTALL)
    if not json_match:
        # Try to find the clusters JSON in the entire output as a fallback
        json_match = re.search(r'"clusters"\s*:\s*(\[.*?\])', stdout_text, re.DOTALL)
        if not json_match:
            print("[ERROR] Could not extract clusters list from task output")
            # Print part of the task output for debugging
            print(f"[DEBUG] Task output snippet: {task_output[:200]}")
            return []
    
    try:
        clusters_json = json_match.group(1)
        clusters = json.loads(clusters_json)
        return clusters
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse clusters JSON: {e}")
        return []


def get_cluster_by_name(cluster_name):
    """
    Get cluster information by name
    
    Args:
        cluster_name (str): Name of the cluster to find
    
    Returns:
        tuple: (cluster_name, cluster_uid) if found, otherwise (None, None)
    """
    # First enumerate clusters with the name filter
    clusters = enumerate_clusters(name_filter=cluster_name)
    
    if not clusters:
        print(f"[ERROR] No clusters found with name: {cluster_name}")
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
        print(f"[INFO] Using cluster: {cluster_name} with UID: {cluster_uid}")
        return cluster_name, cluster_uid
    
    return None, None


def enumerate_backup_locations(name_filter=None):
    """
    Enumerate backup locations in PX-Backup using Ansible
    
    Args:
        name_filter (str, optional): Filter backup locations by name
    
    Returns:
        list: List of matching backup locations
    """
    print(f"[INFO] Enumerating backup locations with filter: {name_filter}")
    
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
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[DEBUG] Ansible command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        print(f"[ERROR] Failed to enumerate backup locations")
        return []
    
    # Extract backup locations from output
    stdout_text = result.stdout
    
    # Look for the backup locations task output - match various possible task names
    task_match = re.search(r"TASK \[(Enumerate backup locations|Backup Location Enumerate call)].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate backup locations|Backup Location Enumerate call)].*?\n(.*?)$", stdout_text, re.DOTALL)
        if not task_match:
            print("[ERROR] Could not find backup locations task output")
            return []
    
    task_output = task_match.group(2)
    
    # Try to extract JSON
    json_match = re.search(r'"backup_locations"\s*:\s*(\[.*?\])', task_output, re.DOTALL)
    if not json_match:
        # Try to find the backup_locations JSON in the entire output as a fallback
        json_match = re.search(r'"backup_locations"\s*:\s*(\[.*?\])', stdout_text, re.DOTALL)
        if not json_match:
            print("[ERROR] Could not extract backup locations list from task output")
            return []
    
    try:
        locations_json = json_match.group(1)
        locations = json.loads(locations_json)
        return locations
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse backup locations JSON: {e}")
        return []


def get_backup_location_by_name(location_name):
    """
    Get backup location information by name
    
    Args:
        location_name (str): Name of the backup location to find
    
    Returns:
        tuple: (location_name, location_uid) if found, otherwise (None, None)
    """
    # First enumerate backup locations with the name filter
    locations = enumerate_backup_locations(name_filter=location_name)
    
    if not locations:
        print(f"[ERROR] No backup locations found with name: {location_name}")
        return None, None
    
    # Find exact match
    for location in locations:
        if location.get("metadata", {}).get("name") == location_name:
            location_uid = location.get("metadata", {}).get("uid")
            return location_name, location_uid
    
    # If no exact match, use the first one with partial match
    if locations:
        location = locations[0]
        location_name = location.get("metadata", {}).get("name")
        location_uid = location.get("metadata", {}).get("uid")
        print(f"[INFO] Using backup location: {location_name} with UID: {location_uid}")
        return location_name, location_uid
    
    return None, None


def enumerate_schedule_policies(name_filter=None):
    """
    Enumerate schedule policies in PX-Backup using Ansible with improved error handling
    
    Args:
        name_filter (str, optional): Filter schedule policies by name
    
    Returns:
        list: List of matching schedule policies
    """
    print(f"[INFO] Enumerating schedule policies with filter: {name_filter}")
    
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
    print(f"[DEBUG] Ansible command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        print(f"[ERROR] Failed to enumerate schedule policies")
        return []
    
    # Extract schedule policies from output
    stdout_text = result.stdout
    
    # Look for the schedule policies task output - match various possible task names
    task_match = re.search(r"TASK \[(Enumerate schedule policies|Schedule Policy Enumerate call)].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate schedule policies|Schedule Policy Enumerate call)].*?\n(.*?)$", stdout_text, re.DOTALL)
        if not task_match:
            print("[WARNING] Could not find schedule policies task output, trying alternative pattern")
            # Try another pattern - look for schedule_policies in the output anywhere
            json_match = re.search(r'"schedule_policies"\s*:\s*(\[.*?\])', stdout_text, re.DOTALL)
            if json_match:
                try:
                    policies_json = json_match.group(1)
                    policies = json.loads(policies_json)
                    return policies
                except json.JSONDecodeError as e:
                    print(f"[ERROR] Failed to parse schedule policies JSON: {e}")
                    return []
            print("[ERROR] Could not extract schedule policies from output")
            return []
    
    task_output = task_match.group(2)
    
    # Try to extract JSON
    json_match = re.search(r'"schedule_policies"\s*:\s*(\[.*?\])', task_output, re.DOTALL)
    if not json_match:
        # Try to find the schedule_policies JSON in the entire output as a fallback
        json_match = re.search(r'"schedule_policies"\s*:\s*(\[.*?\])', stdout_text, re.DOTALL)
        if not json_match:
            print("[ERROR] Could not extract schedule policies list from task output")
            return []
    
    try:
        policies_json = json_match.group(1)
        policies = json.loads(policies_json)
        return policies
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse schedule policies JSON: {e}")
        return []

def extract_time_from_policy_name(policy_name):
    """
    Extract time from a policy name with format pxb-<vm-name>-sched-policy-HHMMAM/PM
    
    Args:
        policy_name (str): The policy name
    
    Returns:
        datetime or None: The extracted time as a datetime object, or None if extraction fails
    """
    # Extract the time portion (last part after last hyphen)
    parts = policy_name.split('-')
    if len(parts) < 4:
        return None
    
    time_str = parts[-1]
    
    # Try to parse the time string in format like 0602pm
    try:
        # Check if it ends with am or pm (case insensitive)
        if time_str.lower().endswith('am') or time_str.lower().endswith('pm'):
            # Extract hours and minutes
            hours_minutes = time_str[:-2]  # Remove am/pm
            if len(hours_minutes) == 3:  # For formats like 602pm
                hours = int(hours_minutes[0])
                minutes = int(hours_minutes[1:])
            elif len(hours_minutes) == 4:  # For formats like 0602pm or 1045am
                hours = int(hours_minutes[:2])
                minutes = int(hours_minutes[2:])
            else:
                return None
                
            # Adjust hours for PM
            if time_str.lower().endswith('pm') and hours < 12:
                hours += 12
            elif time_str.lower().endswith('am') and hours == 12:
                hours = 0
            
            # Create time object
            return datetime.now().replace(hour=hours, minute=minutes, second=0, microsecond=0)
    except (ValueError, IndexError):
        pass
    
    return None


def find_latest_policy_time(policies):
    """
    Find the latest policy time from a list of policy objects
    
    Args:
        policies (list): List of policy objects
    
    Returns:
        datetime or None: The latest policy time as a datetime object, or None if no valid times found
    """
    latest_time = None
    
    for policy in policies:
        policy_name = policy.get("metadata", {}).get("name", "")
        if "pxb-" in policy_name and "sched-policy" in policy_name:
            time = extract_time_from_policy_name(policy_name)
            if time and (latest_time is None or time > latest_time):
                latest_time = time
    
    return latest_time


def get_vms_with_existing_policies(policies):
    """
    Get VMs that already have policies
    
    Args:
        policies (list): List of policy objects
    
    Returns:
        set: Set of VM names that already have policies
    """
    vms_with_policies = set()
    
    for policy in policies:
        policy_name = policy.get("metadata", {}).get("name", "")
        if "pxb-" in policy_name and "sched-policy" in policy_name:
            # Extract VM name from policy name (format: pxb-<vm-name>-sched-policy-time)
            parts = policy_name.split('-')
            if len(parts) >= 4 and parts[0] == "pxb" and "sched-policy" in policy_name:
                # VM name is everything between "pxb-" and "-sched-policy"
                vm_name_parts = []
                for i in range(1, len(parts)):
                    if parts[i] == "sched-policy":
                        break
                    vm_name_parts.append(parts[i])
                
                vm_name = "-".join(vm_name_parts)
                if vm_name:
                    vms_with_policies.add(vm_name)
    
    return vms_with_policies


def create_schedule_policy(vm_name, policy_time,namespace):
    """
    Creates a schedule policy for a specific VM or returns existing one
    
    Args:
        vm_name (str): VM name
        policy_time (datetime): Time for the policy
        
    Returns:
        tuple: (policy_name, policy_uid) if created/found successfully, otherwise (None, None)
    """
    # Format the time in the required format (e.g., "0602pm")
    formatted_time = policy_time.strftime("%I%M%p").lower().lstrip("0")
    
    # Create a policy name using the new convention
    policy_name = f"pxb-{vm_name}-{namespace}-sched-policy-{formatted_time}"

    # Check if policy already exists before attempting to create it
    existing_policies = enumerate_schedule_policies(name_filter=policy_name)
    for policy in existing_policies:
        if policy.get("metadata", {}).get("name") == policy_name:
            policy_uid = policy.get("metadata", {}).get("uid")
            print(f"[INFO] Policy {policy_name} already exists. Using existing policy.")
            return policy_name, policy_uid

    # Construct extra-vars JSON object
    extra_vars = json.dumps({
        "schedule_policies": [
            {
                "name": policy_name,
                "validate_certs": True,
                "labels": {
                    "policy-label": "test-label"
                },
                "schedule_policy": {
                    "daily": {
                        "time": policy_time.strftime("%I:%M%p").lstrip("0"),
                        "retain": 5,
                        "incremental_count": {
                            "count": 6
                        }
                    }
                }
            }
        ]
    })

    print(f"[INFO] Creating schedule policy: {policy_name} with time {policy_time.strftime('%I:%M%p').lstrip('0')}")
    cmd = [
        "ansible-playbook", "examples/schedule_policy/create.yaml", "-vvvv",
        "--extra-vars", extra_vars
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[DEBUG] Ansible command for policy {policy_name} completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        # Check if the error is due to policy already existing
        if "already exists" in result.stderr or "already exists" in result.stdout:
            print(f"[INFO] Policy {policy_name} appears to already exist. Trying to fetch it directly.")
            # Try to get the policy details again
            retry_policies = enumerate_schedule_policies(name_filter=policy_name)
            for policy in retry_policies:
                if policy.get("metadata", {}).get("name") == policy_name:
                    policy_uid = policy.get("metadata", {}).get("uid")
                    print(f"[INFO] Successfully retrieved existing policy: {policy_name}")
                    return policy_name, policy_uid
        
        print(f"[ERROR] Failed to create schedule policy: {policy_name}")
        return None, None
        
    stdout_text = result.stdout
    if not stdout_text:
        print(f"[ERROR] No output from Ansible playbook for policy {policy_name}.")
        return None, None

    # Locate the "Create schedule policy" task output
    task_match = re.search(r"TASK \[Create schedule policy].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        print(f"[ERROR] Could not find 'Create schedule policy' task output for policy {policy_name}.")
        return None, None
    task_output = task_match.group(1)

    # Extract JSON from the task output
    json_match = re.search(r'(\{.*\})', task_output, re.DOTALL)
    if not json_match:
        print(f"[ERROR] Could not extract JSON from 'Create schedule policy' task output for policy {policy_name}.")
        return None, None
    raw_json = json_match.group(1).strip()

    try:
        decoder = json.JSONDecoder()
        parsed_json, idx = decoder.raw_decode(raw_json)
        print(f"[SUCCESS] Created schedule policy successfully - {policy_name}")
        policy_uid = parsed_json.get("schedule_policy", {}).get("metadata", {}).get("uid")
        return policy_name, policy_uid
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON parsing failed for policy {policy_name}: {str(e)}")
        return None, None

def create_vm_backup_schedule(vm, namespace, policy_name, policy_uid, backup_location_ref, cluster_ref):
    """
    Create a backup schedule for a single VM
    
    Args:
        vm (str): VM name
        namespace (str): VM namespace
        policy_name (str): Policy name
        policy_uid (str): Policy UID
        backup_location_ref (dict): Backup location reference
        cluster_ref (dict): Cluster reference
        
    Returns:
        tuple: (success, backup_name) where success is a boolean indicating if the operation succeeded
    """
    # Extract time from policy name
    time_match = re.search(r'-([0-9]{2,4}[ap]m)$', policy_name)
    time_str = time_match.group(1) if time_match else datetime.now().strftime("%I%M%p").lower().lstrip("0")
    
    # Create backup schedule name
    backup_name = f"pxb-{vm}-sched-backup-{time_str}"
    
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
    
    skip_vm_auto_exec_rules = os.getenv("SKIP_VM_AUTO_EXEC_RULES", "True").lower() == "true"
    
    playbook_data = [{
        "name": "Configure VM Backup Schedule",
        "hosts": "localhost",
        "gather_facts": False,
        "vars": {
            "backup_schedules": [{
                "name": backup_name,
                "backup_location_ref": backup_location_ref,
                "schedule_policy_ref": schedule_policy_ref,
                "cluster_ref": cluster_ref,
                "backup_type": "Normal",
                "backup_object_type": backup_object_type,
                "skip_vm_auto_exec_rules": skip_vm_auto_exec_rules,
                "validate_certs": True,
                "labels": {
                    "vm-name": vm,
                    "vm-namespace": namespace,
                    "created-at": datetime.now().strftime("%Y-%m-%d")
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
    playbook_file = f"create_backup_{vm}_{timestamp}.yaml"
    with open(playbook_file, "w") as f:
        yaml.safe_dump(playbook_data, f, default_flow_style=False)

    print(f"[INFO] Creating backup schedule for VM: {vm} in namespace: {namespace} using policy: {policy_name}")

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
    
    if result.returncode != 0:
        print(f"[ERROR] Failed to create backup schedule for VM: {vm}")
        return False, backup_name

    # Check for success in output
    stdout_text = result.stdout
    
    # Locate the "Create Backup Schedule" task output
    task_match = re.search(r"TASK \[Create Backup Schedule].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        print(f"[ERROR] Could not find 'Create Backup Schedule' task output for VM {vm}.")
        return False, backup_name
    
    # Success
    print(f"[SUCCESS] Created backup schedule for VM: {vm} - {backup_name}")
    return True, backup_name


def create_policies_and_schedules(vm_map, backup_location_name, cluster_name):
    """
    Create policies and backup schedules for VMs
    
    Args:
        vm_map (dict): Dictionary mapping namespaces to lists of VM names
        backup_location_name (str): Name of backup location to use
        cluster_name (str): Name of cluster to use
        
    Returns:
        dict: Results of backup schedule creation with focus on failed schedules
    """
    # Get backup location info
    bl_name, bl_uid = get_backup_location_by_name(backup_location_name)
    if not bl_name or not bl_uid:
        raise ValueError(f"Backup location '{backup_location_name}' not found")
        
    backup_location_ref = {
        "name": bl_name,
        "uid": bl_uid
    }
    
    # Get cluster info
    cl_name, cl_uid = get_cluster_by_name(cluster_name)
    if not cl_name or not cl_uid:
        raise ValueError(f"Cluster '{cluster_name}' not found")
        
    cluster_ref = {
        "name": cl_name,
        "uid": cl_uid
    }
    
    # Enumerate existing policies
    existing_policies = enumerate_schedule_policies(name_filter="pxb")
    
    # Get all VMs that need policies
    all_vms = []
    for namespace, vm_list in vm_map.items():
        for vm in vm_list:
            all_vms.append((vm, namespace))
    
    if not existing_policies:
        # No existing policies, start at 6:00 PM
        print("[INFO] No existing policies found with 'pxb' prefix. Creating new policies starting at 6:00 PM")
        start_time = datetime.now().replace(hour=int(DEFAULT_START_TIME[:2]), minute=int(DEFAULT_START_TIME[2:]), second=0, microsecond=0)
        gap_minutes = GAP_MINUTES
        vms_needing_policies = all_vms
    else:
        # Find VMs that already have policies
        vms_with_policies = get_vms_with_existing_policies(existing_policies)
        
        # Filter VMs that need new policies
        # print(f"[INFO] vm needing policies {vms_needing_policies}")
        vms_needing_policies = [(vm, ns) for vm, ns in all_vms if vm+"-"+ns not in vms_with_policies]
        
        if not vms_needing_policies:
            print("[INFO] All VMs already have policies. No new policies needed.")
            return {
                "total_vms": len(all_vms), 
                "success_count": len(all_vms), 
                "failed_count": 0, 
                "failed_schedules": []
            }
        
        # Find the latest policy time
        latest_time = find_latest_policy_time(existing_policies)
        if latest_time:
            # Start 2 minutes after the latest policy
            start_time = latest_time + timedelta(minutes=2)
            print(f"[INFO] Found latest policy time: {latest_time.strftime('%I:%M%p')}. Starting at: {start_time.strftime('%I:%M%p')}")
        else:
            # Fallback to 6:00 PM if no valid time found
            start_time = datetime.now().replace(hour=int(DEFAULT_START_TIME[:2]), minute=int(DEFAULT_START_TIME[2:]), second=0, microsecond=0)
            print(f"[INFO] Could not determine latest policy time. Starting at default time: {start_time.strftime('%I:%M%p')}")
        
        gap_minutes = GAP_MINUTES
    
    # Prepare results dictionary with focus on failed schedules
    results = {
        "total_vms": len(all_vms),
        "processed_vms": len(vms_needing_policies),
        "success_count": 0,
        "failed_count": 0,
        "failed_schedules": []
    }
    
    print(f"[INFO] Processing {len(vms_needing_policies)} VMs that need policies")
    
    # Create policies and schedules for each VM
    for i, (vm, namespace) in enumerate(vms_needing_policies):
        # Calculate policy time
        policy_time = start_time + timedelta(minutes=i * gap_minutes)
        policy_time_str = policy_time.strftime('%I:%M%p')
        
        # Create policy
        policy_name, policy_uid = create_schedule_policy(vm, policy_time, namespace)
        
        if not policy_name or not policy_uid:
            print(f"[ERROR] Failed to create policy for VM: {vm}")
            results["failed_count"] += 1
            results["failed_schedules"].append({
                "vm": vm,
                "namespace": namespace,
                "policy_time": policy_time_str,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            continue
        
        # Create backup schedule
        success, backup_name = create_vm_backup_schedule(
            vm, namespace, policy_name, policy_uid, backup_location_ref, cluster_ref
        )
        
        # Update results
        if success:
            results["success_count"] += 1
        else:
            results["failed_count"] += 1
            results["failed_schedules"].append({
                "vm": vm,
                "namespace": namespace,
                "backup_name": backup_name,
                "policy_name": policy_name,
                "policy_time": policy_time_str,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
    
    # Print summary
    print(f"\n[SUMMARY] Total VMs: {results['total_vms']}")
    print(f"[SUMMARY] VMs processed: {results['processed_vms']}")
    print(f"[SUMMARY] Successful schedules: {results['success_count']}")
    print(f"[SUMMARY] Failed schedules: {results['failed_count']}")
    
    # Print details of failed schedules
    if results["failed_count"] > 0:
        print("\n[FAILED SCHEDULES]")
        for failed in results["failed_schedules"]:
            print(f"  VM: {failed['vm']} (Namespace: {failed['namespace']})")
            print(f"  Policy Time: {failed['policy_time']}")
            print(f"  Error: {failed['error']} at {failed['timestamp']}")
            print()
    
    return results

def get_cluster_info(cluster_name):
    """
    Get cluster information for the specified cluster name
    
    Args:
        cluster_name (str): Name of the cluster to find
    
    Returns:
        tuple: (cluster_name, cluster_uid)
        
    Raises:
        ValueError: If cluster name is not provided or cluster is not found
    """
    if not cluster_name:
        raise ValueError("Cluster name must be provided")
        
    # Dynamically get cluster info by name
    cluster_name, cluster_uid = get_cluster_by_name(cluster_name)
    if not cluster_name or not cluster_uid:
        raise ValueError(f"Cluster '{cluster_name}' not found")
        
    return cluster_name, cluster_uid


def inspect_cluster(cluster_name, cluster_uid):
    """
    Inspect a cluster and extract its configuration
    
    Args:
        cluster_name (str): The name of the cluster
        cluster_uid (str): The UID of the cluster
        
    Returns:
        str or None: Path to the output file containing cluster data, or None if inspection failed
        
    Raises:
        ValueError: If inspection fails
    """
    print(f"[INFO] Running Ansible playbook for cluster: {cluster_name}, UID: {cluster_uid}")

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

    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[DEBUG] Ansible command completed with return code: {result.returncode}")

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
        print(f"[SUCCESS] Extracted cluster data successfully.")
        return output_file

    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parsing failed: {str(e)}")
        
    return None


def create_kubeconfig(cluster_file):
    """
    Create a kubeconfig file from cluster data
    
    Args:
        cluster_file (str): Path to the cluster data file
        
    Returns:
        str: Path to the created kubeconfig file
        
    Raises:
        ValueError: If kubeconfig cannot be created
    """
    if not cluster_file:
        raise ValueError("No cluster file provided")
        
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

        print(f"[SUCCESS] Created kubeconfig file: {filename}")
        return filename
        
    except (IOError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to process cluster file: {e}")
        
    return None


def get_inventory(kubeconfig_file):
    """
    Get inventory of all VirtualMachine resources in the cluster
    
    Args:
        kubeconfig_file (str): Path to the kubeconfig file
        
    Returns:
        dict: Dictionary mapping namespaces to lists of VM names
    """
    from kubernetes import client, config

    # Load the provided kubeconfig file
    config.load_kube_config(kubeconfig_file)
    # Setup the cert
    configuration = client.Configuration.get_default_copy()
    configuration.ssl_ca_cert = "ca.crt"
    custom_api = client.CustomObjectsApi()

    group = "kubevirt.io"
    version = "v1"
    plural = "virtualmachines"
    vm_map = {}

    try:
        # List all VirtualMachine custom objects across the cluster
        result = custom_api.list_cluster_custom_object(
            group=group,
            version=version,
            plural=plural
        )
        # Iterate over each VirtualMachine and group by namespace
        for item in result.get("items", []):
            metadata = item.get("metadata", {})
            namespace = metadata.get("namespace", "default")
            name = metadata.get("name")
            if namespace and name:
                if namespace not in vm_map:
                    vm_map[namespace] = []
                vm_map[namespace].append(name)
    except Exception as e:
        print(f"Error listing all VirtualMachines: {e}")

    return vm_map


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create backup schedules for virtual machines")
    parser.add_argument("--cluster", required=True, help="Name of the cluster to use (required)")
    parser.add_argument("--backup-location", required=True, help="Name of the backup location to use (required)")
    parser.add_argument("--output", type=str, default="result", help="Output file for backup results")
    parser.add_argument('--gap_minutes', type=int, default=2, help='Gap between schedules in minutes (default 2 min)')
    parser.add_argument('--default_time', type=str, default='1800', help='Default time in HHMM format (default 1800 HOURS)')
    
    args = parser.parse_args()

    GAP_MINUTES = args.gap_minutes
    DEFAULT_START_TIME = args.default_time
    
    try:
        # Get cluster info
        cluster_name, cluster_uid = get_cluster_info(args.cluster)
        
        # Inspect cluster and create kubeconfig
        cluster_file = inspect_cluster(cluster_name, cluster_uid)
        if not cluster_file:
            raise ValueError("Failed to inspect cluster")
            
        kubeconfig_file = create_kubeconfig(cluster_file)
        
        # Get VM inventory
        vm_by_ns = get_inventory(kubeconfig_file)
        
        # Count total VMs
        total_vm_count = sum(len(vms) for vms in vm_by_ns.values())
        print(f"Total VM count: {total_vm_count}")
        
        if total_vm_count == 0:
            raise ValueError("No VMs found in the cluster. Please verify the cluster has virtual machines.")
        
        # Create policies and schedules
        results = create_policies_and_schedules(
            vm_by_ns, 
            args.backup_location, 
            args.cluster
        )
        
        # Save results to file
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
            
        print(f"Results saved to {args.output}")
            
    except ValueError as e:
        print(f"[ERROR] {str(e)}")
        exit(1)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}")
        exit(1)


# -----------------------
    # print("Total VM count in the cluster:", total_vm_count)
# call a func to print summary

    # Create dummy vm_by_ns dictionary
    # vm_by_ns = {
    #     "fed": ["vm-fed"],
    #     "win": ["win2k22-template-1", "vgm-win2k22-mssql-1"]
    # }
# one vm per backup schedule 
# no of backup scheduels per schedule policy

# no of jobs/policy (batch count)
    # TOTAL_NO_POLICY = total_vm_count/NO_VM_PER_BACKUP
    # policy_name_uid = create_schedule_policy_loop("2:15AM", 3, TOTAL_NO_POLICY)
    # print(f"Policy name to UID mapping: {policy_name_uid}")

    # invoke_backup(vm_by_ns, policy_name_uid)

# trigger every backup - based on param
# no of backups per policy
# start time.
# gap time?

# First Run -
# 1. Query the inventory and finds out all the VMs.
# 2. Create a backup job configuration for each individual VMs  
# Name: VM1_Backup_Cfg
# 3. Each VM has its own backup schedule configuration
# Name: VM1_Backup_schedule
# 4. Print out the summary of the total number of backup and the number of total vMs.
