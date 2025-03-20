import argparse
import base64
import json
import re
import subprocess
import time
from typing import Dict, List, Set, Tuple, Optional, Any
import logging
from datetime import datetime
from kubernetes import client, config

import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("vm-schedule-sync")

def get_cluster_info(cluster_name: str) -> Tuple[str, str]:
    """
    Get cluster information for the specified cluster name
    
    Args:
        cluster_name: Name of the cluster to find
    
    Returns:
        Tuple of (cluster_name, cluster_uid)
        
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

def enumerate_clusters(name_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Enumerate clusters in PX-Backup using Ansible
    
    Args:
        name_filter: Optional filter for cluster names
    
    Returns:
        List of matching clusters as dictionaries
    """
    logger.info(f"Enumerating clusters with filter: {name_filter}")
    
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
    logger.debug(f"Ansible command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        logger.error("Failed to enumerate clusters")
        return []
    
    # Extract clusters from output
    stdout_text = result.stdout
    
    # Look for the cluster enumeration task output
    task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call|List All Clusters)].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call|List All Clusters)].*?\n(.*?)$", stdout_text, re.DOTALL)
        if not task_match:
            logger.error("Could not find cluster enumeration task output")
            return []
    
    task_output = task_match.group(2)
    
    # Try to extract JSON
    json_match = re.search(r'"clusters"\s*:\s*(\[.*?\])', task_output, re.DOTALL)
    if not json_match:
        # Try to find the clusters JSON in the entire output as a fallback
        json_match = re.search(r'"clusters"\s*:\s*(\[.*?\])', stdout_text, re.DOTALL)
        if not json_match:
            logger.error("Could not extract clusters list from task output")
            return []
    
    try:
        clusters_json = json_match.group(1)
        clusters = json.loads(clusters_json)
        return clusters
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse clusters JSON: {e}")
        return []

def get_cluster_by_name(cluster_name: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Get cluster information by name
    
    Args:
        cluster_name: Name of the cluster to find
    
    Returns:
        Tuple of (cluster_name, cluster_uid) if found, otherwise (None, None)
    """
    # First enumerate clusters with the name filter
    clusters = enumerate_clusters(name_filter=cluster_name)
    
    if not clusters:
        logger.error(f"No clusters found with name: {cluster_name}")
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
        logger.info(f"Using cluster: {cluster_name} with UID: {cluster_uid}")
        return cluster_name, cluster_uid
    
    return None, None

def inspect_cluster(cluster_name: str, cluster_uid: str) -> Optional[str]:
    """
    Inspect a cluster and extract its configuration
    
    Args:
        cluster_name: The name of the cluster
        cluster_uid: The UID of the cluster
        
    Returns:
        Path to the output file containing cluster data, or None if inspection failed
    """
    logger.info(f"Running Ansible playbook for cluster: {cluster_name}, UID: {cluster_uid}")

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
    logger.debug(f"Ansible command completed with return code: {result.returncode}")

    if result.returncode != 0:
        logger.error(f"Cluster inspection failed with return code {result.returncode}")
        return None

    stdout_text = result.stdout
    if not stdout_text:
        logger.error("No output from Ansible playbook")
        return None

    # Locate the "Get cluster details" task output
    task_match = re.search(r"TASK \[Get cluster details].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        logger.error("Could not find 'Get cluster details' task output")
        return None

    task_output = task_match.group(1)

    # Extract JSON between "cluster" and "clusters"
    json_match = re.search(r'"cluster"\s*:\s*({.*?})\s*,\s*"clusters"', task_output, re.DOTALL)
    if not json_match:
        logger.error("Could not extract JSON between 'cluster' and 'clusters'")
        return None

    raw_json = json_match.group(1)

    # Parse JSON and save to file
    try:
        parsed_json = json.loads(raw_json)
        output_file = f"cluster_data_{cluster_name}.json"
        with open(output_file, "w") as json_file:
            json.dump(parsed_json, json_file, indent=4)
        logger.info(f"Extracted cluster data successfully to {output_file}")
        return output_file

    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing failed: {e}")
        return None

def create_kubeconfig(cluster_file: str) -> Optional[str]:
    """
    Create a kubeconfig file from cluster data
    
    Args:
        cluster_file: Path to the cluster data file
        
    Returns:
        Path to the created kubeconfig file, or None if creation failed
    """
    if not cluster_file:
        logger.error("No cluster file provided")
        return None
        
    try:
        # Load the JSON data from the file
        with open(cluster_file, 'r') as f:
            data = json.load(f)

        # Extract the cluster name from metadata
        cluster_name = data.get("cluster", {}).get("metadata", {}).get("name", "unknown")

        # Extract the base64 encoded kubeconfig text
        kubeconfig_b64 = data.get("cluster", {}).get("clusterInfo", {}).get("kubeconfig", "")

        if not kubeconfig_b64:
            logger.error("No kubeconfig data found in the cluster file")
            return None

        # Decode the base64 encoded kubeconfig
        try:
            kubeconfig_text = base64.b64decode(kubeconfig_b64).decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to decode kubeconfig: {e}")
            return None

        # Define the output filename
        filename = f"{cluster_name}_kubeconfig"

        # Write the decoded kubeconfig text to the file
        with open(filename, "w") as f:
            f.write(kubeconfig_text)

        logger.info(f"Created kubeconfig file: {filename}")
        return filename
        
    except Exception as e:
        logger.error(f"Failed to process cluster file: {e}")
        return None

def get_vm_inventory(kubeconfig_file: str, ns_list: Optional[List[str]] = None):
    # Load the provided kubeconfig file
    config.load_kube_config(kubeconfig_file)
    # Setup the cert
    # configuration = client.Configuration.get_default_copy()
    # configuration.ssl_ca_cert = "ca.crt"
    # api_client = client.ApiClient(configuration)
    custom_api = client.CustomObjectsApi()

    group = "kubevirt.io"
    version = "v1"
    plural = "virtualmachines"
    vm_map = {}


    for ns in ns_list:
        try:
            # List all VirtualMachine custom objects across the cluster
            result = custom_api.list_namespaced_custom_object(
                group=group,
                version=version,
                plural=plural,
                namespace=ns,
            )
            # Iterate over each VirtualMachine and group by namespace
            for item in result.get("items", []):
                metadata = item.get("metadata", {})
                name = metadata.get("name")
                if ns and name:
                    if ns not in vm_map:
                        vm_map[ns] = []
                    vm_map[ns].append(name)
        except Exception as e:
            print(f"Error listing all VirtualMachines: {e}")
    return vm_map

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
    logger.info(f"Enumerating backup schedules for cluster: {cluster_name}")
    
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
    logger.debug(f"Ansible command completed with return code: {result.returncode}")

    if result.returncode != 0:
        logger.error(f"Failed to enumerate backup schedules")
        return []
    
    # Extract schedules from output
    stdout_text = result.stdout
    
    task_name = "List All Backup Schedule"

    # Find the first occurrence of the specified task
    task_start = stdout_text.find(f"TASK [{task_name}]")

    if task_start == -1:
        return f"Error: Could not locate task '{task_name}' in Ansible output."

    # Truncate the output from this task onward
    truncated_output = stdout_text[task_start:]

    # Find the next occurrence of "TASK [" to locate the next task section
    next_task_start = truncated_output.find("TASK [", len(f"TASK [{task_name}]"))

    if next_task_start == -1:
        # If no next task is found, assume this is the last task and take the whole remaining output
        task_section = truncated_output
    else:
        task_section = truncated_output[:next_task_start]

    # Find the JSON block within the extracted task section
    match = re.search(r'ok: \[localhost\] => ({.*})', task_section, re.DOTALL)

    if match:
        json_data = match.group(1).strip()
        try:
            decoder = json.JSONDecoder()
            parsed_json, idx = decoder.raw_decode(json_data)
            return parsed_json.get("backup_schedules", [])
        except json.JSONDecodeError as e:
            return f"Error parsing JSON: {e}"
    else:
        print(f"Error: Could not extract JSON from task '{task_name}'.")
        return []

def extract_vm_schedules(schedules):
    """
    Extract VM IDs from schedules and classify into active and suspended sets
    
    Args:
        schedules: List of backup schedule dictionaries
        
    Returns:
        Tuple containing:
        - Set of active VM IDs in format 'namespace-vmname'
        - Set of suspended VM IDs in format 'namespace-vmname'
        - Dictionary mapping VM IDs to their schedule info objects
    """
    active_ns_vm_schedules = {}
    suspended_ns_vm_schedules = {}
    all_ns_vm_schedules = {}  # Maps VM IDs to their schedule info
    
    for schedule in schedules:
        metadata = schedule.get("metadata", {})
        schedule_name = metadata.get("name", "")
        schedule_uid = metadata.get("uid", "")
        
        # Check if schedule is suspended
        backup_info = schedule.get("backup_schedule_info", {})
        is_suspended = backup_info.get("suspend", False)
        
        # Extract VM information from included resources
        include_resources = backup_info.get("include_resources", [])
        
        for resource in include_resources:
            # Only process KubeVirt VM resources
            if (resource.get("group") == "kubevirt.io" and 
                resource.get("kind") == "VirtualMachine"):
                vm_name = resource.get("name")
                namespace = resource.get("namespace")
                
                if vm_name and namespace:

                    if namespace not in all_ns_vm_schedules:
                        all_ns_vm_schedules[namespace] = {}
                    all_ns_vm_schedules[namespace][vm_name] = schedule
                    # Add to appropriate set
                    if is_suspended:
                        if namespace not in suspended_ns_vm_schedules:
                            suspended_ns_vm_schedules[namespace] = {}
                        suspended_ns_vm_schedules[namespace][vm_name] = schedule
                    else:
                        if namespace not in active_ns_vm_schedules:
                            active_ns_vm_schedules[namespace] = {}
                        active_ns_vm_schedules[namespace][vm_name] = schedule

    # Summaries
    total_entries = sum(len(inner_dict) for inner_dict in all_ns_vm_schedules.values())
    total_active_entries = sum(len(inner_dict) for inner_dict in active_ns_vm_schedules.values())
    total_suspended_entries = sum(len(inner_dict) for inner_dict in suspended_ns_vm_schedules.values())
    logger.info(f"Total schedules: {total_entries}")
    logger.info(f"Found {total_active_entries} VMs with active schedules")
    logger.info(f"Found {total_suspended_entries} VMs with suspended schedules")
    
    return active_ns_vm_schedules, suspended_ns_vm_schedules, all_ns_vm_schedules


def update_schedules(matching_schedules, suspend=False):
    print("[INFO] Updating backup schedules")
    for schedule in matching_schedules:
        backup_name = schedule["metadata"].get("name", "")
        # Create backup schedule name
        schedule_policy_ref = {
            "name": schedule["backup_schedule_info"].get("schedule_policy_ref", {}).get("name", ""),
            "uid": schedule["backup_schedule_info"].get("schedule_policy_ref", {}).get("uid", "")
        }

        vm_namespaces = schedule["backup_schedule_info"].get("namespaces", [])
        include_resources = schedule["backup_schedule_info"].get("include_resources", [])

        # Define backup config
        backup_object_type = {
            "type": "VirtualMachine"
        }

        playbook_data = [{
            "name": "Update VM Backup Schedule",
            "hosts": "localhost",
            "gather_facts": False,
            "vars": {
                "backup_schedules": [{
                    "name": backup_name,
                    "suspend": suspend,
                    "backup_location_ref": schedule["backup_schedule_info"].get("backup_location_ref", {}),
                    "schedule_policy_ref": schedule["backup_schedule_info"].get("schedule_policy_ref", {}),
                    "cluster_ref": schedule["backup_schedule_info"].get("cluster_ref", {}),
                    "backup_type": "Normal",
                    "backup_object_type": backup_object_type,
                    "skip_vm_auto_exec_rules": True,
                    "validate_certs": True,
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
        playbook_file = f"update_backup_{backup_name}_{timestamp}.yaml"
        with open(playbook_file, "w") as f:
            yaml.safe_dump(playbook_data, f, default_flow_style=False)

        print(f"[INFO] Updating backup schedule for {backup_name}")

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
            print(f"[ERROR] Failed to updatw backup schedule for {backup_name}")
            return False, backup_name

        # Check for success in output


        # Locate the "Create Backup Schedule" task output
        task_match = re.search(r"TASK \[Update Backup Schedule].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
        if not task_match:
            print(f"[ERROR] Could not find 'Update Backup Schedule' task output.")
            return False, backup_name

        # Success
        print(f"[SUCCESS] Updated backup schedule for - {backup_name}")
    return


def suspend_schedules(ns_vm_map, active_ns_vm_schedules):
    """
    Suspends schedules for VMs that no longer exist in the cluster.

    Args:
        ns_vm_map (dict): Dictionary of the entire cluster inventory.
                          Keys are namespaces (str) and values are iterables of VM names (str).
                          Example: {
                            "namespace1": ["vm1", "vm2"],
                            "namespace2": ["vmA"]
                          }
        active_ns_vm_schedules (dict): Dictionary of active schedules.
                                       Keys are namespaces (str), values are sub-dictionaries of
                                       { vm_name (str): schedule_object }.
                          Example: {
                            "namespace1": {
                                "vm1": <schedule_obj1>,
                                "vm2": <schedule_obj2>
                            },
                            "namespace2": {
                                "vmA": <schedule_obj3>
                            }
                          }
    Returns:
        list: A list of schedule objects that were suspended.

    """
    to_suspend = []
    suspended_info = {}

    # Iterate over each namespace and VM in active schedules
    for namespace, vm_dict in active_ns_vm_schedules.items():
        for vm_name, schedule_obj in vm_dict.items():
            # Check if this VM still exists in ns_vm_map
            if namespace not in ns_vm_map or vm_name not in ns_vm_map[namespace]:
                # VM no longer exists => schedule needs to be suspended
                to_suspend.append(schedule_obj)
                metadata = schedule_obj.get("metadata", {})
                schedule_name = metadata.get("name", "")
                if namespace not in suspended_info:
                    suspended_info[namespace] = {}
                suspended_info[namespace][vm_name] = schedule_name

    if to_suspend:
        print(f"[INFO] Suspending {len(to_suspend)} schedules for VMs no longer in the cluster")
        # Call your actual suspend function, passing the list of schedule objects
        update_schedules(to_suspend, suspend=True)
    else:
        print("[INFO] No schedules to suspend (all VMs are still present)")

    return suspended_info


def resume_schedules(ns_vm_map, suspended_ns_vm_schedules):
    """
    Resumes schedules for VMs that are currently suspended but have reappeared in the cluster.

    Args:
        ns_vm_map (dict):
            Dictionary of the entire cluster inventory.
            Keys are namespaces (str), values are lists/sets of VM names (str).
            Example:
                {
                    "namespace1": ["vm1", "vm2"],
                    "namespace2": ["vmA"]
                }
        suspended_ns_vm_schedules (dict):
            Dictionary of suspended schedules.
            Keys are namespaces (str), values are dictionaries of { vm_name: schedule_object }.
            Example:
                {
                    "namespace1": {
                        "vm1": {...schedule_obj1...},
                        "vm2": {...schedule_obj2...}
                    },
                    "namespace2": {
                        "vmA": {...schedule_obj3...}
                    }
                }

    Returns:
        dict: resumed_info
            A dictionary where keys are namespaces (str) and values are sub-dictionaries mapping
            vm_name (str) to schedule_name (str) for the resumed schedules. For example:
                {
                    "namespace1": {
                        "vm1": "some-schedule-name",
                        "vm2": "other-schedule-name"
                    },
                    ...
                }
    """
    resumed_info = {}
    to_resume = []

    for namespace, vm_dict in suspended_ns_vm_schedules.items():
        for vm_name, schedule_obj in vm_dict.items():
            # Check if this VM is present in ns_vm_map (i.e., the VM re-appeared in the cluster)
            if namespace in ns_vm_map and vm_name in ns_vm_map[namespace]:
                # Extract schedule name from the schedule object's metadata
                metadata = schedule_obj.get("metadata", {})
                schedule_name = metadata.get("name", "")

                # Record the resumed schedule for reporting
                if namespace not in resumed_info:
                    resumed_info[namespace] = {}
                resumed_info[namespace][vm_name] = schedule_name

                # Collect the schedule object in a list to pass to update_schedules
                to_resume.append(schedule_obj)

    if to_resume:
        print(f"[INFO] Resuming {len(to_resume)} schedules for VMs that reappeared in the cluster")
        # Actually resume them by calling your update function with suspend=False
        update_schedules(to_resume, suspend=False)
    else:
        print("[INFO] No schedules to resume (no suspended VMs re-appeared in the cluster)")

    return resumed_info


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
    print(f"[INFO] Creating backup schedule for {vm} in namespace {namespace}")
    time_match = re.search(r'-([0-9]{2,4}[ap]m)$', policy_name)
    time_str = time_match.group(1) if time_match else datetime.now().strftime("%I%M%p").lower().lstrip("0")

    # Create backup schedule name
    backup_name = f"pxb-{namespace}-{vm}-sched-backup-{time_str}"

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
    playbook_file = f"create_backup_{namespace}_{vm}_{timestamp}.yaml"
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
    stdout_text = result.stdout
    if result.returncode != 0:
        print(f"[ERROR] Failed to create backup schedule for VM: {vm}")
        return False, backup_name

    # Check for success in output


    # Locate the "Create Backup Schedule" task output
    task_match = re.search(r"TASK \[Create Backup Schedule].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        print(f"[ERROR] Could not find 'Create Backup Schedule' task output for VM {vm}.")
        return False, backup_name

    # Success
    print(f"[SUCCESS] Created backup schedule for VM: {vm} - {backup_name}")
    return True, backup_name


def create_schedules(new_vm_map, bl_name, bl_uid,cluster_name, cluster_uid):
    if len(new_vm_map) == 0:
        print("[INFO] No schedules to create")
        return
    schedules_created = {}
    print("[INFO] Creating schedules for ", new_vm_map)
    for ns, vms in new_vm_map.items():
        for vm in vms:
            print(f"[INFO] Creating schedule for VM: {vm} in namespace: {ns}")
            backup_name = create_vm_backup_schedule(vm, ns, "12hr", "3f81933e-4b5b-4c9c-b42a-fae31eb82d58", {"name": bl_name, "uid": bl_uid}, {"name": cluster_name, "uid": cluster_uid})
            schedules_created[f"Namespace -> {ns} / VM Name -> {vm}"] = backup_name
    return schedules_created


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
    task_match = re.search(r"TASK \[(Enumerate backup locations|Backup Location Enumerate call)].*?\n(.*?)\nTASK ",
                           stdout_text, re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate backup locations|Backup Location Enumerate call)].*?\n(.*?)$",
                               stdout_text, re.DOTALL)
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

def get_new_vms(ns_vm_map, all_ns_vm_schedules):
    """
    Identifies newly created VMs (those in the cluster inventory but not present
    in the all_ns_vm_schedules dictionary).

    Args:
        ns_vm_map (dict):
            Dictionary of the entire cluster inventory.
            Keys are namespaces (str), values are lists/sets of VM names (str).
            Example:
                {
                    "namespaceA": ["vm1", "vm2"],
                    "namespaceB": ["vm5", "vm6"]
                }
        all_ns_vm_schedules (dict):
            Dictionary of all VMs that already have schedules.
            Keys are namespaces (str), values are lists/sets of VM names (str).
            Example:
                {
                    "namespaceA": ["vm1", "vm2"],
                    "namespaceB": ["vm5"]
                }

    Returns:
        dict: A dictionary mapping namespace -> list of VM names that are new
              (in the cluster but not in all_ns_vm_schedules).
              Example:
                {
                    "namespaceB": ["vm6"]
                }
              if "vm6" was in the cluster but no schedules existed for it.
    """
    new_vm_map = {}
    for namespace, vm_list in ns_vm_map.items():
        existing_vms = all_ns_vm_schedules.get(namespace, [])
        for vm_name in vm_list:
            if vm_name not in existing_vms:
                if namespace not in new_vm_map:
                    new_vm_map[namespace] = []
                new_vm_map[namespace].append(vm_name)
    return new_vm_map


def print_namespace_vm_schedules(ns_vm_map):
    """
    Prints a nested dictionary in the form:
        namespace -> { vm: schedule_name }

    Example structure:
    {
        "namespace1": { "vm1": "scheduleA", "vm2": "scheduleB" },
        "namespace2": { "vmX": "scheduleC" }
    }
    """
    for namespace, vms in ns_vm_map.items():
        print(namespace)
        for vm, schedule in vms.items():
            metadata = schedule.get("metadata", {})
            schedule_name = metadata.get("name", "")
            print(f"  {vm} => {schedule_name}")


# def generate_report(
#         inventory_map,
#         active_vm_schedules,
#         suspended_vm_schedules,
#         new_vms,
#         suspended_info,
#         resumed_info,
#         newly_created_schedules,
#         report_file_path="vm_protection_report.txt"
# ):
#     """
#     Generates a text-based report of the VM protection operations and writes it to the console
#     and to a file (report_file_path). The report includes:
#       1) Cluster inventory (namespace -> list of VM names)
#       2) Active schedules (namespace -> vm -> schedule_name)
#       3) Suspended schedules (namespace -> vm -> schedule_name)
#       4) Newly created VMs in the cluster (namespace -> list of VM names)
#       5) Summary of actions performed:
#          - Schedules suspended (namespace -> vm -> schedule_name)
#          - Schedules resumed (namespace -> vm -> schedule_name)
#          - Schedules created for new VMs (namespace -> vm -> schedule_name)
#
#     Args:
#         inventory_map (dict):
#             The cluster inventory, namespace -> list of VM names
#         active_vm_schedules (dict):
#             Dictionary of active schedules: { namespace -> { vm_name -> schedule_name } }
#         suspended_vm_schedules (dict):
#             Dictionary of suspended schedules: { namespace -> { vm_name -> schedule_name } }
#         new_vms (dict):
#             Newly created VMs not previously scheduled: { namespace -> list of VM names }
#         suspended_info (dict):
#             Schedules that were suspended: { namespace -> { vm_name -> schedule_name } }
#         resumed_info (dict):
#             Schedules that were resumed: { namespace -> { vm_name -> schedule_name } }
#         newly_created_schedules (dict):
#             Schedules created for new VMs: { namespace -> { vm_name -> schedule_name } }
#         report_file_path (str):
#             File path where the report will be written (default 'vm_protection_report.txt').
#
#     Returns:
#         None
#     """
#     lines = []
#     lines.append("====== VM Protection Management Report ======\n")
#
#     # 1) Print cluster inventory
#     lines.append("Cluster Inventory (namespace -> VMs):\n")
#     for ns, vm_list in inventory_map.items():
#         lines.append(f"{ns}:\n")
#         for vm in vm_list:
#             lines.append(f"  - {vm}\n")
#     lines.append("\n")
#
#     # 2) Print active schedules
#     lines.append("Active Schedules (namespace -> VM -> Schedule name):\n")
#     if active_vm_schedules:
#         for ns, vm_dict in active_vm_schedules.items():
#             lines.append(f"{ns}:\n")
#             for vm, schedule in vm_dict.items():
#                 schedule_metadata = schedule.get("metadata", {})
#                 sched_name = schedule_metadata.get("name", "")
#                 lines.append(f"  {vm} -> {sched_name}\n")
#     else:
#         lines.append("  (None)\n")
#     lines.append("\n")
#
#     # 3) Print suspended schedules
#     lines.append("Suspended Schedules (namespace -> VM -> Schedule name):\n")
#     if suspended_vm_schedules:
#         for ns, vm_dict in suspended_vm_schedules.items():
#             lines.append(f"{ns}:\n")
#             for vm, schedule in vm_dict.items():
#                 schedule_metadata = schedule.get("metadata", {})
#                 sched_name = schedule_metadata.get("name", "")
#                 lines.append(f"  {vm} -> {sched_name}\n")
#     else:
#         lines.append("  (None)\n")
#     lines.append("\n")
#
#     # 4) Print newly created VMs
#     lines.append("Newly Created VMs (namespace -> VMs):\n")
#     if new_vms:
#         for ns, vm_list in new_vms.items():
#             lines.append(f"{ns}:\n")
#             for vm in vm_list:
#                 lines.append(f"  - {vm}\n")
#     else:
#         lines.append("  (None)\n")
#     lines.append("\n")
#
#     # 5) Summary of actions performed
#     lines.append("Summary of Actions Performed:\n")
#
#     # a) Schedules suspended
#     lines.append("  - Schedules Suspended:\n")
#     if suspended_info:
#         for ns, vm_dict in suspended_info.items():
#             lines.append(f"    {ns}:\n")
#             for vm, schedule in vm_dict.items():
#                 schedule_metadata = schedule.get("metadata", {})
#                 sched_name = schedule_metadata.get("name", "")
#                 lines.append(f"      {vm} -> {sched_name}\n")
#     else:
#         lines.append("    (None)\n")
#
#     # b) Schedules resumed
#     lines.append("  - Schedules Resumed:\n")
#     if resumed_info:
#         for ns, vm_dict in resumed_info.items():
#             lines.append(f"    {ns}:\n")
#             for vm, schedule in vm_dict.items():
#                 schedule_metadata = schedule.get("metadata", {})
#                 sched_name = schedule_metadata.get("name", "")
#                 lines.append(f"      {vm} -> {sched_name}\n")
#     else:
#         lines.append("    (None)\n")
#
#     # c) New schedules created
#     lines.append("  - New Schedules Created:\n")
#     if newly_created_schedules:
#         for ns, vm_dict in newly_created_schedules.items():
#             lines.append(f"    {ns}:\n")
#             for vm, schedule in vm_dict.items():
#                 schedule_metadata = schedule.get("metadata", {})
#                 sched_name = schedule_metadata.get("name", "")
#                 lines.append(f"      {vm} -> {sched_name}\n")
#     else:
#         lines.append("    (None)\n")
#
#     # Join lines into a single report string
#     report_str = "".join(lines)
#
#     # Print to console
#     print(report_str)
#
#     # Write to file
#     with open(report_file_path, "w") as f:
#         f.write(report_str)

def generate_report(
        inventory_map,
        active_vm_schedules,
        suspended_vm_schedules,
        new_vms,
        suspended_info,
        resumed_info,
        newly_created_schedules,
        report_file_path="vm_protection_report.txt"
):
    """
    Generates a text-based report of the VM protection operations and writes it to the console
    and to a file (report_file_path). The report includes:
      1) Cluster inventory (namespace -> list of VM names)
      2) Active schedules (namespace -> vm -> schedule_name)
      3) Suspended schedules (namespace -> vm -> schedule_name)
      4) Newly created VMs in the cluster (namespace -> list of VM names)
      5) Summary of actions performed:
         - Schedules suspended (namespace -> vm -> schedule_name)
         - Schedules resumed (namespace -> vm -> schedule_name)
         - Schedules created for new VMs (namespace -> vm -> schedule_name)

    Args:
        inventory_map (dict):
            The cluster inventory, namespace -> list of VM names
        active_vm_schedules (dict):
            Dictionary of active schedules: { namespace -> { vm_name -> schedule_name } }
        suspended_vm_schedules (dict):
            Dictionary of suspended schedules: { namespace -> { vm_name -> schedule_name } }
        new_vms (dict):
            Newly created VMs not previously scheduled: { namespace -> list of VM names }
        suspended_info (dict):
            Schedules that were suspended: { namespace -> { vm_name -> schedule_name } }
        resumed_info (dict):
            Schedules that were resumed: { namespace -> { vm_name -> schedule_name } }
        newly_created_schedules (dict):
            Schedules created for new VMs: { namespace -> { vm_name -> schedule_name } }
        report_file_path (str):
            File path where the report will be written (default 'vm_protection_report.txt').

    Returns:
        None
    """
    lines = []
    lines.append("====== VM Protection Management Report ======\n")
    lines.append("------------------------------------------------------\n")

    # 1) Print cluster inventory
    lines.append("Cluster Inventory (namespace -> list of VM names):\n")
    lines.append("--------------------------------------------------\n")
    for ns, vm_list in inventory_map.items():
        lines.append(f"{ns}:\n")
        for vm in vm_list:
            lines.append(f"  - {vm}\n")
    lines.append("\n")

    # 2) Print active schedules
    lines.append("Active Schedules (namespace -> VM -> Schedule name):\n")
    lines.append("--------------------------------------------------\n")
    if active_vm_schedules:
        for ns, vm_dict in active_vm_schedules.items():
            lines.append(f"{ns}:\n")
            for vm, schedule in vm_dict.items():
                lines.append(f"  {vm} -> {schedule}\n")
    else:
        lines.append("  (None)\n")
    lines.append("\n")

    # 3) Print suspended schedules
    lines.append("Suspended Schedules (namespace -> VM -> Schedule name):\n")
    lines.append("--------------------------------------------------\n")
    if suspended_vm_schedules:
        for ns, vm_dict in suspended_vm_schedules.items():
            lines.append(f"{ns}:\n")
            for vm, schedule in vm_dict.items():
                lines.append(f"  {vm} -> {schedule}\n")
    else:
        lines.append("  (None)\n")
    lines.append("\n")

    # 4) Print newly created VMs
    lines.append("Newly Created VMs (namespace -> VMs):\n")
    lines.append("--------------------------------------------------\n")
    if new_vms:
        for ns, vm_list in new_vms.items():
            lines.append(f"{ns}:\n")
            for vm in vm_list:
                lines.append(f"  - {vm}\n")
    else:
        lines.append("  (None)\n")
    lines.append("\n")

    # 5) Summary of actions performed
    lines.append("Summary of Actions Performed:\n")
    lines.append("--------------------------------------------------\n")

    # a) Schedules suspended
    lines.append("  - Schedules Suspended:\n")
    if suspended_info:
        for ns, vm_dict in suspended_info.items():
            lines.append(f"    {ns}:\n")
            for vm, schedule in vm_dict.items():
                lines.append(f"      {vm} -> {schedule}\n")
    else:
        lines.append("    (None)\n")

    # b) Schedules resumed
    lines.append("  - Schedules Resumed:\n")
    if resumed_info:
        for ns, vm_dict in resumed_info.items():
            lines.append(f"    {ns}:\n")
            for vm, schedule in vm_dict.items():
                lines.append(f"      {vm} -> {schedule}\n")
    else:
        lines.append("    (None)\n")

    # c) New schedules created
    lines.append("  - New Schedules Created:\n")
    if newly_created_schedules:
        for ns, vm_dict in newly_created_schedules.items():
            lines.append(f"    {ns}:\n")
            for vm, schedule in vm_dict.items():
                lines.append(f"      {vm} -> {schedule}\n")
    else:
        lines.append("    (None)\n")

    # Join lines into a single report string
    report_str = "".join(lines)

    # Print to console
    print(report_str)

    # Write to file
    with open(report_file_path, "w") as f:
        f.write(report_str)

def main():
    parser = argparse.ArgumentParser(description="Synchronize VM backup schedules with current VM inventory")
    parser.add_argument("--cluster", required=True, help="Name of the cluster to use")
    parser.add_argument("--namespaces", nargs="+", help="List of namespaces to check (if not specified, checks all namespaces)")
    parser.add_argument("--backup-location", required=True, help="Name of the backup location to use (required)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--output-file", help="Write results to file")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        backup_location_name = args.backup_location
        bl_name, bl_uid = get_backup_location_by_name(backup_location_name)
        # Get cluster info
        cluster_name, cluster_uid = get_cluster_info(args.cluster)
        logger.info(f"Using cluster: {cluster_name} (UID: {cluster_uid})")
        
        # Inspect cluster and create kubeconfig
        cluster_file = inspect_cluster(cluster_name, cluster_uid)
        if not cluster_file:
            raise ValueError("Failed to inspect cluster")
            
        kubeconfig_file = create_kubeconfig(cluster_file)
        if not kubeconfig_file:
            raise ValueError("Failed to create kubeconfig")
        
        # Get VM inventory
        ns_list = ["vikas1", "vikas2", "win", "win2", "win3", "win4"]
        ns_list = list(set(ns_list))

        ns_vm_map = get_vm_inventory(kubeconfig_file, ns_list)
        total_count = sum(len(v) for v in ns_vm_map.values())
        logger.info(f"Found {total_count} VMs in current inventory")
        
        # Get backup schedules
        schedules = enumerate_backup_schedules(cluster_name, cluster_uid)
        logger.info(f"Found {len(schedules)} backup schedules")
        
        # Extract VM information from schedules
        active_ns_vm_schedules, suspended_ns_vm_schedules, all_ns_vm_schedules = extract_vm_schedules(schedules)
        print_namespace_vm_schedules(active_ns_vm_schedules)
        print_namespace_vm_schedules(suspended_ns_vm_schedules)
        print_namespace_vm_schedules(all_ns_vm_schedules)

        suspended_info = suspend_schedules(ns_vm_map, active_ns_vm_schedules)
        print(suspended_info)


        # VMs to add (in inventory but no active schedule)
        resumed_info = resume_schedules(ns_vm_map, suspended_ns_vm_schedules)
        print(resumed_info)


        new_vm_map = get_new_vms(ns_vm_map, all_ns_vm_schedules)
        schedules_created = create_schedules(new_vm_map, bl_name, bl_uid, cluster_name, cluster_uid)
        print(schedules_created)

        generate_report(
            ns_vm_map,
            active_ns_vm_schedules,
            suspended_ns_vm_schedules,
            new_vm_map,
            suspended_info,
            resumed_info,
            schedules_created,
            report_file_path="vm_protection_report.txt"
        )

    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    exit(main())