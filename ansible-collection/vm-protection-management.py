import argparse
import base64
import json
import logging
import re
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

import yaml
from kubernetes import client, config

# Configure logging
timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
LOG_FILE = f"vm-protection-management_{timestamp}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ]
)


def create_vm_backup_schedule(vm, namespace, policy_name, policy_uid, backup_location_ref, cluster_ref, csi_driver_map,
                              dry_run=False):
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

    # Create backup schedule name
    backup_name = f"pxb-{namespace}-{vm}-{policy_name}"

    if dry_run:
        logging.debug(
            f"[DRY RUN] Would create backup schedule: {backup_name} for VM {vm} in namespace {namespace} using policy {policy_name}")
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
                    "created-at": datetime.now().strftime("%Y-%m-%d")
                },
                "advanced_resource_label_selector": ""
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
    logging.info(f"Enumerating clusters with filter: {name_filter}")
    
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
    logging.debug(f"Ansible command completed with return code: {result.returncode}")
    
    if result.returncode != 0:
        logging.error("Failed to enumerate clusters")
        return []
    
    # Extract clusters from output
    stdout_text = result.stdout
    
    # Look for the cluster enumeration task output
    task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call|List All Clusters)].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call|List All Clusters)].*?\n(.*?)$", stdout_text, re.DOTALL)
        if not task_match:
            logging.error("Could not find cluster enumeration task output")
            return []
    
    task_output = task_match.group(2)
    logging.info(f"Enumerated clusters: {task_output}")
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    task_output_clean = ansi_escape.sub('', task_output)
    stdout_text_clean = ansi_escape.sub('', stdout_text)

    # Regex to capture the "clusters": [ ... ] block (non-greedy)
    pattern = r'"clusters"\s*:\s*(\[[\s\S]*?\])'
    
    # Try to extract JSON
    json_match = re.search(pattern, task_output_clean, re.DOTALL)
    if not json_match:
        # Try to find the clusters JSON in the entire output as a fallback
        json_match = re.search(r'"clusters"\s*:\s*(\[[\s\S]*?\])', stdout_text_clean, re.DOTALL)
        if not json_match:
            logging.error("Could not extract clusters list from task output")
            return []
    
    try:
        clusters_json = json_match.group(1)
        clusters = json.loads(clusters_json)
        return clusters
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse clusters JSON: {e}")
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

def inspect_cluster(cluster_name: str, cluster_uid: str) -> Optional[str]:
    """
    Inspect a cluster and extract its configuration
    
    Args:
        cluster_name: The name of the cluster
        cluster_uid: The UID of the cluster
        
    Returns:
        Path to the output file containing cluster data, or None if inspection failed
    """
    logging.info(f"Running Ansible playbook for cluster: {cluster_name}, UID: {cluster_uid}")

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
    logging.debug(f"Ansible command completed with return code: {result.returncode}")

    if result.returncode != 0:
        logging.error(f"Cluster inspection failed with return code {result.returncode}")
        return None

    stdout_text = result.stdout
    if not stdout_text:
        logging.error("No output from Ansible playbook")
        return None

    # Locate the "Get cluster details" task output
    task_match = re.search(r"TASK \[Get cluster details].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        logging.error("Could not find 'Get cluster details' task output")
        return None

    task_output = task_match.group(1)

    # Extract JSON between "cluster" and "clusters"
    json_match = re.search(r'"cluster"\s*:\s*({.*?})\s*,\s*"clusters"', task_output, re.DOTALL)
    if not json_match:
        logging.error("Could not extract JSON between 'cluster' and 'clusters'")
        return None

    raw_json = json_match.group(1)

    # Parse JSON and save to file
    try:
        parsed_json = json.loads(raw_json)
        output_file = f"cluster_data_{cluster_name}.json"
        with open(output_file, "w") as json_file:
            json.dump(parsed_json, json_file, indent=4)
        logging.info(f"Extracted cluster data successfully to {output_file}")
        return output_file

    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing failed: {e}")
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
        logging.error("No cluster file provided")
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
            logging.error("No kubeconfig data found in the cluster file")
            return None

        # Decode the base64 encoded kubeconfig
        try:
            kubeconfig_text = base64.b64decode(kubeconfig_b64).decode("utf-8")
        except Exception as e:
            logging.error(f"Failed to decode kubeconfig: {e}")
            exit(1)

        # Define the output filename
        filename = f"{cluster_name}_kubeconfig"

        # Write the decoded kubeconfig text to the file
        with open(filename, "w") as f:
            f.write(kubeconfig_text)

        logging.info(f"Created kubeconfig file: {filename}")
        return filename
        
    except Exception as e:
        logging.error(f"Failed to process cluster file: {e}")
        exit(1)

def get_vm_inventory(kubeconfig_file: str, ns_list: Optional[List[str]] = None, label_selector=None):
    # Load the provided kubeconfig file
    config.load_kube_config(kubeconfig_file)
    # Setup the cert
    configuration = client.Configuration.get_default_copy()
    configuration.ssl_ca_cert = "ca.crt"
    api_client = client.ApiClient(configuration)
    custom_api = client.CustomObjectsApi(api_client)

    group = "kubevirt.io"
    version = "v1"
    plural = "virtualmachines"
    vm_map = {}

    if ns_list:
        for ns in ns_list:
            try:
                # List all VirtualMachine custom objects across the cluster
                result = custom_api.list_namespaced_custom_object(
                    group=group,
                    version=version,
                    plural=plural,
                    namespace=ns,
                    label_selector=label_selector,
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
                exit(1)
    else:
        try:
            # List all VirtualMachine custom objects across the cluster
            result = custom_api.list_cluster_custom_object(
                group=group,
                version=version,
                plural=plural,
                label_selector=label_selector,
            )
            # Iterate over each VirtualMachine and group by namespace
            for item in result.get("items", []):
                metadata = item.get("metadata", {})
                namespace = metadata.get("namespace")
                name = metadata.get("name")
                if namespace and name:
                    if namespace not in vm_map:
                        vm_map[namespace] = []
                    vm_map[namespace].append(name)
        except Exception as e:
            logging.error(f"Error listing all VirtualMachines: {e}")
            exit(1)
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
        logging.error(f"Could not extract JSON from task '{task_name}'.")
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
    logging.info(f"Total schedules: {total_entries}")
    logging.info(f"Found {total_active_entries} VMs with active schedules")
    logging.info(f"Found {total_suspended_entries} VMs with suspended schedules")
    
    return active_ns_vm_schedules, suspended_ns_vm_schedules, all_ns_vm_schedules


def update_schedules(matching_schedules, suspend=False):
    logging.info("Updating backup schedules")
    for schedule in matching_schedules:
        backup_name = schedule["metadata"].get("name", "")
        # Create backup schedule name

        vm_namespaces = schedule["backup_schedule_info"].get("namespaces", [])
        include_resources = schedule["backup_schedule_info"].get("include_resources", [])

        # Define backup config
        backup_object_type = {
            "type": "VirtualMachine"
        }

        # Extract and preserve the original volume_snapshot_class_mapping
        volume_snapshot_class_mapping = schedule["backup_schedule_info"].get("volume_snapshot_class_mapping", {})
        if volume_snapshot_class_mapping:
            logging.info(f"Preserving original volume_snapshot_class_mapping for schedule {backup_name}: {volume_snapshot_class_mapping}")
        else:
            logging.info(f"No volume_snapshot_class_mapping found in original schedule {backup_name}")

        playbook_data = [{
            "name": "Update VM Backup Schedule",
            "hosts": "localhost",
            "gather_facts": False,
            "vars": {
                "backup_schedules": [{
                    "name": backup_name,
                    "suspend": suspend,
                    "volume_snapshot_class_mapping": volume_snapshot_class_mapping,
                    "backup_location_ref": schedule["backup_schedule_info"].get("backup_location_ref", {}),
                    "schedule_policy_ref": schedule["backup_schedule_info"].get("schedule_policy_ref", {}),
                    "cluster_ref": schedule["backup_schedule_info"].get("cluster_ref", {}),
                    "backup_type": "Normal",
                    "backup_object_type": backup_object_type,
                    "skip_vm_auto_exec_rules": True,
                    "validate_certs": True,
                    "remark":"Schedule updated by script(vm-protection-management)",
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

        logging.info(f"Updating backup schedule for {backup_name}")

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
            logging.error(f"Failed to updatw backup schedule for {backup_name}")
            return False, backup_name

        # Check for success in output


        # Locate the "Create Backup Schedule" task output
        task_match = re.search(r"TASK \[Update Backup Schedule].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
        if not task_match:
            logging.error(f"Could not find 'Update Backup Schedule' task output.")
            return False, backup_name

        # Success
        logging.info(f"Updated backup schedule for - {backup_name}")
    return


def suspend_schedules(ns_vm_map, active_ns_vm_schedules, dry_run=False):
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

    if not dry_run:
        if to_suspend:
            logging.info(f"Suspending {len(to_suspend)} schedules for VMs no longer in the cluster")
            # Call your actual suspend function, passing the list of schedule objects
            update_schedules(to_suspend, suspend=True)
        else:
            logging.info("No schedules to suspend (all VMs are still present)")

    return suspended_info


def resume_schedules(ns_vm_map, suspended_ns_vm_schedules, dry_run=False):
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
    if not dry_run:
        if to_resume:
            logging.info(f"Resuming {len(to_resume)} schedules for VMs that reappeared in the cluster")
            # Actually resume them by calling your update function with suspend=False
            update_schedules(to_resume, suspend=False)
        else:
            logging.info("No schedules to resume (no suspended VMs re-appeared in the cluster)")

    return resumed_info

def get_backup_location_by_name(location_name):
    """
    Get backup location information by name

    Args:
        location_name (str): Name of the backup location to find

    Returns:
        tuple: (location_name, location_uid) if found, otherwise (None, None)
    """
    # First enumerate backup locations with the name filter
    enumerate_response = enumerate_backup_locations(name_filter=location_name)
    locations = enumerate_response.get("backup_locations", [])
    print(f"Enumerated backup locations: {locations}")

    if not locations:
        logging.error(f"No backup locations found with name: {location_name}")
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
        logging.info(f"Using backup location: {location_name} with UID: {location_uid}")
        return location_name, location_uid

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
        print(f"\n{namespace}")
        for vm, schedule in vms.items():
            metadata = schedule.get("metadata", {})
            schedule_name = metadata.get("name", "")
            print(f"  {vm} => {schedule_name}")


def print_new_vm_schedules(ns_vm_map):
    for namespace, vms in ns_vm_map.items():
        print(f"\n{namespace}")
        for vm in vms:
            print(f"  {vm}")


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

    # Look for the schedule policies task output - match various possible task names
    task_match = re.search(r"TASK \[(Enumerate schedule policies|Schedule Policy Enumerate call)].*?\n(.*?)\nTASK ",
                           stdout_text, re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate schedule policies|Schedule Policy Enumerate call)].*?\n(.*?)$",
                               stdout_text, re.DOTALL)
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


def get_filtered_schedule_policies():
    import re
    matched_policies = {}
    pattern = re.compile(r"^pxb-(\d{4})$")
    existing_policies = enumerate_schedule_policies()

    for policy in existing_policies:
        policy_name = policy.get("metadata", {}).get("name", "")
        policy_uid = policy.get("metadata", {}).get("uid", "")
        match = pattern.match(policy_name)
        if match:
            number_str = match.group(1)  # This group(1) is the 4-digit part
            number_val = int(number_str)
            if 0 <= number_val <= 2359:
                logging.info(f"Policy {policy_name} was created by the setup script."
                      f" Will not be used for VM schedule distribution")
                matched_policies[policy_name] = policy_uid
        else:
            logging.info(f"Policy {policy_name} was not created by the setup script. Will not be used")
    return matched_policies


def distribute_vms_schedules(new_vms_map, policy_dict, backup_location_ref, cluster_ref, csi_driver_map):
    """
    Distributes newly created VMs among the given policies, where each policy first gets
    floor(total_vms / num_policies) VMs, then the leftover VMs are assigned one-by-one
    to each policy in order until no leftovers remain.

    In this version, `policy_dict` is a dictionary mapping policy_name -> policy_uid.
    The returned distribution maps each policy_name to:
      {
        "policy_uid": <uid>,
        "vms": [ (namespace, vm_name), ... ]
      }

    For example, if total VMs = 14 and policy_dict has 4 entries, each policy gets 3 VMs
    (base_count = 3). Leftover = 2 => the first two policies get 1 additional VM each.

    Args:
        new_vms_map (dict):
            e.g. {
              "ns1": ["vm1", "vm2"],
              "ns2": ["vm3", "vm4"]
            }
        policy_dict (dict):
            Dictionary mapping policy_name -> policy_uid.
            e.g. {
              "policyA": "uidA",
              "policyB": "uidB",
              ...
            }

    Returns:
        dict:
            { policy_name:
                {
                  "policy_uid": <uid>,
                  "vms": [ (namespace, vm_name), ... ]
                }
            }
    """
    # 1) Flatten all VMs into a list of (namespace, vm_name) tuples
    all_vms = []
    if len(new_vms_map) == 0:
        logging.info("No schedules to create")
        return {}, {}

    for ns, vm_list in new_vms_map.items():
        for vm_name in vm_list:
            all_vms.append((ns, vm_name))

    # Prepare result distribution: each policy_name => { "policy_uid": ..., "vms": ... }
    distribution = {}
    for p_name, p_uid in policy_dict.items():
        distribution[p_name] = {
            "policy_uid": p_uid,
            "vms": []
        }

    if not all_vms or not policy_dict:
        return distribution

    total_vms = len(all_vms)
    policy_names = list(policy_dict.keys())  # preserve dict order
    num_policies = len(policy_names)

    # 2) Determine base_count and leftover
    base_count = total_vms // num_policies
    leftover = total_vms % num_policies

    # 3) Assign base_count to each policy in order
    start_idx = 0
    for p_name in policy_names:
        end_idx = start_idx + base_count
        distribution[p_name]["vms"].extend(all_vms[start_idx:end_idx])
        start_idx = end_idx

    # 4) Distribute leftover VMs one by one to each policy in order
    for i in range(leftover):
        policy_name = policy_names[i]
        distribution[policy_name]["vms"].append(all_vms[start_idx])
        start_idx += 1
    schedules_created = {}
    for p_name, data in distribution.items():
        for namespace, vm_name in data["vms"]:
            success, backup_schedule_name = create_vm_backup_schedule(vm_name, namespace, p_name, data["policy_uid"],
                                                                      backup_location_ref, cluster_ref,
                                                                      csi_driver_map)
            if success:
                if namespace not in schedules_created:
                    schedules_created[namespace] = {}
                schedules_created[namespace][vm_name] = backup_schedule_name

    return distribution, schedules_created

def parse_input_map(map_str):
    result = {}
    if map_str:
        for pair in map_str.split(','):
            if ':' not in pair:
                raise ValueError(f"Invalid pair format: {pair}")
            key, value = pair.split(':', 1)
            result[key.strip()] = value.strip()
    return result

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
    lines.append("\nCluster Inventory (namespace -> list of VM names):\n")
    lines.append("--------------------------------------------------\n")
    for ns, vm_list in inventory_map.items():
        lines.append(f"{ns}:\n")
        for vm in vm_list:
            lines.append(f"  - {vm}\n")
    lines.append("\n")

    # 2) Print active schedules
    lines.append("\nActive Schedules (namespace -> VM -> Schedule name):\n")
    lines.append("--------------------------------------------------\n")
    if active_vm_schedules:
        for ns, vm_dict in active_vm_schedules.items():
            lines.append(f"{ns}:\n")
            for vm, schedule in vm_dict.items():
                # Extract metadata.name from the schedule dictionary
                schedule_name = schedule.get('metadata', {}).get('name', '(Unknown)')
                lines.append(f"  {vm} -> {schedule_name}\n")
    else:
        lines.append("  (None)\n")
    lines.append("\n")

    # 3) Print suspended schedules
    lines.append("\nSuspended Schedules (namespace -> VM -> Schedule name):\n")
    lines.append("--------------------------------------------------\n")
    if suspended_vm_schedules:
        for ns, vm_dict in suspended_vm_schedules.items():
            lines.append(f"{ns}:\n")
            for vm, schedule in vm_dict.items():
                schedule_name = schedule.get('metadata', {}).get('name', '(Unknown)')
                lines.append(f"  {vm} -> {schedule_name}\n")
    else:
        lines.append("  (None)\n")
    lines.append("\n")


    # 4) Print newly created VMs
    lines.append("\nNewly Created VMs (namespace -> VMs):\n")
    lines.append("--------------------------------------------------\n")
    if new_vms:
        for ns, vm_list in new_vms.items():
            lines.append(f"{ns}:\n")
            for vm in vm_list:
                lines.append(f"  - {vm}\n")
    else:
        lines.append("  (None)\n")
    lines.append("\n")

    # Print Deleted VMs from suspended schedules
    lines.append("\nDeleted VMs (namespace -> VMs):\n")
    lines.append("--------------------------------------------------\n")
    if suspended_info:
        for ns, vm_dict in suspended_info.items():
            lines.append(f"{ns}:\n")
            for vm, schedule in vm_dict.items():
                lines.append(f"  {vm}\n")

    # 5) Summary of actions performed
    lines.append("\n\nSummary of Actions Performed:\n")
    lines.append("--------------------------------------------------\n")

    # a) Schedules suspended
    lines.append("\n  - Schedules Suspended:\n")
    if suspended_info:
        for ns, vm_dict in suspended_info.items():
            lines.append(f"    {ns}:\n")
            for vm, schedule in vm_dict.items():
                lines.append(f"      {vm} -> {schedule}\n")
    else:
        lines.append("    (None)\n")

    # b) Schedules resumed
    lines.append("\n  - Schedules Resumed:\n")
    if resumed_info:
        for ns, vm_dict in resumed_info.items():
            lines.append(f"    {ns}:\n")
            for vm, schedule in vm_dict.items():
                lines.append(f"      {vm} -> {schedule}\n")
    else:
        lines.append("    (None)\n")

    # c) New schedules created
    lines.append("\n  - New Schedules Created:\n")
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
    logging.info(report_str)

    # Write to file
    with open(report_file_path, "w") as f:
        f.write(report_str)


def print_info(info):
    if info:
        for ns, vm_dict in info.items():
            print(f"\n{ns}:")
            for vm, schedule in vm_dict.items():
                print(f"      {vm} -> {schedule}")
    else:
        print("    (None)\n")


def main():
    parser = argparse.ArgumentParser(description="Synchronize VM backup schedules with current VM inventory")
    parser.add_argument("--cluster-name", required=True, help="Name of the cluster to use")
    parser.add_argument("--cluster-uid", required=True, help="UID of the cluster to use")
    parser.add_argument("--namespaces", nargs="+",
                        help="List of namespaces to check (if not specified, checks all namespaces)")
    parser.add_argument("--backup-location", required=True, help="Name of the backup location to use (required)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--dry-run", action="store_true", help="Dry run to list the vm list")
    parser.add_argument('--csiDriver_map', "-d", type=str, help='Map input in the form csiDriver1:VSC1,csiDriver2:VSC2')
    parser.add_argument("--label-selector", help="Kubernetes label selector string, e.g., 'env=prod,app!=myapp'")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    print(f"Logs are getting captured at {LOG_FILE}")

    try:
        report_file_name = f"vm-protection-report-{timestamp}.txt"
        backup_location_name = args.backup_location
        cluster_name = args.cluster_name
        cluster_uid = args.cluster_uid
        bl_name, bl_uid = get_backup_location_by_name(backup_location_name)
        # Get cluster info

        logging.info(f"Using cluster: {cluster_name} (UID: {cluster_uid})")
        
        # Inspect cluster and create kubeconfig
        cluster_file = inspect_cluster(cluster_name, cluster_uid)
        if not cluster_file:
            raise ValueError("Failed to inspect cluster")
            
        kubeconfig_file = create_kubeconfig(cluster_file)
        if not kubeconfig_file:
            raise ValueError("Failed to create kubeconfig")

        # Get schedule policies created
        matched_policies = get_filtered_schedule_policies()
        logging.info(f"Found {len(matched_policies)} policies to use")
        logging.info(f"Policies to use: {matched_policies}")

        # Get VM inventory
        ns_list = args.namespaces
        if ns_list is None:
            logging.info("No namespace list provided. Will act on all namespaces in the cluster")
        else:
            logging.info(f"Namespaces to check: {ns_list}")

        ns_vm_map = get_vm_inventory(kubeconfig_file, ns_list, args.label_selector)
        total_count = sum(len(v) for v in ns_vm_map.values())
        logging.info(f"Found {total_count} VMs in current inventory")
        
        # Get backup schedules
        schedules = enumerate_backup_schedules(cluster_name, cluster_uid)
        logging.info(f"Found {len(schedules)} backup schedules")
        
        # Extract VM information from schedules
        active_ns_vm_schedules, suspended_ns_vm_schedules, all_ns_vm_schedules = extract_vm_schedules(schedules)
        new_vm_map = get_new_vms(ns_vm_map, all_ns_vm_schedules)

        logging.info("Active vm schedules:")
        print_namespace_vm_schedules(active_ns_vm_schedules)

        logging.info("Suspended vm schedules:")
        print_namespace_vm_schedules(suspended_ns_vm_schedules)

        logging.info("All vm schedules:")
        print_namespace_vm_schedules(all_ns_vm_schedules)

        logging.info("New VMs:")
        print_new_vm_schedules(new_vm_map)

        suspended_info = suspend_schedules(ns_vm_map, active_ns_vm_schedules, args.dry_run)
        logging.info("Schedules to suspend:")
        print_info(suspended_info)

        # VMs to add (in inventory but no active schedule)
        resumed_info = resume_schedules(ns_vm_map, suspended_ns_vm_schedules, args.dry_run)
        logging.info("Schedules to resume:")
        print_info(resumed_info)

        if args.dry_run:
            logging.info("Dry run mode: No changes made, exiting gracefully.")
            exit(0)  # Exit with success status code

        backup_location_ref = {
            "name": bl_name,
            "uid": bl_uid
        }
        cluster_ref = {
            "name": cluster_name,
            "uid": cluster_uid
        }
        distribution_result, schedules_created = distribute_vms_schedules(new_vm_map, matched_policies,
                                                                          backup_location_ref, cluster_ref,
                                                                          parse_input_map(args.csiDriver_map))

        generate_report(
            ns_vm_map,
            active_ns_vm_schedules,
            suspended_ns_vm_schedules,
            new_vm_map,
            suspended_info,
            resumed_info,
            schedules_created,
            report_file_path=report_file_name
        )
        if distribution_result:
            for p_name, data in distribution_result.items():
                logging.info(f"{p_name} (UID={data['policy_uid']}):")
                for namespace, vm_name in data["vms"]:
                    logging.info(f"  namespace={namespace}, vm={vm_name}")

        lines = []
        lines.append("\n\n====== New VM Schedule Distribution Report ======\n")
        lines.append("------------------------------------------------------\n")
        if distribution_result:
            for p_name, data in distribution_result.items():
                lines.append(f"Policy Name - {p_name} (UID={data['policy_uid']}):\n")
                if data["vms"]:
                    for namespace, vm_name in data["vms"]:
                        lines.append(f"  namespace={namespace}, vm={vm_name}\n")
                else:
                    lines.append("  (None)\n")
        else:
            lines.append("  No New VMs found to distribute\n")
        lines.append("------------------------------------------------------\n")

        # Join lines into a single report string
        report_str = "".join(lines)
        # Append report_str in vm_protection_report.txt file
        with open(report_file_name, "a") as f:
            f.write(report_str)
        print(f"Please check {report_file_name} for detailed report")

    except Exception as e:
        logging.error(f"Error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    exit(main())