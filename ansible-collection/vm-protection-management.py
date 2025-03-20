import argparse
import base64
import json
import re
import subprocess
from typing import Dict, List, Set, Tuple, Optional, Any
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("vm-schedule-sync")

class VMScheduleInfo:
    """Class to represent a schedule with its associated VM info"""
    def __init__(self, schedule_name: str, schedule_uid: str, vm_name: str, namespace: str, suspended: bool):
        self.schedule_name = schedule_name
        self.schedule_uid = schedule_uid
        self.vm_name = vm_name
        self.namespace = namespace
        self.vm_id = f"{namespace}-{vm_name}"
        self.suspended = suspended
    
    def __str__(self):
        status = "Suspended" if self.suspended else "Active"
        return f"Schedule '{self.schedule_name}' ({status}): VM '{self.vm_id}'"
    
    def __repr__(self):
        return self.__str__()

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

def get_vm_inventory(kubeconfig_file: str, ns_list: Optional[List[str]] = None) -> Set[str]:
    """
    Get inventory of all VirtualMachine resources in the cluster
    
    Args:
        kubeconfig_file: Path to the kubeconfig file
        ns_list: Optional list of namespaces to check
        
    Returns:
        Set of strings in format 'namespace-vmname'
    """
    from kubernetes import client, config

    # Load the provided kubeconfig file
    config.load_kube_config(kubeconfig_file)
    custom_api = client.CustomObjectsApi()

    group = "kubevirt.io"
    version = "v1"
    plural = "virtualmachines"
    vm_ids = set()
    vm_details = {}  # For logging details

    if ns_list is None:
        # Get all the virtual machines in the cluster
        try:
            result = custom_api.list_cluster_custom_object(
                group=group,
                version=version,
                plural=plural,
            )
            for item in result.get("items", []):
                metadata = item.get("metadata", {})
                name = metadata.get("name")
                namespace = metadata.get("namespace")
                if namespace and name:
                    vm_id = f"{namespace}-{name}"
                    vm_ids.add(vm_id)
                    if namespace not in vm_details:
                        vm_details[namespace] = []
                    vm_details[namespace].append(name)
        except Exception as e:
            logger.error(f"Error listing all VirtualMachines: {e}")
    else:
        for ns in ns_list:
            try:
                # List VirtualMachines in the specified namespace
                result = custom_api.list_namespaced_custom_object(
                    group=group,
                    version=version,
                    plural=plural,
                    namespace=ns,
                )
                # Iterate over each VirtualMachine
                for item in result.get("items", []):
                    metadata = item.get("metadata", {})
                    name = metadata.get("name")
                    if name:
                        vm_id = f"{ns}-{name}"
                        vm_ids.add(vm_id)
                        if ns not in vm_details:
                            vm_details[ns] = []
                        vm_details[namespace].append(name)
            except Exception as e:
                logger.error(f"Error listing VirtualMachines in namespace {ns}: {e}")

    # Log the VMs found
    for ns, vms in vm_details.items():
        logger.debug(f"Found VMs in namespace {ns}: {', '.join(vms)}")

    return vm_ids

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

def extract_vm_schedules(schedules: List[Dict[str, Any]]) -> Tuple[Set[str], Set[str], Dict[str, List[VMScheduleInfo]]]:
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
    active_vm_ids = set()
    suspended_vm_ids = set()
    vm_schedule_info = {}  # Maps VM IDs to their schedule info
    
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
                    vm_id = f"{namespace}-{vm_name}"
                    
                    # Create schedule info object
                    schedule_info = VMScheduleInfo(
                        schedule_name=schedule_name,
                        schedule_uid=schedule_uid,
                        vm_name=vm_name,
                        namespace=namespace,
                        suspended=is_suspended
                    )
                    
                    # Add to appropriate set
                    if is_suspended:
                        suspended_vm_ids.add(vm_id)
                    else:
                        active_vm_ids.add(vm_id)
                    
                    # Store schedule info
                    if vm_id not in vm_schedule_info:
                        vm_schedule_info[vm_id] = []
                    vm_schedule_info[vm_id].append(schedule_info)
    
    logger.info(f"Found {len(active_vm_ids)} VMs with active schedules")
    logger.info(f"Found {len(suspended_vm_ids)} VMs with suspended schedules")
    
    return active_vm_ids, suspended_vm_ids, vm_schedule_info

def main():
    parser = argparse.ArgumentParser(description="Synchronize VM backup schedules with current VM inventory")
    parser.add_argument("--cluster", required=True, help="Name of the cluster to use")
    parser.add_argument("--namespaces", nargs="+", help="List of namespaces to check (if not specified, checks all namespaces)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--output-file", help="Write results to file")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
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
        current_vm_ids = get_vm_inventory(kubeconfig_file, args.namespaces)
        logger.info(f"Found {len(current_vm_ids)} VMs in current inventory")
        
        # Get backup schedules
        schedules = enumerate_backup_schedules(cluster_name, cluster_uid)
        logger.info(f"Found {len(schedules)} backup schedules")
        
        # Extract VM information from schedules
        active_vm_ids, suspended_vm_ids, vm_schedule_info = extract_vm_schedules(schedules)
        print(f"active:{active_vm_ids}")
        print(f"suspended: {suspended_vm_ids}")
        print(f"schedule_info{vm_schedule_info}")
        # Calculate the changes needed
        # VMs to remove (have active schedules but not in inventory)
        remove_list = active_vm_ids - current_vm_ids
        
        # VMs to add (in inventory but no active schedule)
        add_list = current_vm_ids - active_vm_ids
        
        # For VMs to add, determine which already have suspended schedules
        resume_list = add_list & suspended_vm_ids
        create_list = add_list - resume_list
        
        # Print results
        logger.info("\n===== Schedule Sync Results =====")
        logger.info(f"Current VM inventory: {len(current_vm_ids)} VMs")
        logger.info(f"VMs with active schedules: {len(active_vm_ids)}")
        logger.info(f"VMs with suspended schedules: {len(suspended_vm_ids)}")
        
        logger.info(f"\nVMs to suspend schedules for ({len(remove_list)}):")
        for vm_id in sorted(remove_list):
            schedules_info = vm_schedule_info.get(vm_id, [])
            if schedules_info:
                schedule_names = ", ".join(s.schedule_name for s in schedules_info)
                logger.info(f"  {vm_id} (Schedules: {schedule_names})")
            else:
                logger.info(f"  {vm_id}")
        
        logger.info(f"\nVMs to resume schedules for ({len(resume_list)}):")
        for vm_id in sorted(resume_list):
            schedules_info = vm_schedule_info.get(vm_id, [])
            if schedules_info:
                schedule_names = ", ".join(s.schedule_name for s in schedules_info)
                logger.info(f"  {vm_id} (Schedules: {schedule_names})")
            else:
                logger.info(f"  {vm_id}")
        
        logger.info(f"\nVMs to create new schedules for ({len(create_list)}):")
        for vm_id in sorted(create_list):
            logger.info(f"  {vm_id}")

        if args.dry_run:
            logger.info("\n===== Dry Run Complete, Exiting. =====")
            exit(1)
        
        # Output to file if requested
        if args.output_file:
            result = {
                "timestamp": datetime.now().isoformat(),
                "cluster": cluster_name,
                "summary": {
                    "current_inventory": len(current_vm_ids),
                    "active_schedules": len(active_vm_ids),
                    "suspended_schedules": len(suspended_vm_ids),
                    "to_suspend": len(remove_list),
                    "to_resume": len(resume_list),
                    "to_create": len(create_list)
                },
                "actions": {
                    "suspend": sorted(list(remove_list)),
                    "resume": sorted(list(resume_list)),
                    "create": sorted(list(create_list))
                }
            }
            
            with open(args.output_file, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Results saved to {args.output_file}")
            
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    exit(main())


        # Enumerate backup schedules for active states - active schedule list
        # Enumerate backup schedules for suspended states - suspended schedule list
        # Create remove list
        # Create added list

        # Suspend the schedules for the VMs in remove list
        # Compare added list with suspended list
        # If match, make it active
        # Remove from added list to resumed list
        # Make it active
        # At this point we will have an added list of new VMs with no history
        # Create new schedules for this