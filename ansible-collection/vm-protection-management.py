import argparse
import base64
import json
import re
import subprocess


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


def get_inventory(kubeconfig_file, ns_list=None):
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
    # configuration = client.Configuration.get_default_copy()
    # configuration.ssl_ca_cert = "ca.crt"
    # api_client = client.ApiClient(configuration)
    custom_api = client.CustomObjectsApi()

    group = "kubevirt.io"
    version = "v1"
    plural = "virtualmachines"
    vm_map = {}

    if ns_list is None:
        # get all the virtual machines in the cluster
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
                    if namespace not in vm_map:
                        vm_map[namespace] = []
                    vm_map[namespace].append(name)
        except Exception as e:
            print(f"Error listing all VirtualMachines: {e}")
    else:
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
    task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call)].*?\n(.*?)\nTASK ", stdout_text,
                           re.DOTALL)
    if not task_match:
        # Try looking for it at the end of the output (last task)
        task_match = re.search(r"TASK \[(Enumerate clusters|Cluster Enumerate call)].*?\n(.*?)$", stdout_text,
                               re.DOTALL)
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create backup schedules for virtual machines")
    parser.add_argument("--cluster", required=True, help="Name of the cluster to use (required)")
    parser.add_argument("--backup-location", required=True, help="Name of the backup location to use (required)")
    parser.add_argument("--output", type=str, default="result", help="Output file for backup results")
    parser.add_argument('--gap_minutes', type=int, default=2, help='Gap between schedules in minutes (default 2 min)')

    args = parser.parse_args()

    GAP_MINUTES = 0

    try:
        # Get cluster info
        cluster_name, cluster_uid = get_cluster_info(args.cluster)

        # Inspect cluster and create kubeconfig
        cluster_file = inspect_cluster(cluster_name, cluster_uid)
        if not cluster_file:
            raise ValueError("Failed to inspect cluster")

        kubeconfig_file = create_kubeconfig(cluster_file)

        ns_list = ["vikas1", "vikas2", "win", "win2", "win3", "win4", "fed"]

        # Get VM inventory
        vm_by_ns = get_inventory(kubeconfig_file, ns_list)

        print(f"====================================================================")
        for namespace, vms in vm_by_ns.items():
            for vm in vms:
                print(f"Namespace: {namespace}, VM Name: {vm}")

        # Count total VMs
        total_vm_count = sum(len(vms) for vms in vm_by_ns.values())
        print(f"Total VM count: {total_vm_count}")

        print(f"====================================================================")

        # Count total VMs
        total_vm_count = sum(len(vms) for vms in vm_by_ns.values())
        print(f"Total VM count: {total_vm_count}")

        if total_vm_count == 0:
            raise ValueError("No VMs found in the cluster. Please verify the cluster has virtual machines.")


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