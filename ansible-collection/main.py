import base64
import json
import os
import re
import subprocess
import time
from collections import defaultdict

import yaml
from kubernetes import client, config


def get_failed_volumes(file_path):
    """
    Reads the backup JSON file and builds a mapping from namespace to the list of PVC names
    that have failed (where the volume status equals 4). Returns a tuple containing:
      - A dictionary { namespace: [failed pvc, ...] }
      - The backup name from metadata (used for naming the output YAML file)
    """
    with open(file_path, 'r') as f:
        data = json.load(f)

    failed_map = defaultdict(list)
    # Navigate to the backup_info and get the list of volumes
    backup_info = data.get("backup_info", {})
    volumes = backup_info.get("volumes", [])

    # Iterate through each volume and check its failure status
    for vol in volumes:
        status_info = vol.get("status", {})
        if status_info.get("status") == 4 or status_info.get("status") == "Failed":  # 4 indicates failure
            namespace = vol.get("namespace")
            pvc = vol.get("pvc")
            if namespace and pvc:
                failed_map[namespace].append(pvc)

    # Retrieve the backup name from the metadata; use "output" as default if not set
    backup_name = data.get("metadata", {}).get("name", "output")
    return dict(failed_map), backup_name


def get_cluster_info(file_path):
    """
    Reads the backup JSON file at 'file_path' and returns the cluster name and UID.
    These values are extracted from the 'cluster_ref' section under 'backup_info'.

    Args:
        file_path (str): The path to the backup JSON file.

    Returns:
        tuple: A tuple (cluster_name, cluster_uid). If not found, returns (None, None).
    """
    with open(file_path, 'r') as f:
        data = json.load(f)

    cluster_ref = data.get("backup_info", {}).get("cluster_ref", {})
    cluster_name = cluster_ref.get("name")
    cluster_uid = cluster_ref.get("uid")
    return cluster_name, cluster_uid


def extract_pvc_name_from_volume(vol):
    """
    Extracts the PVC name reference from a volume in a VirtualMachine spec.
    The function checks for three possible keys:
      - If the volume has a "persistentVolumeClaim", it returns its 'claimName'.
      - Else if the volume has a "dataVolume", it returns its 'name'.
      - Else if the volume is defined as a "containerDisk", it returns the volume's own name.
    Returns None if none of these are present.
    """
    if "persistentVolumeClaim" in vol:
        return vol["persistentVolumeClaim"].get("claimName")
    elif "dataVolume" in vol:
        return vol["dataVolume"].get("name")
    elif "containerDisk" in vol:
        return vol.get("name")
    elif "cloudInitNoCloud" in vol:
        return vol.get("name")
    elif "cloudInitConfigDrive" in vol:
        return vol.get("name")
    elif "ephemeral" in vol:
        return vol.get("name")
    elif "emptydisk" in vol:
        return vol.get("name")
    elif "hostDisk" in vol:
        return vol.get("name")
    elif "configMap" in vol:
        return vol.get("name")
    elif "secret" in vol:
        return vol.get("name")
    elif "serviceAccount" in vol:
        return vol.get("name")
    elif "downwardMetrics" in vol:
        return vol.get("name")
    return None


def get_kubevirt_vms_by_namespace(failed_map, vms_in_backup, kubeconfig_file):
    """
    Uses the Kubernetes CustomObjectsApi to list all KubeVirt VirtualMachines in each namespace
    from the failed_map. For each VirtualMachine, it inspects its pod template volumes (located at
    spec.template.spec.volumes). If any volume references a PVC (via persistentVolumeClaim, dataVolume,
    or containerDisk) that appears in the failed PVC list for that namespace, the VM's name is added
    to the list for that namespace.

    Returns a dictionary mapping each namespace to a list of VM names.
    """
    # Load the kubeconfig (adjust config_file argument if your kubeconfig is in a non-default location)
    config.load_kube_config(kubeconfig_file)
    # config.load_incluster_config()
    custom_api = client.CustomObjectsApi()

    vm_map = {}
    group = "kubevirt.io"
    version = "v1"
    plural = "virtualmachines"  # CRD plural for VirtualMachines

    for namespace, pvc_list in failed_map.items():
        ns_vm_list = []
        try:
            # List VirtualMachine custom objects for the namespace from the vms_in_backup mapping
            vms = vms_in_backup.get(namespace, [])
            # Create the list of Virtual Machine objects for the given VM names in vms
            for vm_name in vms:
                vm_obj = custom_api.get_namespaced_custom_object(
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=plural,
                    name=vm_name
                )
                # Navigate to the pod template volumes in the VM spec
                volumes = vm_obj.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", [])
                # Check each volume for a reference to a failed PVC
                for vol in volumes:
                    pvc_name = extract_pvc_name_from_volume(vol)
                    if pvc_name and pvc_name in pvc_list:
                        ns_vm_list.append(vm_name)
                        break

        except Exception as e:
            print(f"Error listing VirtualMachines in namespace {namespace}: {e}")
            continue

        vm_map[namespace] = ns_vm_list
    return vm_map


def create_yaml_file(vm_map, output_filename):
    """
    Converts the vm_map (a dictionary mapping namespace -> list of VM names) into an array of objects.
    Each object in the array contains two keys:
      - "namespace": the namespace name
      - "vmlist": an array of VM names associated with that namespace
    The output is written to a YAML file named <output_filename>.yaml.
    """
    output_list = []
    for ns, vm_list in vm_map.items():
        output_list.append({
            "namespace": ns,
            "vmlist": vm_list
        })

    yaml_filename = os.path.join(LOG_DIR, f"{output_filename}.yaml")
    with open(yaml_filename, "w") as f:
        yaml.safe_dump(output_list, f, default_flow_style=False)
    print(f"YAML output written to {yaml_filename}")
    return yaml_filename


def inspect_cluster(cluster_name, cluster_uid):
    """
    Runs an Ansible playbook to inspect a cluster and extracts cluster details from the output.

    The playbook used is assumed to output a section labeled "TASK [Get cluster details]"
    containing a JSON structure between "cluster" and "clusters". The extracted JSON is saved
    to a file named "cluster_data_<cluster_name>.json" under LOG_DIR.

    Args:
        cluster_name (str): The name of the cluster to inspect.
        cluster_uid (str): The UID of the cluster to inspect.

    Returns:
        str: The file path to the saved JSON data.
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

    stdout_text = result.stdout
    if not stdout_text:
        print("[ERROR] No output from Ansible playbook.")
        exit(1)

    # Step 1: Locate the "Get cluster details" task output
    task_match = re.search(r"TASK \[Get cluster details].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        print("[ERROR] Could not find 'Get cluster details' task output.")
        output_file = os.path.join(LOG_DIR, "cluster_inspect_full_output.log")
        with open(output_file, "w") as log_file:
            log_file.write(stdout_text)
        print(f"[INFO] Full Ansible output saved to {output_file}")
        exit(1)

    task_output = task_match.group(1)

    # Step 2: Extract JSON between "cluster" and "clusters"
    json_match = re.search(r'"cluster"\s*:\s*({.*?})\s*,\s*"clusters"', task_output, re.DOTALL)
    if not json_match:
        print("[ERROR] Could not extract JSON between 'cluster' and 'clusters'.")
        output_file = os.path.join(LOG_DIR, "cluster_inspect_full_output.log")
        with open(output_file, "w") as log_file:
            log_file.write(stdout_text)
        print(f"[INFO] Full Ansible output saved to {output_file}")
        exit(1)

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
        print(f"[ERROR] JSON parsing failed: {str(e)}")
        output_file = os.path.join(LOG_DIR, "cluster_inspect_full_output.log")
        with open(output_file, "w") as log_file:
            log_file.write(stdout_text)
        print(f"[INFO] Full Ansible output saved to {output_file}")


def create_kubeconfig(cluster_file):
    """
    Reads the cluster JSON file at 'cluster_file', extracts the base64 encoded kubeconfig text from the
    'clusterinfo' section, decodes it, and writes it to a file named '<cluster_name>_kubeconfig'.

    Args:
        cluster_file (str): Path to the JSON file containing cluster information.

    Returns:
        str: The filename of the created kubeconfig file.
    """
    # Load the JSON data from the file
    with open(cluster_file, 'r') as f:
        data = json.load(f)

    # Extract the cluster name from metadata; default to "unknown" if not present
    cluster_name = data.get("cluster", {}).get("metadata", {}).get("name", "unknown")

    # Extract the base64 encoded kubeconfig text from the clusterinfo section
    kubeconfig_b64 = data.get("cluster", {}).get("clusterInfo", {}).get("kubeconfig", "")

    if not kubeconfig_b64:
        raise ValueError("No kubeconfig data found in the cluster file.")

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

    return filename

def inspect_backup(backup_name, backup_uid):
    print(f"[INFO] Running Ansible playbook for backup: {backup_name}, UID: {backup_uid}")

    # Define the Ansible command with extra-vars
    cmd = [
        "ansible-playbook", "examples/backup/inspect_vm_backup.yaml", "-vvvv",
        "--extra-vars", f"backup_name={backup_name} backup_uid={backup_uid}"
    ]

    # Run the command
    result = subprocess.run(cmd, capture_output=True, text=True)

    print(f"[DEBUG] Ansible command completed with return code: {result.returncode}")

    # Extract stdout
    stdout_text = result.stdout

    if not stdout_text:
        print("[ERROR] No output from Ansible playbook.")
        exit(1)

    # **Step 1: Locate the "Get backup details" task output**
    task_match = re.search(r"TASK \[Get backup details].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)

    if not task_match:
        print("[ERROR] Could not find 'Get backup details' task output.")
        output_file = os.path.join(LOG_DIR, "backup_inspect_full_output.log")
        with open(output_file, "w") as log_file:
            log_file.write(stdout_text)
        print(f"[INFO] Full Ansible output saved to {output_file}")
        exit(1)

    task_output = task_match.group(1)

    # **Step 2: Extract everything between "backup" and "backups"**
    json_match = re.search(r'"backup"\s*:\s*({.*?})\s*,\s*"backups"', task_output, re.DOTALL)

    if not json_match:
        print("[ERROR] Could not extract JSON between 'backup' and 'backups'.")
        output_file = os.path.join(LOG_DIR, "backup_inspect_full_output.log")
        with open(output_file, "w") as log_file:
            log_file.write(stdout_text)
        print(f"[INFO] Full Ansible output saved to {output_file}")
        exit(1)

    raw_json = json_match.group(1)

    # **Step 3: Parse JSON and save to file**
    try:
        parsed_json = json.loads(raw_json)
        output_file = os.path.join(LOG_DIR, f"backup_data_{backup_name}.json")
        with open(output_file, "w") as json_file:
            json.dump(parsed_json, json_file, indent=4)
        print(f"[SUCCESS] Extracted backup data successfully. File saved as {output_file}")
        return output_file

    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON parsing failed: {str(e)}")
        output_file = os.path.join(LOG_DIR, "backup_inspect_full_output.log")
        with open(output_file, "w") as log_file:
            log_file.write(stdout_text)
        print(f"[INFO] Full Ansible output saved to {output_file}")

def invoke_backup(vm_map, backup_info):
    """
    Generates an Ansible playbook dynamically and invokes the backup call.
    
    - vm_map: {namespace: [vm1, vm2, ...]} - VMs to be backed up.
    - backup_info: JSON metadata containing backup details.
    """

    # Extract necessary backup details
    backup_name = backup_info.get("metadata", {}).get("name", "backup")
    epoch_time = int(time.time())
    new_backup_name = f"{backup_name}-retry-{epoch_time}"

    backup_location_ref = backup_info.get("backup_info", {}).get("backup_location_ref", {})
    cluster_ref = backup_info.get("backup_info", {}).get("cluster_ref", {})

    # Construct include_resources dynamically
    include_resources = []
    vm_namespaces = []

    for entry in vm_map:  # vm_map is a list of dicts
        namespace = entry.get("namespace")
        vmlist = entry.get("vmlist", [])
        
        if namespace and vmlist:
            vm_namespaces.append(namespace)
            for vm in vmlist:
                include_resources.append({
                    "group": "kubevirt.io",
                    "kind": "VirtualMachine",
                    "version": "v1",
                    "name": vm,
                    "namespace": namespace
                })

    # Define backup config
    skip_vm_auto_exec_rules = os.getenv("SKIP_VM_AUTO_EXEC_RULES", "True").lower() == "true"
    playbook_data = [{
        "name": "Create VM Backup",
        "hosts": "localhost",
        "gather_facts": False,
        "vars": {
            "backups": [{
                "name": new_backup_name,
                "backup_location_ref": backup_location_ref,
                "cluster_ref": cluster_ref,
                "backup_type": "Normal",
                "backup_object_type": "VirtualMachine",
                "skip_vm_auto_exec_rules": skip_vm_auto_exec_rules,
                "validate_certs": True
            }],
            "vm_namespaces": vm_namespaces,   # Pass extracted namespaces
            "include_resources": include_resources  # Pass extracted include_resources
        },
        "tasks": [
            {
                "name": "Trigger VM Backup",
                "include_tasks": "examples/backup/backup_task.yaml"
            }
        ]
    }]

    # Save generated playbook
    playbook_file = "create_vm_backup_retry.yaml"
    with open(playbook_file, "w") as f:
        yaml.safe_dump(playbook_data, f, default_flow_style=False)

    print(f"[INFO] Ansible playbook written to {playbook_file}")

    # Define log file for Ansible execution
    log_file = os.path.join(LOG_DIR, "backup_create.log")
    json_output_file = os.path.join(LOG_DIR, f"{new_backup_name}.json")

    # Invoke the Ansible playbook and capture logs
    ansible_cmd = [
        "ansible-playbook", playbook_file, "-vvvv",
       "--extra-vars", f"vm_namespaces='{json.dumps(vm_namespaces)}'",
       "--extra-vars", f"include_resources='{json.dumps(include_resources)}'",
    ]

    with open(log_file, "w") as log:
        result = subprocess.run(ansible_cmd, stdout=log, stderr=log, text=True)

    print(f"[DEBUG] Ansible command completed with return code: {result.returncode}")

    if result.returncode != 0:
        print(f"[ERROR] Backup playbook execution failed. Logs saved to {log_file}")

        # Save failure response as JSON
        response = {
            "status": "failure",
            "backup_name": new_backup_name,
            "error": f"Backup execution failed. Check {log_file} for details.",
            "ansible_return_code": result.returncode
        }

        with open(json_output_file, "w") as json_file:
            json.dump(response, json_file, indent=4)

    else:
        print(f"[SUCCESS] Backup successfully triggered. Playbook: {playbook_file}")

        # Save success response as JSON
        response = {
            "status": "success",
            "backup_name": new_backup_name,
            "message": "Backup executed successfully."
        }

        with open(json_output_file, "w") as json_file:
            json.dump(response, json_file, indent=4)

    return new_backup_name

def load_yaml(file_path):
    """Loads a YAML file and returns its contents."""
    with open(file_path, "r") as f:
        return yaml.safe_load(f)

def load_json(file_path):
    """Loads a JSON file and returns its contents."""
    with open(file_path, "r") as f:
        return json.load(f)


def get_all_vms_from_backup(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    resources = data.get("backup_info", {}).get("include_resources", [])
    vm_map = {}
    for resource in resources:
        if resource.get("group") == "kubevirt.io" and resource.get("kind") == "VirtualMachine":
            ns = resource.get("namespace")
            vm_name = resource.get("name")
            if ns:
                vm_map.setdefault(ns, []).append(vm_name)
    return vm_map

if __name__ == "__main__":
    # Accept two command line arguments: backup name and backup UID
    # Example usage: python main.py backup-name backup-uid
    import sys
    if len(sys.argv) != 3:
        print("Usage: python main.py <backup-name> <backup-uid>")
        sys.exit(1)

    backup_name = sys.argv[1]
    backup_uid = sys.argv[2]
    print(f"Backup name: {backup_name}, Backup UID: {backup_uid}")

    LOG_DIR = "/tmp/logs"
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    # Inspect Backup
    file_path = inspect_backup(backup_name, backup_uid)
    print(f"Backup data saved to {file_path}")

    # Get cluster info
    cluster_name, cluster_uid = get_cluster_info(file_path)
    print(f"Cluster name: {cluster_name}, Cluster UID: {cluster_uid}")
    if cluster_name and cluster_uid:
        cluster_file = inspect_cluster(cluster_name, cluster_uid)
        print(f"Cluster data saved")

    # Create kubeconfig file
    kubeconfig_file = create_kubeconfig(cluster_file)

    # Build the mapping of namespace -> list of failed PVCs and get the backup name
    failed_volumes, backup_name = get_failed_volumes(file_path)
    print("Failed volumes map:")
    print(json.dumps(failed_volumes, indent=2))
    print(f"\nBackup name (for YAML output): {backup_name}")

    # Get the mapping of namespace -> list of KubeVirt VM names that reference a failed PVC

    vms_in_backup = get_all_vms_from_backup(file_path)
    vm_by_ns = get_kubevirt_vms_by_namespace(failed_volumes, vms_in_backup, kubeconfig_file)
    print("\nMapping of namespace to KubeVirt VM names referencing a failed PVC:")
    print(json.dumps(vm_by_ns, indent=2))

    # Create the YAML file as an array of objects with each object having the keys "namespace" and "vmlist"
    yaml_filename = create_yaml_file(vm_by_ns, backup_name)
    print(f"VM list saved to {yaml_filename}")

    # Load VM mapping (YAML)
    vm_map = load_yaml(yaml_filename)

    # Load backup info (JSON)
    backup_info = load_json(file_path)

    new_backup_name = invoke_backup(vm_map, backup_info)
    print("Created retry backup for failed VMs: ", new_backup_name)
