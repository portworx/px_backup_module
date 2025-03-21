import argparse
import datetime
import json
import os
import re
import subprocess
import time
from zoneinfo import ZoneInfo

import yaml
import logging


timestamp = datetime.datetime.now().strftime("%d%m%Y_%H%M%S")
LOG_FILE = f"retry-failed-logs_{timestamp}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ]
)


def enumerate_cluster(cluster_name):
    logging.info("Running Ansible playbook for enumerate clusters")

    # Define the Ansible command
    cmd = ["ansible-playbook", "examples/cluster/enumerate.yaml", "-vvvv"]

    # Run the command
    result = subprocess.run(cmd, capture_output=True, text=True)

    logging.debug(f"Ansible command completed with return code: {result.returncode}")

    # Extract stdout
    stdout_text = result.stdout

    if not stdout_text:
        logging.error("No output from Ansible playbook.")
        exit(1)

    # **Step 1: Locate the "Get list of clusters" task output**
    task_match = re.search(r"TASK \[Cluster Enumerate call].*?\n(.*?)\nRead vars_file ", stdout_text, re.DOTALL)

    if not task_match:
        logging.error("Could not find 'Get list of clusters' task output.")
        exit(1)

    task_output = task_match.group(1)
    logging.debug(f"Ansible task output: {task_output}")

    # **Step 2: Extract everything between "cluster" and "clusters"**
    pattern = r"ok:\s*\[localhost\]\s*=>\s*(\{.*\})"
    json_match = re.search(pattern, task_output, re.DOTALL)

    if not json_match:
        logging.error("Could not extract JSON between 'cluster' and 'clusters'.")
        exit(1)

    raw_json = json_match.group(1)

    # **Step 3: Parse JSON and save to file**
    try:
        decoder = json.JSONDecoder()
        parsed_json, idx = decoder.raw_decode(raw_json)
        # loop through the clusters and check if the cluster name is matching
        for cluster in parsed_json.get("clusters", []):
            if cluster.get("metadata", {}).get("name") == cluster_name:
                cluster_uid = cluster.get("metadata", {}).get("uid")
                return cluster_uid
        # Get cluster UID from the first cluster
        # cluster_uid = parsed_json.get("clusters", [{}])[0].get("metadata", {}).get("uid")
        # return cluster_uid

    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing failed: {str(e)}")

def get_all_backups(cluster_name_filter, cluster_uid):
    logging.debug(f"[INFO] Running Ansible playbook for enumerate backups")


    # Define the Ansible command with extra-vars
    cmd = [
        "ansible-playbook", "examples/backup/enumerate_vm_backups.yaml", "-vvvv",
        "--extra-vars", f"cluster_name_filter={cluster_name_filter} cluster_uid_filter={cluster_uid}"
    ]

    # Run the command
    result = subprocess.run(cmd, capture_output=True, text=True)

    logging.debug(f"[DEBUG] Ansible command completed with return code: {result.returncode}")

    # Extract stdout
    stdout_text = result.stdout

    if not stdout_text:
        logging.debug("[ERROR] No output from Ansible playbook.")
        exit(1)

    # **Step 1: Locate the "Get list of backups" task output**
    task_match = re.search(r"TASK \[Get list of backups].*?\n(.*?)\nTASK", stdout_text, re.DOTALL)

    if not task_match:
        logging.debug("[ERROR] Could not find 'Get backup details' task output.")
        exit(1)

    task_output = task_match.group(1)


    # **Step 2: Extract everything between "backup" and "backups"**
    json_match = re.search(r'(\{.*\})', task_output, re.DOTALL)

    if not json_match:
        logging.debug("[ERROR] Could not extract JSON between 'backup' and 'backups'.")
        exit(1)

    raw_json = json_match.group(1)

    # **Step 3: Parse JSON and save to file**
    try:
        decoder = json.JSONDecoder()
        parsed_json, idx = decoder.raw_decode(raw_json)
        output_file = f"backup_data_enumerate.json"
        with open(output_file, "w") as json_file:
            json.dump(parsed_json, json_file, indent=4)
        logging.debug(f"[SUCCESS] Extracted backup data successfully. File saved as {output_file}")
        return output_file

    except json.JSONDecodeError as e:
        logging.debug(f"[ERROR] JSON parsing failed: {str(e)}")


def get_failed_backups(file_path, min_last_update, tz_str=None):
    """
    Reads the backup JSON file and returns a list of backup objects (each containing
    'metadata' and 'backup_info') that match all of the following criteria:
      - backup_object_type == 'VirtualMachine'
      - status == 'Failed' or 'PartialSuccess'
      - last_update_time > min_last_update (converted to UTC)

    Args:
        file_path (str): Path to the backup JSON file.
        min_last_update (str): Minimum last update time in 'MM/DD/YYYY HH:MMAM/PM' format.
        tz_str (str, optional): Time zone identifier (e.g. 'Asia/Kolkata'). Defaults to 'America/New_York' (EDT)
                                if not provided.

    Returns:
        list: A list of backup objects, where each object includes 'metadata' and 'backup_info'.
    """
    if tz_str is None:
        tz_str = "America/New_York"  # Default to EDT

    # Parse the min_last_update. Example: "03/18/2025 07:25AM"
    try:
        local_dt = datetime.datetime.strptime(min_last_update, "%m/%d/%Y %I:%M%p")
        # Convert local time to the specified TZ, then to UTC
        local_dt = local_dt.replace(tzinfo=ZoneInfo(tz_str))
        min_last_update_dt = local_dt.astimezone(ZoneInfo("UTC"))
    except ValueError as e:
        raise ValueError("min_last_update must be in 'MM/DD/YYYY HH:MMAM/PM' format") from e

    with open(file_path, 'r') as f:
        data = json.load(f)

    failed_backups = []
    for backup in data.get("backups", []):
        status = backup.get("backup_info", {}).get("status", {}).get("status")
        backup_type = backup.get("backup_info", {}).get("backup_object_type", {}).get("type")
        last_update_str = backup.get("metadata", {}).get("last_update_time")
        if not last_update_str:
            continue

        # Parse the ISO8601 last_update_time
        try:
            last_update_str = last_update_str.rstrip("Z")
            if '.' in last_update_str:
                date_part, frac = last_update_str.split('.', 1)
                frac = frac[:6]  # Truncate microseconds to 6 digits
                last_update_str = f"{date_part}.{frac}"
            last_update_dt = datetime.datetime.fromisoformat(last_update_str)
            if last_update_dt.tzinfo is None:
                # If there's no tzinfo, assume the timestamp is already in UTC
                last_update_dt = last_update_dt.replace(tzinfo=ZoneInfo("UTC"))
        except Exception as e:
            logging.debug(f"[WARNING] Error parsing last_update_time '{last_update_str}': {e}")
            continue

        # Check filters
        if backup_type == "VirtualMachine" and status in ["Failed", "PartialSuccess"] and last_update_dt > min_last_update_dt:
            # Append the entire backup object but keep only metadata + backup_info
            new_backup_obj = {
                "metadata": backup.get("metadata", {}),
                "backup_info": backup.get("backup_info", {})
            }
            failed_backups.append(new_backup_obj)

    return failed_backups

def inspect_backup(backup_name, backup_uid):
    logging.info(f"Running Ansible playbook for backup: {backup_name}, UID: {backup_uid}")

    # Define the Ansible command with extra-vars
    cmd = [
        "ansible-playbook", "examples/backup/inspect_vm_backup.yaml", "-vvvv",
        "--extra-vars", f"backup_name={backup_name} backup_uid={backup_uid}"
    ]

    # Run the command
    result = subprocess.run(cmd, capture_output=True, text=True)

    logging.debug(f"Ansible command completed with return code: {result.returncode}")

    # Extract stdout
    stdout_text = result.stdout

    if not stdout_text:
        logging.error("No output from Ansible playbook.")
        exit(1)

    # **Step 1: Locate the "Get backup details" task output**
    task_match = re.search(r"TASK \[Get backup details].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)

    if not task_match:
        logging.error("Could not find 'Get backup details' task output.")
        exit(1)

    task_output = task_match.group(1)

    # **Step 2: Extract everything between "backup" and "backups"**
    json_match = re.search(r'"backup"\s*:\s*({.*?})\s*,\s*"backups"', task_output, re.DOTALL)

    if not json_match:
        logging.error("Could not extract JSON between 'backup' and 'backups'.")
        exit(1)

    raw_json = json_match.group(1)

    # **Step 3: Parse JSON and save to file**
    try:
        parsed_json = json.loads(raw_json)
        output_file = f"backup_data_{backup_name}.json"
        with open(output_file, "w") as json_file:
            json.dump(parsed_json, json_file, indent=4)
        logging.debug(f"Extracted backup data successfully. File saved as {output_file}")
        return output_file

    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing failed: {str(e)}")

def get_resources_from_backup(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    resources = data.get("backup_info", {}).get("include_resources", [])
    return resources

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

    yaml_filename = f"{output_filename}.yaml"
    with open(yaml_filename, "w") as f:
        yaml.safe_dump(output_list, f, default_flow_style=False)
    logging.debug(f"YAML output written to {yaml_filename}")
    return yaml_filename

def load_yaml(file_path):
    """Loads a YAML file and returns its contents."""
    with open(file_path, "r") as f:
        return yaml.safe_load(f)

def load_json(file_path):
    """Loads a JSON file and returns its contents."""
    with open(file_path, "r") as f:
        return json.load(f)


def invoke_backup(resources, backup_info):
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
    vm_namespaces = backup_info.get("backup_info", {}).get("namespaces", [])
    vscMap = backup_info.get("backup_info", {}).get("volume_snapshot_class_mapping", {})

    # for entry in vm_map:  # vm_map is a list of dicts
    #     namespace = entry.get("namespace")
    #     vmlist = entry.get("vmlist", [])
    #
    #     if namespace and vmlist:
    #         vm_namespaces.append(namespace)
    #         for vm in vmlist:
    #             include_resources.append({
    #                 "group": "kubevirt.io",
    #                 "kind": "VirtualMachine",
    #                 "version": "v1",
    #                 "name": vm,
    #                 "namespace": namespace
    #             })

    # Define backup config
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
                "skip_vm_auto_exec_rules": True,
                "volume_snapshot_class_mapping": vscMap,
            }],
            "vm_namespaces": vm_namespaces,  # Pass extracted namespaces
            "include_resources": resources  # Pass extracted include_resources
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

    logging.info(f"Ansible playbook written to {playbook_file}")

    json_output_file = f"{new_backup_name}.json"

    # Invoke the Ansible playbook and print the output
    ansible_cmd = [
        "ansible-playbook", playbook_file, "-vvvv",
        "--extra-vars", f"vm_namespaces='{json.dumps(vm_namespaces)}'",
        "--extra-vars", f"include_resources='{json.dumps(include_resources)}'",
    ]

    result = subprocess.run(ansible_cmd, capture_output=True, text=True)

    logging.debug(f"Ansible stdout: {result.stdout}")

    logging.debug(f"Ansible command completed with return code: {result.returncode}")

    if result.returncode != 0:
        logging.error("Backup playbook execution failed.")

        # Save failure response as JSON
        response = {
            "status": "failure",
            "backup_name": new_backup_name,
            "error": f"Backup execution failed.",
            "ansible_return_code": result.returncode
        }

        with open(json_output_file, "w") as json_file:
            json.dump(response, json_file, indent=4)

    else:
        logging.debug(f"Backup successfully triggered. Playbook: {playbook_file}")

        # Save success response as JSON
        response = {
            "status": "success",
            "backup_name": new_backup_name,
            "message": "Backup executed successfully."
        }

        with open(json_output_file, "w") as json_file:
            json.dump(response, json_file, indent=4)

    return new_backup_name

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

def inspect_cluster(cluster_name):
    """
    Runs an Ansible playbook to inspect a cluster and extracts cluster details from the output.

    The playbook used is assumed to output a section labeled "TASK [Get cluster details]"
    containing a JSON structure between "cluster" and "clusters". The extracted JSON is saved
    to a file named "cluster_data_<cluster_name>.json".

    Args:
        cluster_name (str): The name of the cluster to inspect.

    Returns:
        str: Cluster UID.
    """
    logging.info(f"Running Ansible playbook for cluster: {cluster_name}")

    # Construct extra-vars as a JSON object
    extra_vars = json.dumps({
        "clusters_inspect": [{
            "name": cluster_name,
            "include_secrets": True
        }]
    })

    cmd = [
        "ansible-playbook", "examples/cluster/inspect.yaml", "-vvvv",
        "--extra-vars", extra_vars
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    logging.debug(f"Ansible command completed with return code: {result.returncode}")

    stdout_text = result.stdout
    if not stdout_text:
        logging.error("No output from Ansible playbook.")
        exit(1)

    # Step 1: Locate the "Get cluster details" task output
    task_match = re.search(r"TASK \[Get cluster details].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
    if not task_match:
        logging.error("Could not find 'Get cluster details' task output.")
        exit(1)

    task_output = task_match.group(1)

    # Step 2: Extract JSON between "cluster" and "clusters"
    json_match = re.search(r'"cluster"\s*:\s*({.*?})\s*,\s*"clusters"', task_output, re.DOTALL)
    if not json_match:
        logging.error("Could not extract JSON between 'cluster' and 'clusters'.")
        exit(1)

    raw_json = json_match.group(1)

    # Step 3: Parse JSON and save to file
    try:
        parsed_json = json.loads(raw_json)
        cluster_uid = parsed_json.get("cluster_info", {}).get("cluster_uid", {})
        logging.debug("Extracted cluster data successfully.")
        return cluster_uid

    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing failed: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backup Processing Script")
    parser.add_argument("--cluster-name", required=True, help="Name of the application cluster")
    parser.add_argument("--timestamp", required=True,
                        help="Timestamp for filtering failed backups in MM/DD/YYYY HH:MMAM/PM format e.g., 03/18/2025 07:25AM")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()
    print(f"Logs are getting captured at {LOG_FILE}")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cluster_uid = enumerate_cluster(args.cluster_name)
    logging.info(f"Backing up cluster: {args.cluster_name} with uid {cluster_uid}")
    enumerate_response = get_all_backups(args.cluster_name, cluster_uid)
    failed_backups = get_failed_backups(enumerate_response, args.timestamp)
    # print only the backup name from the failed backups
    failed_backup_names = [backup.get("metadata", {}).get("name") for backup in failed_backups]
    logging.debug(f"Enumerated backup list: {failed_backup_names}")
    for backup in failed_backups:
        backup_name = backup.get("metadata", {}).get("name")
        backup_uid = backup.get("metadata", {}).get("uid")
        # Inspect Backup
        file_path = inspect_backup(backup_name, backup_uid)
        vms_in_backup = get_all_vms_from_backup(file_path)
        # logging.debug the failed VM names and namespaces
        logging.debug(f"VMs in failed backup {backup_name}:")
        logging.debug(json.dumps(vms_in_backup, indent=2))
        resources = get_resources_from_backup(file_path)
        # logging.debug("\nMapping of namespace to KubeVirt VM names referencing a failed PVC:")
        # logging.debug(json.dumps(resources, indent=2))

        # Create the YAML file as an array of objects with each object having the keys "namespace" and "vmlist"
        # yaml_filename = create_yaml_file(resources, backup_name)
        # logging.debug(f"VM list saved to {yaml_filename}")
        #
        # # Load VM mapping (YAML)
        # vm_map = load_yaml(yaml_filename)
        #
        # Load backup info (JSON)
        backup_info = load_json(file_path)

        new_backup_name = invoke_backup(resources, backup_info)
        logging.debug("Created retry backup for failed VMs: ", new_backup_name)
        # sleep for 2 minutes
        time.sleep(120)