import argparse
import datetime
import json
import logging
import os
import re
import subprocess
import time
from collections import defaultdict
from zoneinfo import ZoneInfo

import yaml

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


def extract_json_object(text, key):
    """
    Extract a JSON object for a given key from text using brace matching.

    Args:
        text: The text to search in
        key: The JSON key to find (e.g., "cluster", "backup")

    Returns:
        The extracted JSON string, or None if not found
    """
    # Find the key pattern: "key": {
    pattern = rf'"{key}"\s*:\s*\{{'
    match = re.search(pattern, text)
    if not match:
        return None

    # Find the opening brace position
    brace_start = text.find('{', match.start())
    if brace_start == -1:
        return None

    # Use brace matching to find the complete JSON object
    brace_depth = 0
    i = brace_start
    while i < len(text):
        if text[i] == '{':
            brace_depth += 1
        elif text[i] == '}':
            brace_depth -= 1
            if brace_depth == 0:
                # Found matching closing brace
                return text[brace_start:i + 1]
        i += 1

    return None


def extract_json_array(text, key):
    """
    Extract a JSON array for a given key from text using bracket matching.

    Args:
        text: The text to search in
        key: The JSON key to find (e.g., "clusters", "backups")

    Returns:
        The extracted JSON string, or None if not found
    """
    # Find the key pattern: "key": [
    pattern = rf'"{key}"\s*:\s*\['
    match = re.search(pattern, text)
    if not match:
        return None

    # Find the opening bracket position
    bracket_start = text.find('[', match.start())
    if bracket_start == -1:
        return None

    # Use bracket matching to find the complete JSON array
    bracket_depth = 0
    i = bracket_start
    while i < len(text):
        if text[i] == '[':
            bracket_depth += 1
        elif text[i] == ']':
            bracket_depth -= 1
            if bracket_depth == 0:
                # Found matching closing bracket
                return text[bracket_start:i + 1]
        i += 1

    return None


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

    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', stdout_text)

    # Extract JSON from console output
    parsed_json = extract_json_from_console(cleaned_output)

    if parsed_json is None:
        logging.error("Could not extract JSON from Ansible output.")
        exit(1)

    # loop through the clusters and check if the cluster name is matching
    for cluster in parsed_json.get("clusters", []):
        if cluster.get("metadata", {}).get("name") == cluster_name:
            cluster_uid = cluster.get("metadata", {}).get("uid")
            return cluster_uid

def get_all_backups(cluster_name_filter, cluster_uid):
    logging.debug(f"[INFO] Running Ansible playbook for enumerate backups")

    # Use JSON format for extra-vars to handle special characters properly
    extra_vars = json.dumps({
        "cluster_name_filter": cluster_name_filter,
        "cluster_uid_filter": cluster_uid
    })

    # Define the Ansible command with extra-vars
    cmd = [
        "ansible-playbook", "examples/backup/enumerate_vm_backups.yaml", "-vvvv",
        "--extra-vars", extra_vars
    ]

    # Run the command
    result = subprocess.run(cmd, capture_output=True, text=True)

    logging.debug(f"[DEBUG] Ansible command completed with return code: {result.returncode}")

    # Extract stdout
    stdout_text = result.stdout

    if not stdout_text:
        logging.error("[ERROR] No output from Ansible playbook.")
        exit(1)

    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', stdout_text)

    # Extract JSON from console output
    parsed_json = extract_json_from_console(cleaned_output)

    if parsed_json is None:
        logging.error("[ERROR] Could not extract JSON from Ansible output.")
        logging.debug(f"Ansible output: {cleaned_output}")
        exit(1)

    # Save to a file for downstream processing
    json_file_path = f"backups_{cluster_name_filter}_{cluster_uid}.json"
    with open(json_file_path, 'w') as f:
        json.dump(parsed_json, f, indent=4)

    logging.debug(f"[SUCCESS] Saved backup data to: {json_file_path}")
    return json_file_path


def get_failed_backups(file_path, min_last_update, tz_str=None, time_field="completion_time"):
    """
    Reads the backup JSON file and returns a list of backup objects (each containing
    'metadata' and 'backup_info') that match all of the following criteria:
      - backup_object_type == 'VirtualMachine'
      - status == 'Failed' or 'PartialSuccess'
      - specified time field > min_last_update (converted to UTC)

    Args:
        file_path (str): Path to the backup JSON file.
        min_last_update (str): Minimum last update time in 'MM/DD/YYYY HH:MMAM/PM' format.
        tz_str (str, optional): Time zone identifier (e.g. 'Asia/Kolkata'). Defaults to 'America/New_York' (EDT)
                                if not provided.
        time_field (str, optional): Time field to use for filtering. Either 'create_time' or 'completion_time'.
                                   Defaults to 'completion_time'.

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

    data = load_json(file_path)
    failed_backups = []
    for backup in data.get("backups", []):
        status = backup.get("backup_info", {}).get("status", {}).get("status")
        backup_type = backup.get("backup_info", {}).get("backup_object_type", {}).get("type")

        # Get the time field based on user choice
        if time_field == "create_time":
            time_str = backup.get("metadata", {}).get("create_time")
        else:  # default to completion_time
            # Get completion time from backup_info.completion_time_info.total_completion_time
            time_str = backup.get("backup_info", {}).get("completion_time_info", {}).get("total_completion_time", {})

        if not time_str:
            continue

        # Parse the ISO8601 timestamp
        try:
            time_str = time_str.rstrip("Z")
            if '.' in time_str:
                date_part, frac = time_str.split('.', 1)
                frac = frac[:6]  # Truncate microseconds to 6 digits
                time_str = f"{date_part}.{frac}"
            time_dt = datetime.datetime.fromisoformat(time_str)
            if time_dt.tzinfo is None:
                # If there's no tzinfo, assume the timestamp is already in UTC
                time_dt = time_dt.replace(tzinfo=ZoneInfo("UTC"))
        except Exception as e:
            logging.debug(f"[WARNING] Error parsing {time_field} '{time_str}': {e}")
            continue

        # Check filters
        if backup_type == "VirtualMachine" and status in ["Failed", "PartialSuccess"] and time_dt >= min_last_update_dt:
            # Append the entire backup object but keep only metadata + backup_info
            new_backup_obj = {
                "metadata": backup.get("metadata", {}),
                "backup_info": backup.get("backup_info", {})
            }
            failed_backups.append(new_backup_obj)

    return failed_backups

def inspect_backup(backup_name, backup_uid):
    logging.info(f"Running Ansible playbook for backup: {backup_name}, UID: {backup_uid}")

    # Use JSON format for extra-vars to handle special characters properly
    extra_vars = json.dumps({
        "backup_name": backup_name,
        "backup_uid": backup_uid
    })

    # Define the Ansible command with extra-vars
    cmd = [
        "ansible-playbook", "examples/backup/inspect_vm_backup.yaml", "-vvvv",
        "--extra-vars", extra_vars
    ]

    # Run the command
    result = subprocess.run(cmd, capture_output=True, text=True)

    logging.info(f"Ansible command completed with return code: {result.returncode}")

    # Extract stdout
    stdout_text = result.stdout
    logging.debug(f"Ansible stdout: {stdout_text}")

    if not stdout_text:
        logging.error("No output from Ansible playbook.")
        exit(1)

    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', stdout_text)

    # Extract JSON from console output
    parsed_json = extract_json_from_console(cleaned_output)

    if parsed_json is None:
        logging.error("Could not extract JSON from Ansible output.")
        logging.debug(f"Ansible output: {cleaned_output}")
        exit(1)

    # Save to a file for downstream processing
    json_file_path = f"backup_data_{backup_name}_{backup_uid}.json"
    with open(json_file_path, 'w') as f:
        json.dump(parsed_json, f, indent=4)

    logging.info(f"Extracted backup data successfully. File: {json_file_path}")
    return json_file_path

def get_resources_from_backup(data):
    # Handle both direct backup_info and nested backup.backup_info structures
    backup_info = data.get("backup", {}).get("backup_info", {}) or data.get("backup_info", {})
    resources = backup_info.get("include_resources", [])
    return resources

def get_resources_from_backup_schedule(data):
    backup_schedule = data.get("backup_info", {}).get("backup_schedule", {})
    schedule_name = backup_schedule.get("name")
    schedule_uid = backup_schedule.get("uid")

    schedule_inspect_response = inspect_backup_schedule(schedule_name, schedule_uid, verbose=args.verbose)
    logging.info(
        f"Successfully retrieved schedule: {schedule_inspect_response.get('backup_schedule', {}).get('metadata', {}).get('name', '')}")
    return schedule_inspect_response.get('backup_schedule', {}).get('backup_schedule_info', {}).get('include_resources', [])

def is_scheduled_backup(data):
    # Handle both direct backup_info and nested backup.backup_info structures
    backup_info = data.get("backup", {}).get("backup_info", {}) or data.get("backup_info", {})
    backup_schedule = backup_info.get("backup_schedule", {})
    if backup_schedule:
        return True
    else:
        return False

def inspect_backup_schedule(name, uid, org_id="default", verbose=False):
    """
    Inspect a specific backup schedule in PX-Backup using Ansible

    Args:
        name (str): Name of the backup schedule to inspect
        uid (str): UID of the backup schedule to inspect
        org_id (str, optional): Organization ID. Defaults to "default".
        verbose (bool, optional): If True, print detailed debug info

    Returns:
        dict: The backup schedule object if found, None otherwise
    """
    logging.info(f"Inspecting backup schedule: {name} (UID: {uid})")

    # Prepare extra vars for the Ansible command
    extra_vars = {
        "name": name,
        "uid": uid,
        "org_id": org_id
    }

    # Convert to JSON string
    extra_vars_json = json.dumps(extra_vars)

    # Run the Ansible command
    cmd = [
        "ansible-playbook", "examples/backup_schedule/inspect.yaml", "-vvvv",
        "--extra-vars", extra_vars_json
    ]

    cmd_str = " ".join(cmd)
    logging.info(f"Running command: {cmd_str}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        logging.info(f"Command completed with return code: {result.returncode}")

        if verbose:
            # Print first few lines of stdout and stderr if verbose is enabled
            stdout_preview = "\n".join(result.stdout.splitlines()[:20])
            stderr_preview = "\n".join(result.stderr.splitlines()[:20])
            logging.info(f"Command stdout preview:\n{stdout_preview}\n...")
            if result.stderr:
                logging.info(f"Command stderr preview:\n{stderr_preview}\n...")

        if result.returncode != 0:
            error_msg = f"Failed to inspect backup schedule: {name}, return code: {result.returncode}"
            if result.stderr:
                error_msg += f"\nError output: {result.stderr[:500]}..."
            logging.error(error_msg)
            return None

        # Extract backup schedule from output
        stdout_text = result.stdout

        if verbose:
            # Save the full output to a file for debugging
            debug_file = f"debug_backup_schedule_{name}_{int(time.time())}.log"
            with open(debug_file, 'w') as f:
                f.write(f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}")
            logging.info(f"Full command output saved to {debug_file}")

        # Remove ANSI escape codes
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        cleaned_output = ansi_escape.sub('', stdout_text)

        # Extract JSON from console output
        parsed = extract_json_from_console(cleaned_output)

        if parsed is None:
            logging.error("Could not extract JSON from Ansible output.")
            return {}

        return parsed

    except Exception as e:
        logging.error(f"Exception when inspecting backup schedule: {str(e)}")
        return None

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
    # Handle both direct structure and nested backup.* structure
    backup_data = backup_info.get("backup", {}) if "backup" in backup_info else backup_info
    metadata = backup_data.get("metadata", {})
    backup_info_data = backup_data.get("backup_info", {})

    backup_name = metadata.get("name", "backup")
    epoch_time = int(time.time())
    new_backup_name = f"{backup_name}-retry-{epoch_time}"

    backup_location_ref = backup_info_data.get("backup_location_ref", {})
    cluster_ref = backup_info_data.get("cluster_ref", {})

    # Construct namespace dynamically
    if resources:
        # parse the resources to get all the namespaces and put them in a list
        vm_namespaces = [resource.get("namespace") for resource in resources]
        # remove duplicates
        vm_namespaces = list(set(vm_namespaces))
    else:
        # if no resources, get the namespaces from the backup_info
        vm_namespaces = backup_info_data.get("namespaces", [])
    vscMap = backup_info_data.get("volume_snapshot_class_mapping", {})

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
        "vars_files": [
            "{{ inventory_dir }}/group_vars/common/all.yaml"
        ],
        "vars": {
            "backups": [{
                "name": new_backup_name,
                "backup_location_ref": backup_location_ref,
                "cluster_ref": cluster_ref,
                "backup_type": "Normal",
                "backup_object_type": {"type": "VirtualMachine"},
                "skip_vm_auto_exec_rules": True,
                "volume_snapshot_class_mapping": vscMap,
            }],
            "vm_namespaces": vm_namespaces,
            "include_resources": resources
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

    # Use JSON format for extra-vars to handle complex data structures properly
    extra_vars = json.dumps({
        "vm_namespaces": vm_namespaces,
        "include_resources": resources
    })

    # Invoke the Ansible playbook and print the output
    ansible_cmd = [
        "ansible-playbook", playbook_file, "-vvvv",
        "--extra-vars", extra_vars
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
    data = load_json(file_path)
    resources = data.get("backup_info", {}).get("resources", [])
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

    The playbook uses the output_handler role to output JSON in a "Display as JSON" task.
    The extracted cluster UID is returned.

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

    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cleaned_output = ansi_escape.sub('', stdout_text)

    # Extract JSON from console output
    parsed_data = extract_json_from_console(cleaned_output)

    if parsed_data is None:
        logging.error("Could not extract JSON from Ansible output.")
        exit(1)

    # Handle loop output with 'results' array
    if 'results' in parsed_data and parsed_data['results']:
        first_result = parsed_data['results'][0]
        cluster_data = first_result.get('cluster', {})
    elif 'cluster' in parsed_data:
        cluster_data = parsed_data['cluster']
    else:
        logging.error("No 'cluster' or 'results' key found in parsed output.")
        exit(1)

    # Handle nested cluster structure (cluster.cluster)
    if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
        cluster_data = cluster_data['cluster']

    # UID is stored in metadata.uid
    cluster_uid = cluster_data.get("metadata", {}).get("uid")
    logging.debug("Extracted cluster data successfully.")
    return cluster_uid

def map_failed_vms_by_namespace(data):
    failed_volume_map = defaultdict(set)
    # Handle both direct backup_info and nested backup.backup_info structures
    backup_info = data.get("backup", {}).get("backup_info", {}) or data.get("backup_info", {})
    volumes = backup_info.get("volumes", {})
    for vol in volumes:
        status = vol.get("status", {}).get("status")
        if status in ["4", "Failed"]:
            namespace = vol.get("namespace")
            vm_name = vol.get("virtual_machine_name")
            if namespace and vm_name:
                failed_volume_map[namespace].add(vm_name)
    return dict(failed_volume_map)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backup Processing Script")
    parser.add_argument("--cluster-name", required=True, help="Name of the application cluster")
    parser.add_argument("--cluster-uid", required=True, help="UID of the cluster to use")
    parser.add_argument("--timestamp", required=False,
                        help="Timestamp for filtering failed backups in MM/DD/YYYY HH:MMAM/PM format "
                             "e.g., 03/18/2025 07:25AM")
    parser.add_argument("--hours-ago", type=int,
                        help="Number of hours ago to use if no timestamp is provided. Defaults to 12.")
    parser.add_argument("--time-field", choices=["create_time", "completion_time"], default="completion_time",
                        help="Time field to use for filtering backups. Choose 'completion_time' (default) or 'create_time'.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")

    args = parser.parse_args()
    print(f"Logs are getting captured at {LOG_FILE}")
    retried_backups = []

    if not args.timestamp:
        hours = args.hours_ago if args.hours_ago else 12
        hours_ago_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
        args.timestamp = hours_ago_time.strftime("%m/%d/%Y %I:%M%p")
        logging.info(f"No timestamp provided. Defaulting to {hours} hours ago: {args.timestamp}")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cluster_name = args.cluster_name
    cluster_uid = args.cluster_uid
    logging.info(f"Backing up cluster: {cluster_name} with uid {cluster_uid}")
    logging.info(f"Using time field: {args.time_field} for filtering backups")
    enumerate_response = get_all_backups(cluster_name, cluster_uid)
    failed_backups = get_failed_backups(enumerate_response, args.timestamp, time_field=args.time_field)
    # print only the backup name from the failed backups
    failed_backup_names = [backup.get("metadata", {}).get("name") for backup in failed_backups]
    logging.debug(f"Enumerated backup list: {failed_backup_names}")
    lines = ["*** Summary of backups to be retried ***\n"]
    for backup in failed_backups:
        backup_name = backup.get("metadata", {}).get("name")
        backup_uid = backup.get("metadata", {}).get("uid")
        # Inspect Backup
        file_path = inspect_backup(backup_name, backup_uid)
        retried_backups.append(backup_name)
        data = load_json(file_path)
        if is_scheduled_backup(data):
            logging.info(f"Fetching resources for scheduled backup: {backup_name}")
            resources = get_resources_from_backup_schedule(data)
        else:
            logging.info(f"Fetching resources for manual backup: {backup_name}")
            resources = get_resources_from_backup(data)
        lines.append(f"\nVMs found in {backup_name}:\n")
        # Handle both direct backup_info and nested backup.backup_info structures
        backup_info = data.get("backup", {}).get("backup_info", {}) or data.get("backup_info", {})
        backup_status = backup_info.get("status", {}).get("status")
        if backup_status == "Failed":
            failed_volumes = defaultdict(set)
            for resource in resources:
                ns = resource.get("namespace")
                vm = resource.get("name")
                failed_volumes[ns].add(vm)
            failed_resources = resources
        else:
            # get the list of vms which has failed and map it with ns so that doesn't get added to resource
            failed_volumes = map_failed_vms_by_namespace(data)

            # Filter only the resources matching failed VMs
            failed_resources = []
            for resource in resources:
                ns = resource.get("namespace")
                vm_name = resource.get("name")
                if ns in failed_volumes and vm_name in failed_volumes[ns]:
                    failed_resources.append(resource)

        for ns, vm_names in failed_volumes.items():
            lines.append(f"Namespace: {ns}\n")
            for vm_name in vm_names:
                lines.append(f"  - {vm_name}\n")

        logging.debug(f"Resources to be backed up: {failed_resources}")
        if args.dry_run:
            logging.info("Dry run mode enabled. Skipping backup invocation.")
            continue
        logging.info(f"Invoking backup: {backup_name} with uid {backup_uid}")
        new_backup_name = invoke_backup(failed_resources, data)
        logging.debug(f"Created retry backup for failed VMs: {new_backup_name}")
    if retried_backups:
        lines.append(f"\n\nBackups which will be retried:\n")
        for backup in retried_backups:
            lines.append(f"{backup}\n")

    report_file_name = f"retry-failed-backups-{timestamp}.txt"
    report_str = "".join(lines)
    with open(report_file_name, "a") as f:
        f.write(report_str)
    print(f"Please check {report_file_name} for detailed report")