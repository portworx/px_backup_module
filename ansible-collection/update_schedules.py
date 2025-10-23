import json
from collections import defaultdict
import time
import subprocess
import json
import re
import argparse
import tempfile

import yaml


def run_ansible_playbook(playbook, extra_vars=None):
    """Run an Ansible playbook with given extra variables."""
    cmd = [
        "ansible-playbook", playbook, "-vvvv",
        "--extra-vars", json.dumps(extra_vars)
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Log output to a file
        LOG_FILE = "ansible_success.log"
        with open(LOG_FILE, "a") as log:
            log.write(f"--- Running {playbook} ---\n")
            log.write(result.stdout)
            log.write("\n\n")

        print("Successfully ran the playbook.")

        return result.stdout, None
    except subprocess.CalledProcessError as e:
        print("Failed to run playbook.")
        LOG_FILE = "ansible_failure.log"
        with open(LOG_FILE, "a") as log:
            log.write(f"--- Error in {playbook} ---\n")
            log.write(e.stdout)
            log.write("\n\n")
        return None, e.stderr


def fetch_schedules():
    """Runs the enumerate playbook to fetch all schedules."""

    output, error = run_ansible_playbook("examples/backup_schedule/enumerate_schedule.yaml")
    if error:
        print(f"Error fetching schedules: {error}")
        return None
    
    task_name = "List All Backup Schedule"

    # Find the first occurrence of the specified task
    task_start = output.find(f"TASK [{task_name}]")

    if task_start == -1:
        return f"Error: Could not locate task '{task_name}' in Ansible output."

    # Truncate the output from this task onward
    truncated_output = output[task_start:]

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
            return parsed_json
        except json.JSONDecodeError as e:
            return f"Error parsing JSON: {e}"
    else:
        print(f"Error: Could not extract JSON from task '{task_name}'.")
        return []

def filter_schedules(schedules, pattern, cluster_name):
    """Filters schedules matching the given pattern."""
    if isinstance(schedules, dict):
        schedules = schedules.get("backup_schedules", [])

    filtered_schedules = []
    for schedule in schedules:
        if not isinstance(schedule, dict) or "metadata" not in schedule or not isinstance(schedule["metadata"], dict):
            print(f"Skipping invalid schedule entry: {schedule}")
            continue

        name = schedule["metadata"].get("name", "")

        if re.match(pattern, name) and schedule["backup_schedule_info"].get("cluster_ref", {}).get("name", "") == cluster_name:
            filtered_schedules.append(schedule)

    return filtered_schedules

def update_schedules(matching_schedules):
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
                    "suspend": schedule["backup_schedule_info"].get("suspend", False),
                    "backup_location_ref": schedule["backup_schedule_info"].get("backup_location_ref", {}),
                    "schedule_policy_ref": schedule["backup_schedule_info"].get("schedule_policy_ref", {}),
                    "cluster_ref": schedule["backup_schedule_info"].get("cluster_ref", {}),
                    "backup_type": "Normal",
                    "backup_object_type": backup_object_type,
                    "skip_vm_auto_exec_rules": True,
                    "validate_certs": True,
                    "remark":"Schedule updated by script(update-schedules)",
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



if __name__ == "__main__":
    # Accept two command line arguments: pattern
    # Example usage: python delete_schedules.py <pattern>
    import sys
    if len(sys.argv) != 3:
        print("Usage: python delete_schedules.py <pattern>")
        sys.exit(1)

    pattern = sys.argv[1]
    cluster_name = sys.argv[2]
    print(f"Backup schedule name pattern: {pattern}")

    print("Fetching all VM backup schedules...")
    schedules = fetch_schedules()
    if not schedules:
        print("No schedules found or failed to fetch schedules.")
        exit(1)
    print(f"Found {len(schedules)} schedules.")

    print("Filtering VM schedules matching pattern:", pattern)
    matching_schedules = filter_schedules(schedules, pattern, cluster_name)

    print(f"Found {len(matching_schedules)} matching VM schedules.")
    # Print the name of the schedules
    for schedule in matching_schedules:
        print(schedule["metadata"]["name"])
    update_schedules(matching_schedules)