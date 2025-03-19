import json
from collections import defaultdict
import time
import subprocess
import json
import re
import argparse
import tempfile

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
            parsed_json = json.loads(json_data)
            return parsed_json
        except json.JSONDecodeError as e:
            return f"Error parsing JSON: {e}"
    else:
        print(f"Error: Could not extract JSON from task '{task_name}'.")
        return []

def filter_schedules(schedules, pattern):
    """Filters schedules matching the given pattern."""
    if isinstance(schedules, dict):
        schedules = schedules.get("backup_schedules", [])

    filtered_schedules = []
    for schedule in schedules:
        if not isinstance(schedule, dict) or "metadata" not in schedule or not isinstance(schedule["metadata"], dict):
            print(f"Skipping invalid schedule entry: {schedule}")
            continue

        name = schedule["metadata"].get("name", "")
        uid = schedule["metadata"].get("uid", "")

        if re.match(pattern, name):
            filtered_schedules.append({"name": name, "uid": uid})

    return filtered_schedules

def delete_schedules(matching_schedules):
    """Runs the delete playbook for the matching schedules."""
    if not matching_schedules:
        print("No schedules matched the pattern. Skipping deletion.")
        return

    extra_vars = {
        "schedule_deletes": matching_schedules 
    }

    output, error = run_ansible_playbook("examples/backup_schedule/delete_schedule.yaml", extra_vars)
    if error:
        print(f"Error deleting schedules: {error}")
    else:
        print("Deletion results:\n", output)


if __name__ == "__main__":
    # Accept two command line arguments: pattern
    # Example usage: python delete_schedules.py <pattern>
    import sys
    if len(sys.argv) != 2:
        print("Usage: python delete_schedules.py <pattern>")
        sys.exit(1)

    pattern = sys.argv[1]
    print(f"Backup schedule name pattern: {pattern}")

    print("Fetching all VM backup schedules...")
    schedules = fetch_schedules()
    if not schedules:
        print("No schedules found or failed to fetch schedules.")
        exit(1)

    print("Filtering VM schedules matching pattern:", pattern)
    matching_schedules = filter_schedules(schedules, pattern)

    print(f"Found {len(matching_schedules)} matching VM schedules.")
    delete_schedules(matching_schedules)