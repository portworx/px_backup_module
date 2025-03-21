import json
from collections import defaultdict
import time
import subprocess
import json
import re
import argparse
import tempfile

schedule_policies = {}

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


def fetch_schedules(cluster_name):
    """Runs the enumerate playbook to fetch all schedules."""

    extra_vars = { "cluster_name_filter": cluster_name}
    output, error = run_ansible_playbook("examples/backup_schedule/enumerate_schedule.yaml", extra_vars)
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
            policy = schedule["backup_schedule_info"]["schedule_policy_ref"]
            uid = policy["uid"]
            schedule_policies[uid] = policy  # This will overwrite duplicates

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
        print("Deleted schedules: ", matching_schedules)

def fetch_policies():
    """Runs the enumerate playbook to fetch all policies."""

    output, error = run_ansible_playbook("examples/schedule_policy/enumerate_policy.yaml")
    if error:
        print(f"Error fetching policies: {error}")
        return None
    
    task_name = "Get list of schedule policies"

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

def filter_policies(policies, pattern):
    """Filters policies matching the given pattern."""
    if isinstance(policies, dict):
        policies = policies.get("schedule_policies", [])

    filtered_policies = []
    for policy in policies:
        if not isinstance(policy, dict) or "metadata" not in policy or not isinstance(policy["metadata"], dict):
            print(f"Skipping invalid policy entry: {policy}")
            continue

        name = policy["metadata"].get("name", "")
        uid = policy["metadata"].get("uid", "")

        if re.match(pattern, name):
            filtered_policies.append({"name": name, "uid": uid})

    return filtered_policies


def delete_policies(matching_policies):
    """Runs the delete playbook for the matching policies."""
    if not matching_policies:
        print("No policies matched the pattern. Skipping deletion.")
        return

    extra_vars = {
        "schedule_policies_delete": matching_policies 
    }

    output, error = run_ansible_playbook("examples/schedule_policy/delete_policy.yaml", extra_vars)
    if error:
        print(f"Error deleting policies: {error}")
    else:
        print("Deleted schedule policies: ", matching_policies)


if __name__ == "__main__":
    # Accept two command line arguments: pattern
    # Example usage: python delete_schedule_and_policy.py <pattern>
    import argparse

    parser = argparse.ArgumentParser(description="Delete schedules and policies by pattern.")
    parser.add_argument("schedule_pattern", help="Schedule name pattern")
    parser.add_argument("policy_pattern", nargs="?", default=None, help="(Optional) Policy name pattern")
    parser.add_argument("cluster_name", help="Cluster name")

    args = parser.parse_args()

    # Step 1: Fetch and filter schedules
    print("Fetching all VM backup schedules...")
    schedules = fetch_schedules(args.cluster_name)
    if not schedules:
        print("No schedules found or failed to fetch schedules.")
        exit(1)


    print("Filtering VM schedules matching pattern:", args.schedule_pattern)
    matching_schedules = filter_schedules(schedules, args.schedule_pattern)
    print(f"Found {len(matching_schedules)} matching VM schedules: ", matching_schedules)

    # Step 3: Delete matching schedules
    delete_schedules(matching_schedules)

    # Step 4: Wait until schedules are fully deleted (timeout: 5 mins)
    timeout = 300  # 5 minutes
    interval = 10  # check every 10 seconds
    elapsed = 0

    print("Waiting for schedules to be fully deleted...")
    while elapsed < timeout:
        current_schedules = fetch_schedules(args.cluster_name)
        remaining = filter_schedules(current_schedules, args.schedule_pattern)
        
        if not remaining:
            print("All matching schedules deleted.")
            break
        
        print(f"{len(remaining)} schedules still remaining. Retrying in {interval} seconds...")
        time.sleep(interval)
        elapsed += interval
    else:
        print("Timeout reached. Some schedules were not deleted.")
        exit(1) 

    # Step 5: Delete unique policies
    if not args.policy_pattern:
        print("No policy pattern provided. Deleting corresponding policies.")
        unique_policy_list = list(schedule_policies.values())
        print(f"Found schedule policies for above schedules: ", unique_policy_list)
        delete_policies(unique_policy_list)
    else:
        print(f"Schedule policy name pattern: {args.policy_pattern}")
        print("Fetching all policies...")
        policies = fetch_policies()
        if not policies:
            print("No policies found or failed to fetch policies.")
            exit(1)

        print("Filtering policies matching pattern:", args.policy_pattern)
        matching_policies = filter_policies(policies, args.policy_pattern)

        print(f"Found {len(matching_policies)} matching policies.")
        delete_policies(matching_policies)

        # Summary report
        print("\n=== Px-Backup Schedules and Policies Deletion Summary ===\n")
        print(f"\nCluster: {args.cluster_name} ")
        print(f"\nDeleted Schedules: {len(matching_schedules)}")
        for s in matching_schedules:
            print(f" - {s["name"]}")
        
        print(f"\nDeleted Policies: {len(matching_policies)}")
        for p in matching_policies:
            print(f" - {p["name"]}")