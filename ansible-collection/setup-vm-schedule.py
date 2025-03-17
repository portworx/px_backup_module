import base64
from datetime import datetime, timedelta
import json, subprocess, re, time, os

import yaml
from kubernetes import client, config


def create_schedule_policy_loop(start_time, interval, count=5):
    policy_name_uid = {}
    # Parse the start time (assumed to be in time.Kitchen format, e.g., "6:05PM")
    current_time = datetime.strptime(start_time, "%I:%M%p")

    for i in range(count):
        # Calculate new time by adding (i * interval) minutes to the start time
        new_time = current_time + timedelta(minutes=i * interval)
        # Format the new time in time.Kitchen format (e.g., "6:05PM")
        formatted_time = new_time.strftime("%I:%M%p").lstrip("0")
        # Create a policy name by removing colons from the formatted time
        policy_name = f"test-{formatted_time.replace(':', '')}"
        # Convert policy_name to lower case
        policy_name = policy_name.lower()

        # Construct extra-vars JSON object with the schedule_policies list
        extra_vars = json.dumps({
            "schedule_policies": [
                {
                    "name": policy_name,
                    "validate_certs": True,
                    "labels": {
                        "policy-label": "test-label"
                    },
                    "schedule_policy": {
                        "daily": {
                            "time": formatted_time,
                            "retain": 5,
                            "incremental_count": {
                                "count": 6
                            }
                        }
                    }
                }
            ]
        })

        print(f"[INFO] Creating schedule policy: {policy_name} with time {formatted_time}")
        cmd = [
            "ansible-playbook", "examples/schedule_policy/create.yaml", "-vvvv",
            "--extra-vars", extra_vars
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(f"[DEBUG] Ansible command for policy {policy_name} completed with return code: {result.returncode}")
        stdout_text = result.stdout
        if not stdout_text:
            print(f"[ERROR] No output from Ansible playbook for policy {policy_name}.")
            continue

        # Locate the "Create schedule policy" task output
        task_match = re.search(r"TASK \[Create schedule policy].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
        if not task_match:
            print(f"[ERROR] Could not find 'Create schedule policy' task output for policy {policy_name}.")
            continue
        task_output = task_match.group(1)

        # Extract JSON from the task output
        json_match = re.search(r'(\{.*\})', task_output, re.DOTALL)
        if not json_match:
            print(f"[ERROR] Could not extract JSON from 'Create schedule policy' task output for policy {policy_name}.")
            continue
        raw_json = json_match.group(1).strip()

        try:
            decoder = json.JSONDecoder()
            parsed_json, idx = decoder.raw_decode(raw_json)
            print(f"[INFO] Parsed JSON: {parsed_json}")
            timestamp = int(time.time())
            # output_file = f"schedule_policy_create_{policy_name}_{timestamp}.json"
            # with open(output_file, "w") as json_file:
            #     json.dump(parsed_json, json_file, indent=4)
            print(f"[SUCCESS] Created schedule policy successfully - {policy_name}")
            policy_name_uid[policy_name] = parsed_json.get("schedule_policy", {}).get("metadata", {}).get("uid")
        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON parsing failed for policy {policy_name}: {str(e)}")
        # Optional pause between iterations
        # time.sleep(2)
    return policy_name_uid

def get_cluster_info():
    return "ocp-pxe", "bbfe26ef-2c8f-4187-9ef3-797c0df9d476"

def inspect_cluster(cluster_name, cluster_uid):
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
        exit(1)

    task_output = task_match.group(1)

    # Step 2: Extract JSON between "cluster" and "clusters"
    json_match = re.search(r'"cluster"\s*:\s*({.*?})\s*,\s*"clusters"', task_output, re.DOTALL)
    if not json_match:
        print("[ERROR] Could not extract JSON between 'cluster' and 'clusters'.")
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


def create_kubeconfig(cluster_file):
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

def get_inventory(kubeconfig_file):
    from kubernetes import client, config

    # Load the provided kubeconfig file
    config.load_kube_config(kubeconfig_file)
    custom_api = client.CustomObjectsApi()

    group = "kubevirt.io"
    version = "v1"
    plural = "virtualmachines"
    vm_map = {}

    try:
        # List all VirtualMachine custom objects across the cluster
        result = custom_api.list_cluster_custom_object(
            group=group,
            version=version,
            plural=plural
        )
        # Iterate over each VirtualMachine and group by namespace
        for item in result.get("items", []):
            metadata = item.get("metadata", {})
            namespace = metadata.get("namespace", "default")
            name = metadata.get("name")
            if namespace and name:
                if namespace not in vm_map:
                    vm_map[namespace] = []
                vm_map[namespace].append(name)
    except Exception as e:
        print(f"Error listing all VirtualMachines: {e}")

    return vm_map


def invoke_backup(vm_map, policy_name_uid):
    # Extract necessary backup details

    backup_location_ref = {
        "name": "nfs1",
        "uid": "21393102-a15e-444e-8998-fda6236cc1b2"
    }
    cluster_ref = {
        "name": "ocp-pxe",
        "uid": "bbfe26ef-2c8f-4187-9ef3-797c0df9d476"
    }

    # Construct include_resources dynamically

    for namespace, vm_list in vm_map.items():
        for vm, (policy_name, policy_uid) in zip(vm_list, policy_name_uid.items()):
            timestamp = int(time.time())
            backup_name = f"gm-backup-{vm}-{namespace}-{timestamp}"
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
            skip_vm_auto_exec_rules = os.getenv("SKIP_VM_AUTO_EXEC_RULES", "True").lower() == "true"
            playbook_data = [{
                "name": "Configure PX-Backup Schedules",
                "hosts": "localhost",
                "gather_facts": False,
                "vars": {
                    "backup_schedules": [{
                        "name": backup_name,
                        "backup_location_ref": backup_location_ref,
                        "schedule_policy_ref": schedule_policy_ref,
                        "cluster_ref": cluster_ref,
                        "backup_type": "Normal",
                        "backup_object_type": {
                            "type": "VirtualMachine"
                        },
                        "skip_vm_auto_exec_rules": skip_vm_auto_exec_rules,
                        "validate_certs": True
                    }],
                    "vm_namespaces": vm_namespaces,  # Pass extracted namespaces
                    "include_resources": include_resources  # Pass extracted include_resources
                },
                "tasks": [
                    {
                        "name": "Create Backup Schedule",
                        "include_tasks": "examples/backup_schedule/create_vm_schedule.yaml"
                    }
                ]
            }]

            # Save generated playbook
            playbook_file = "create_vm_backup_retry.yaml"
            with open(playbook_file, "w") as f:
                yaml.safe_dump(playbook_data, f, default_flow_style=False)

            print(f"[INFO] Ansible playbook written to {playbook_file}")


            # Invoke the Ansible playbook and print the output
            combined_vars = json.dumps({
                "vm_namespaces": vm_namespaces,
                "include_resources": include_resources
            })
            ansible_cmd = [
                "ansible-playbook", playbook_file, "-vvvv",
                "--extra-vars", combined_vars
            ]

            result = subprocess.run(ansible_cmd, capture_output=True, text=True)

            print(f"[DEBUG] Ansible stdout: {result.stdout}")

            print(f"[DEBUG] Ansible command completed with return code: {result.returncode}")

            stdout_text = result.stdout
            if not stdout_text:
                print(f"[ERROR] No output from Ansible playbook for VM {vm}.")
                continue

            # Locate the "Create backup" task output
            task_match = re.search(r"TASK \[Create Backup Schedule\].*?\n(.*?)\nTASK ", stdout_text, re.DOTALL)
            if not task_match:
                print(f"[ERROR] Could not find 'Create backup' task output for VM {vm}.")
                continue
            task_output = task_match.group(1)

            # Extract JSON from the task output
            json_match = re.search(r'(\{.*\})', task_output, re.DOTALL)
            if not json_match:
                print(f"[ERROR] Could not extract JSON from 'Create backup' task output for VM {vm}.")
                continue
            raw_json = json_match.group(1).strip()

            try:
                decoder = json.JSONDecoder()
                parsed_json, idx = decoder.raw_decode(raw_json)
                timestamp = int(time.time())
                # output_file = f"backup_create_{vm}_{timestamp}.json"
                # with open(output_file, "w") as json_file:
                #     json.dump(parsed_json, json_file, indent=4)
                print(f"[SUCCESS] Created backup successfully - {vm}")
            except json.JSONDecodeError as e:
                print(f"[ERROR] JSON parsing failed for VM {vm}: {str(e)}")
            # Optional pause between iterations
            # time.sleep(2)



if __name__ == "__main__":

    policy_name_uid = create_schedule_policy_loop("4:15PM", 3, 3)
    print(f"Policy name to UID mapping: {policy_name_uid}")

    cluster_name, cluster_uid = get_cluster_info()

    if cluster_name and cluster_uid:
        cluster_file = inspect_cluster(cluster_name, cluster_uid)
        print(f"Cluster data saved")

    # Create kubeconfig file
    kubeconfig_file = create_kubeconfig(cluster_file)

    vm_by_ns = get_inventory(kubeconfig_file)

    # Print the VMs grouped by namespace
    for ns, vm_list in vm_by_ns.items():
        print(f"Namespace: {ns}")
        print(f"VMs: {', '.join(vm_list)}")
        print()

    total_vm_count = sum(len(vms) for vms in vm_by_ns.values())
    print("Total VM count in the cluster:", total_vm_count)

    # Create dummy vm_by_ns dictionary
    vm_by_ns = {
        "fed": ["vm-fed"],
        "win": ["win2k22-template-1", "vgm-win2k22-mssql-1"]
    }

    invoke_backup(vm_by_ns, policy_name_uid)



