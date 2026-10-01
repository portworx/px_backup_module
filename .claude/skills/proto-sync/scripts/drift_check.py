#!/usr/bin/env python3
"""Compare DOCUMENTATION.options with argument_spec for collection modules.

Usage (from ansible-collection/ or repo root):
    PYTHONDONTWRITEBYTECODE=1 python3 .claude/skills/proto-sync/scripts/drift_check.py backup backup_schedule

Prints, per module, top-level options that appear only in DOCUMENTATION or only
in argument_spec, after subtracting the known baseline below. An empty result
means no new drift. Update BASELINE when a listed param gets documented.

Limitations: top-level options only (nested suboptions are not compared), and
argument_spec is parsed by regex, so a module that builds module_args in an
unusual way prints "argument_spec regex miss".
"""
import os
import re
import sys

import yaml

# Known undocumented argument_spec params (spec-only) and documented-but-absent
# (doc-only) params as of 2026-10-01 on main. Not new drift.
BASELINE = {
    "backup": {
        "spec_only": {"exclude_failed_resource", "resource_info", "vm_volume_name"},
        "doc_only": set(),
    },
    "backup_schedule": {
        "spec_only": {"backup_location", "cloud_credential", "cluster", "delete_backups",
                      "schedule_policy", "exclude_failed_resource", "resource_info",
                      "vm_volume_name"},
        "doc_only": set(),
    },
    "backup_location": {
        "spec_only": {"azure_config", "cloud_credential_ref", "google_config"},
        # flattened sub-fields documented at top level
        "doc_only": {"cloud_credential_name", "cloud_credential_uid"},
    },
    "restore": {
        "spec_only": {"exclude_failed_resource", "resource_info", "vm_volume_name",
                      "cluster_name_filter", "cluster_uid_filter", "include_detailed_resources",
                      "max_objects", "name_filter", "owners", "status"},
        "doc_only": set(),
    },
    "cluster": {
        "spec_only": {"add_backup_share", "del_backup_share", "exclude_failed_resource",
                      "include_secrets", "resource_info", "vm_volume_name"},
        "doc_only": set(),
    },
    "cloud_credential": {"spec_only": {"include_secrets"}, "doc_only": set()},
    "schedule_policy": {"spec_only": {"include_secrets"}, "doc_only": set()},
    "receiver": {"spec_only": {"recipient_id"}, "doc_only": set()},
    "role": {
        "spec_only": {"exclude_failed_resource", "resource_info", "vm_volume_name"},
        "doc_only": set(),
    },
}


def find_collection_root():
    here = os.getcwd()
    for cand in (here, os.path.join(here, "ansible-collection")):
        if os.path.isdir(os.path.join(cand, "plugins", "modules")):
            return cand
    sys.exit("run from the repo root or ansible-collection/")


def check(root, m):
    path = os.path.join(root, "plugins", "modules", f"{m}.py")
    src = open(path).read()
    doc_m = re.search(r"DOCUMENTATION\s*=\s*r?'''(.*?)'''", src, re.S)
    if not doc_m:
        return f"{m}: DOCUMENTATION block not found"
    doc = yaml.safe_load(doc_m.group(1)) or {}
    doc_opts = set((doc.get("options") or {}).keys())
    spec_m = re.search(r"module_args\s*=\s*dict\((.*?)\n    \)", src, re.S)
    if not spec_m:
        return f"{m}: argument_spec regex miss"
    spec_opts = set(re.findall(r"^\s{8}(\w+)\s*=\s*dict\(", spec_m.group(1), re.M))
    base = BASELINE.get(m, {"spec_only": set(), "doc_only": set()})
    doc_only = sorted(doc_opts - spec_opts - base["doc_only"])
    spec_only = sorted(spec_opts - doc_opts - base["spec_only"])
    stale = sorted((base["doc_only"] - (doc_opts - spec_opts)) | (base["spec_only"] - (spec_opts - doc_opts)))
    lines = [f"{m}: doc-only {doc_only}  spec-only {spec_only}"]
    if stale:
        lines.append(f"{m}: baseline entries no longer drifting (trim BASELINE): {stale}")
    return "\n".join(lines)


def main():
    mods = sys.argv[1:]
    if not mods:
        print(__doc__)
        sys.exit(2)
    root = find_collection_root()
    for m in mods:
        print(check(root, m))


if __name__ == "__main__":
    main()
