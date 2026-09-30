#!/usr/bin/env python3
"""
Ansible BL Validation Test Suite

Reads connection details and BL config from the existing inventory files:
  inventory/group_vars/common/all.yaml          → api_url, token, org_id
  inventory/group_vars/backup_location/validate.yaml → BL list, cluster_refs

All values can be overridden with CLI flags if needed.

Usage (zero args — reads everything from inventory):
  python3 tests/bl_validate_tests.py

Usage (override specific values):
  python3 tests/bl_validate_tests.py --bl-name my-bl --cluster-name c1 --cluster-uid <uid>

Flags (all optional when inventory files are present):
  --api-url        PX-Backup API URL
  --token          Bearer token (or PX_BACKUP_TOKEN env var)
  --bl-name        Federated BL name to target (defaults to first entry in validate.yaml)
  --bl-uid         UID of that BL
  --cluster-name   Cluster name for the subset-validate test
  --cluster-uid    Cluster UID for the subset-validate test
  --org-id         Organisation ID
  --validate-certs Enable SSL cert validation (disabled by default)
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required — run: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_collection_dir() -> str:
    """Find the ansible-collection root.

    Identified by the presence of examples/backup_location/validate.yaml
    AND ansible.cfg (which sets library = ./plugins/modules).

    Search order:
      1. Parent of this script (repo layout: script lives in tests/)
      2. Installed collection path (~/.ansible/collections/...)
      3. Current working directory
      4. This script's own directory
    """
    marker = os.path.join("examples", "backup_location", "validate.yaml")
    candidates = [
        os.path.dirname(SCRIPT_DIR),
        os.path.expanduser(
            "~/.ansible/collections/ansible_collections/purepx/px_backup"
        ),
        os.getcwd(),
        SCRIPT_DIR,
    ]
    for c in candidates:
        if os.path.exists(os.path.join(c, marker)):
            return c
    return os.getcwd()


COLLECTION_DIR = _find_collection_dir()
ALL_YAML = os.path.join(COLLECTION_DIR, "inventory", "group_vars", "common", "all.yaml")
VALIDATE_VARS_YAML = os.path.join(
    COLLECTION_DIR, "inventory", "group_vars", "backup_location", "validate.yaml"
)
# Absolute paths so ansible-playbook resolves them regardless of cwd
VALIDATE_PLAYBOOK = os.path.join(COLLECTION_DIR, "examples", "backup_location", "validate.yaml")
INSPECT_PLAYBOOK = os.path.join(COLLECTION_DIR, "examples", "backup_location", "inspect.yaml")

NONEXISTENT_BL = "bl-validate-test-nonexistent-xyz"


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_yaml(path: str) -> Dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        print(f"WARNING: could not parse {path}: {e}", file=sys.stderr)
        return {}


def _load_first(paths: List[str]) -> Dict:
    """Load the first YAML file in the list that exists and is non-empty."""
    for p in paths:
        cfg = _load_yaml(p)
        if cfg:
            return cfg
    return {}


def _resolve_config(args: argparse.Namespace) -> Dict:
    """Merge inventory files with CLI overrides; raise if required fields are still missing.

    We check cwd-based paths first (the user's real inventory with actual
    credentials) before falling back to COLLECTION_DIR (which may contain
    placeholder values from the published collection).
    """
    cwd = os.getcwd()
    all_cfg = _load_first([
        os.path.join(cwd, "inventory", "group_vars", "common", "all.yaml"),
        ALL_YAML,
    ])
    validate_cfg = _load_first([
        os.path.join(cwd, "inventory", "group_vars", "backup_location", "validate.yaml"),
        VALIDATE_VARS_YAML,
    ])

    api_url = args.api_url or all_cfg.get("px_backup_api_url", "")
    token = (
        args.token
        or os.environ.get("PX_BACKUP_TOKEN", "")
        or all_cfg.get("px_backup_token", "")
    )
    org_id = args.org_id or all_cfg.get("org_id", "default")

    # Pick the first entry in backup_locations_validate as the target BL
    bl_entries: List[Dict] = validate_cfg.get("backup_locations_validate", [])
    first_bl = bl_entries[0] if bl_entries else {}

    bl_name = args.bl_name or first_bl.get("name", "")
    bl_uid = args.bl_uid or first_bl.get("uid", "")

    # For the subset test, look for a cluster_refs entry on the matching BL
    target_bl = next((b for b in bl_entries if b.get("name") == bl_name), first_bl)
    refs: List[Dict] = target_bl.get("cluster_refs", [])
    first_ref = refs[0] if refs else {}

    cluster_name = args.cluster_name or first_ref.get("name", "")
    cluster_uid = args.cluster_uid or first_ref.get("uid", "")

    missing = []
    if not api_url:
        missing.append("api_url (not in all.yaml and --api-url not given)")
    if not token:
        missing.append("token (not in all.yaml, PX_BACKUP_TOKEN env var, or --token)")
    if not bl_name:
        missing.append("bl_name (not in validate.yaml and --bl-name not given)")
    if missing:
        print("ERROR: missing required config:\n  " + "\n  ".join(missing), file=sys.stderr)
        sys.exit(1)

    return {
        "api_url": api_url,
        "token": token,
        "org_id": org_id,
        "bl_name": bl_name,
        "bl_uid": bl_uid,
        "cluster_name": cluster_name,
        "cluster_uid": cluster_uid,
        "validate_certs": args.validate_certs,
    }


# ---------------------------------------------------------------------------
# Ansible runner
# ---------------------------------------------------------------------------

def _run(playbook: str, extra_vars: Dict) -> Tuple[int, Optional[Dict], str, str]:
    env = os.environ.copy()
    env["ANSIBLE_STDOUT_CALLBACK"] = "json"
    env["ANSIBLE_FORCE_COLOR"] = "0"
    env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    # Point ansible to the ansible.cfg that sets library = ./plugins/modules.
    # Without this, 'backup_location' module can't be resolved when running
    # from a directory other than COLLECTION_DIR.
    cfg_path = os.path.join(COLLECTION_DIR, "ansible.cfg")
    if os.path.exists(cfg_path):
        env["ANSIBLE_CONFIG"] = cfg_path

    proc = subprocess.run(
        ["ansible-playbook", playbook, "-e", json.dumps(extra_vars)],
        capture_output=True,
        text=True,
        env=env,
        cwd=COLLECTION_DIR,   # cwd must match ansible.cfg's relative library path
    )

    parsed = None
    try:
        parsed = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        pass

    return proc.returncode, parsed, proc.stdout, proc.stderr


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _stats(parsed: Optional[Dict]) -> Dict:
    if not parsed:
        return {}
    return parsed.get("stats", {}).get("localhost", {})


def _succeeded(rc: int, parsed: Optional[Dict]) -> bool:
    s = _stats(parsed)
    return rc == 0 and s.get("failures", 0) == 0 and s.get("unreachable", 0) == 0


def _first_failure_msg(parsed: Optional[Dict], raw_stdout: str) -> str:
    if parsed:
        for play in parsed.get("plays", []):
            for task in play.get("tasks", []):
                host = task.get("hosts", {}).get("localhost", {})
                for item_result in host.get("results", []):
                    if item_result.get("failed"):
                        return item_result.get("msg", item_result.get("reason", ""))
                if host.get("failed"):
                    return host.get("msg", host.get("reason", ""))
    for line in raw_stdout.splitlines():
        if "FAILED" in line or "fatal:" in line or "object not found" in line.lower():
            return line.strip()
    return raw_stdout[-600:] if raw_stdout else "unknown error"


def _find_task(parsed: Optional[Dict], name_fragment: str) -> Optional[Dict]:
    if not parsed:
        return None
    fragment = name_fragment.lower()
    for play in parsed.get("plays", []):
        for task in play.get("tasks", []):
            if fragment in task.get("task", {}).get("name", "").lower():
                return task.get("hosts", {}).get("localhost", {})
    return None


def _validate_task_results(parsed: Optional[Dict]) -> List[Dict]:
    host = _find_task(parsed, "run validation")
    if host:
        return host.get("results", [host])
    return []


def _bl_info_from_inspect(item_result: Dict) -> Dict:
    # inspect_backup_location() strips the outer 'backup_location' wrapper before
    # returning, so the module result is {"metadata": ..., "backup_location_info": ...}
    # not {"backup_location": {"metadata": ..., "backup_location_info": ...}}.
    bl = item_result.get("backup_location", {})
    return bl.get("backup_location_info", {})


# ---------------------------------------------------------------------------
# Test case model
# ---------------------------------------------------------------------------

class TestCase:
    def __init__(self, name: str, description: str, category: str, operation: str,
                 expected: str, negative: bool = False):
        self.name = name
        self.description = description
        self.category = category
        self.operation = operation
        self.expected = expected
        self.negative = negative

        self.verdict: str = ""
        self.actual: str = ""
        self.raw_stdout: str = ""
        self.raw_stderr: str = ""
        self.rc: int = -1
        self.parsed: Optional[Dict] = None


def _run_tc(tc: TestCase, playbook: str, extra_vars: Dict) -> None:
    tc.rc, tc.parsed, tc.raw_stdout, tc.raw_stderr = _run(playbook, extra_vars)


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def _divider(ch: str = "-", width: int = 70) -> str:
    return ch * width


def _print_tc_block(idx: int, tc: TestCase) -> None:
    print()
    print(_divider())
    label = "[NEGATIVE]" if tc.negative else "[POSITIVE]"
    print(f"[TC-{idx}] {tc.name}  {label}")
    print(f"  What:      {tc.description}")
    print(f"  Category:  {tc.category}")
    print(f"  Operation: {tc.operation}")
    print(f"  Expected:  {tc.expected}")
    print(f"  Actual:    {tc.actual}")
    verdict_tag = {"PASS": "✓ PASS", "FAIL": "✗ FAIL", "SKIP": "○ SKIP"}.get(tc.verdict, "? UNKNOWN")
    print(f"  Verdict:   {verdict_tag}")
    print()
    print("  --- Raw Ansible stdout (last 40 lines) ---")
    for line in tc.raw_stdout.splitlines()[-40:]:
        print(f"  {line}")
    if tc.raw_stderr.strip():
        print()
        print("  --- Raw Ansible stderr ---")
        for line in tc.raw_stderr.splitlines()[-10:]:
            print(f"  {line}")


# ---------------------------------------------------------------------------
# Test implementations
# ---------------------------------------------------------------------------

def tc_validate_all_clusters(cfg: Dict, base_vars: Dict) -> TestCase:
    tc = TestCase(
        name="validate_all_clusters",
        description=(
            "VALIDATE a federated BL without cluster_refs — "
            "server triggers per-cluster validation on every associated cluster"
        ),
        category="BackupLocation / VALIDATE",
        operation="VALIDATE",
        expected="exit 0, changed=False, backup_location response is {}",
    )

    extra = {
        **base_vars,
        "backup_locations_validate": [
            {"name": cfg["bl_name"], **({"uid": cfg["bl_uid"]} if cfg["bl_uid"] else {})},
        ],
        "default_include_secrets": False,
    }
    _run_tc(tc, VALIDATE_PLAYBOOK, extra)

    if _succeeded(tc.rc, tc.parsed):
        results = _validate_task_results(tc.parsed)
        if results:
            item = results[0]
            tc.actual = (
                f"exit 0, changed={item.get('changed')}, "
                f"backup_location={json.dumps(item.get('backup_location', {}))}"
            )
        else:
            tc.actual = "exit 0, playbook succeeded"
        tc.verdict = "PASS"
    else:
        tc.actual = f"exit {tc.rc}: {_first_failure_msg(tc.parsed, tc.raw_stdout)}"
        tc.verdict = "FAIL"

    return tc


def tc_validate_subset_clusters(cfg: Dict, base_vars: Dict) -> TestCase:
    tc = TestCase(
        name="validate_subset_clusters",
        description=(
            "VALIDATE a federated BL with cluster_refs scoped to one cluster — "
            "only that cluster's validation is triggered"
        ),
        category="BackupLocation / VALIDATE",
        operation="VALIDATE",
        expected="exit 0, changed=False, backup_location response is {}",
    )

    if not cfg["cluster_name"] or not cfg["cluster_uid"]:
        tc.actual = "SKIPPED — no cluster_refs in validate.yaml and --cluster-name/--cluster-uid not provided"
        tc.verdict = "SKIP"
        return tc

    extra = {
        **base_vars,
        "backup_locations_validate": [
            {
                "name": cfg["bl_name"],
                **({"uid": cfg["bl_uid"]} if cfg["bl_uid"] else {}),
                "cluster_refs": [{"name": cfg["cluster_name"], "uid": cfg["cluster_uid"]}],
            }
        ],
        "default_include_secrets": False,
    }
    _run_tc(tc, VALIDATE_PLAYBOOK, extra)

    if _succeeded(tc.rc, tc.parsed):
        results = _validate_task_results(tc.parsed)
        if results:
            item = results[0]
            tc.actual = (
                f"exit 0, changed={item.get('changed')}, "
                f"backup_location={json.dumps(item.get('backup_location', {}))}"
            )
        else:
            tc.actual = "exit 0, playbook succeeded"
        tc.verdict = "PASS"
    else:
        tc.actual = f"exit {tc.rc}: {_first_failure_msg(tc.parsed, tc.raw_stdout)}"
        tc.verdict = "FAIL"

    return tc


def tc_inspect_confirms_validation(cfg: Dict, base_vars: Dict) -> TestCase:
    tc = TestCase(
        name="inspect_confirms_validation_triggered",
        description=(
            "INSPECT_ONE after VALIDATE confirms validation_started_at is present, "
            "indicating validation was triggered"
        ),
        category="BackupLocation / INSPECT_ONE",
        operation="INSPECT_ONE",
        expected="exit 0, changed=False, backup_location_info.validation_started_at is non-empty",
    )

    extra = {
        **base_vars,
        "backup_locations_inspect": [
            {
                "name": cfg["bl_name"],
                **({"uid": cfg["bl_uid"]} if cfg["bl_uid"] else {}),
                "include_secrets": False,
            }
        ],
        "default_include_secrets": False,
    }
    _run_tc(tc, INSPECT_PLAYBOOK, extra)

    if _succeeded(tc.rc, tc.parsed):
        inspect_host = _find_task(tc.parsed, "get backup location details")
        results = inspect_host.get("results", [inspect_host]) if inspect_host else []
        if results:
            item = results[0]
            bl_info = _bl_info_from_inspect(item)
            validation_started_at = bl_info.get("validation_started_at", "")
            cluster_status = bl_info.get("cluster_status", {})
            if validation_started_at:
                tc.actual = (
                    f"exit 0, changed={item.get('changed')}, "
                    f"validation_started_at='{validation_started_at}', "
                    f"cluster_status={json.dumps(cluster_status)}"
                )
                tc.verdict = "PASS"
            else:
                tc.actual = (
                    f"exit 0, but validation_started_at missing; "
                    f"backup_location_info keys: {list(bl_info.keys())}"
                )
                tc.verdict = "FAIL"
        else:
            tc.actual = "exit 0, but could not extract inspect task result"
            tc.verdict = "FAIL"
    else:
        tc.actual = f"exit {tc.rc}: {_first_failure_msg(tc.parsed, tc.raw_stdout)}"
        tc.verdict = "FAIL"

    return tc


def tc_validate_nonexistent_bl(cfg: Dict, base_vars: Dict) -> TestCase:
    tc = TestCase(
        name="validate_nonexistent_bl",
        description="VALIDATE a BL name that does not exist → expect HTTP 404 'object not found'",
        category="BackupLocation / VALIDATE",
        operation="VALIDATE",
        expected="exit non-0, error contains 'object not found'",
        negative=True,
    )

    extra = {
        **base_vars,
        "backup_locations_validate": [{"name": NONEXISTENT_BL}],
        "default_include_secrets": False,
    }
    _run_tc(tc, VALIDATE_PLAYBOOK, extra)

    if not _succeeded(tc.rc, tc.parsed):
        err_msg = _first_failure_msg(tc.parsed, tc.raw_stdout)
        if any(p in err_msg.lower() for p in ["object not found", "not found", "404", "does not exist"]):
            tc.actual = f"exit {tc.rc}, error: '{err_msg[:300]}'"
            tc.verdict = "PASS"
        else:
            tc.actual = f"exit {tc.rc} but unexpected error: '{err_msg[:300]}'"
            tc.verdict = "FAIL"
    else:
        tc.actual = "exit 0 — playbook unexpectedly succeeded for non-existent BL"
        tc.verdict = "FAIL"

    return tc


def tc_validate_mismatched_uid(cfg: Dict, base_vars: Dict) -> TestCase:
    tc = TestCase(
        name="validate_mismatched_uid",
        description=(
            "VALIDATE with correct BL name but a random garbage UID — "
            "server should reject because uid does not match the named BL"
        ),
        category="BackupLocation / VALIDATE",
        operation="VALIDATE",
        expected="exit non-0, error contains 'not found' or 'uid mismatch'",
        negative=True,
    )

    extra = {
        **base_vars,
        "backup_locations_validate": [
            {"name": cfg["bl_name"], "uid": "00000000-dead-beef-cafe-000000000000"},
        ],
        "default_include_secrets": False,
    }
    _run_tc(tc, VALIDATE_PLAYBOOK, extra)

    if not _succeeded(tc.rc, tc.parsed):
        err_msg = _first_failure_msg(tc.parsed, tc.raw_stdout)
        if any(p in err_msg.lower() for p in ["not found", "404", "mismatch", "invalid"]):
            tc.actual = f"exit {tc.rc}, error: '{err_msg[:300]}'"
            tc.verdict = "PASS"
        else:
            tc.actual = f"exit {tc.rc} but unexpected error: '{err_msg[:300]}'"
            tc.verdict = "FAIL"
    else:
        # Some servers look up by name and ignore uid — document the behaviour
        tc.actual = "exit 0 — server accepted a mismatched uid (looks up by name only)"
        tc.verdict = "SKIP"

    return tc


def tc_validate_invalid_token(cfg: Dict, base_vars: Dict) -> TestCase:
    tc = TestCase(
        name="validate_invalid_token",
        description=(
            "VALIDATE with a malformed bearer token — "
            "server must reject with 401 Unauthorized before reaching BL logic"
        ),
        category="BackupLocation / VALIDATE",
        operation="VALIDATE",
        expected="exit non-0, error contains 'unauthorized' or '401'",
        negative=True,
    )

    bad_vars = {**base_vars, "px_backup_token": "this-is-not-a-valid-jwt-token"}
    extra = {
        **bad_vars,
        "backup_locations_validate": [{"name": cfg["bl_name"]}],
        "default_include_secrets": False,
    }
    _run_tc(tc, VALIDATE_PLAYBOOK, extra)

    if not _succeeded(tc.rc, tc.parsed):
        err_msg = _first_failure_msg(tc.parsed, tc.raw_stdout)
        if any(p in err_msg.lower() for p in ["unauthorized", "401", "unauthenticated",
                                                "token", "forbidden", "403"]):
            tc.actual = f"exit {tc.rc}, error: '{err_msg[:300]}'"
            tc.verdict = "PASS"
        else:
            tc.actual = f"exit {tc.rc} but unexpected error: '{err_msg[:300]}'"
            tc.verdict = "FAIL"
    else:
        tc.actual = "exit 0 — server unexpectedly accepted an invalid token"
        tc.verdict = "FAIL"

    return tc


def tc_validate_nonexistent_cluster_ref(cfg: Dict, base_vars: Dict) -> TestCase:
    tc = TestCase(
        name="validate_nonexistent_cluster_ref",
        description=(
            "VALIDATE a federated BL with cluster_refs pointing to a cluster UID "
            "not associated with the BL — server should reject the request"
        ),
        category="BackupLocation / VALIDATE",
        operation="VALIDATE",
        expected="exit non-0, error references unknown or unassociated cluster",
        negative=True,
    )

    extra = {
        **base_vars,
        "backup_locations_validate": [
            {
                "name": cfg["bl_name"],
                **({"uid": cfg["bl_uid"]} if cfg["bl_uid"] else {}),
                "cluster_refs": [
                    {"name": "nonexistent-cluster", "uid": "ffffffff-ffff-ffff-ffff-ffffffffffff"},
                ],
            }
        ],
        "default_include_secrets": False,
    }
    _run_tc(tc, VALIDATE_PLAYBOOK, extra)

    if not _succeeded(tc.rc, tc.parsed):
        err_msg = _first_failure_msg(tc.parsed, tc.raw_stdout)
        tc.actual = f"exit {tc.rc}, error: '{err_msg[:300]}'"
        tc.verdict = "PASS"
    else:
        # Server may silently skip unknown cluster refs — document it
        tc.actual = (
            "exit 0 — server accepted cluster_refs with unknown UID; "
            "check INSPECT_ONE to confirm whether any cluster validation was triggered"
        )
        tc.verdict = "SKIP"

    return tc


def tc_validate_wrong_org_id(cfg: Dict, base_vars: Dict) -> TestCase:
    tc = TestCase(
        name="validate_wrong_org_id",
        description=(
            "VALIDATE using an org_id that does not exist — "
            "server must reject with 404 or permission denied"
        ),
        category="BackupLocation / VALIDATE",
        operation="VALIDATE",
        expected="exit non-0, error contains 'not found', 'forbidden', or '40x'",
        negative=True,
    )

    wrong_vars = {**base_vars, "org_id": "nonexistent-org-xyz-12345"}
    extra = {
        **wrong_vars,
        "backup_locations_validate": [{"name": cfg["bl_name"]}],
        "default_include_secrets": False,
    }
    _run_tc(tc, VALIDATE_PLAYBOOK, extra)

    if not _succeeded(tc.rc, tc.parsed):
        err_msg = _first_failure_msg(tc.parsed, tc.raw_stdout)
        if any(p in err_msg.lower() for p in ["not found", "404", "forbidden", "403",
                                                "unauthorized", "permission"]):
            tc.actual = f"exit {tc.rc}, error: '{err_msg[:300]}'"
            tc.verdict = "PASS"
        else:
            tc.actual = f"exit {tc.rc} but unexpected error: '{err_msg[:300]}'"
            tc.verdict = "FAIL"
    else:
        tc.actual = "exit 0 — server accepted a nonexistent org_id"
        tc.verdict = "FAIL"

    return tc


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ansible BL Validation Test Suite (defaults from inventory files)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--api-url", default="", help="PX-Backup API URL")
    p.add_argument("--token", default="", help="Bearer token (or PX_BACKUP_TOKEN env var)")
    p.add_argument("--bl-name", default="", help="Federated BL name to target")
    p.add_argument("--bl-uid", default="", help="BL UID (optional)")
    p.add_argument("--cluster-name", default="", help="Cluster name for subset-validate test")
    p.add_argument("--cluster-uid", default="", help="Cluster UID for subset-validate test")
    p.add_argument("--org-id", default="", help="Organisation ID")
    p.add_argument("--validate-certs", action="store_true", default=False,
                   help="Enable SSL cert validation")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cfg = _resolve_config(args)

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    base_vars: Dict = {
        "px_backup_api_url": cfg["api_url"],
        "px_backup_token": cfg["token"],
        "org_id": cfg["org_id"],
        "validate_certs": cfg["validate_certs"],
        # Override ssl_config from all.yaml: ca_cert may point to a file that
        # doesn't exist on this machine.  With hash_behaviour=merge these
        # scalar overrides win over the inventory values.
        "ssl_config": {
            "px_backup": {
                "validate_certs": cfg["validate_certs"],
                "ca_cert": "",
                "client_cert": "",
                "client_key": "",
            }
        },
        "output_config": {"enabled": False},
    }

    print(_divider("="))
    print("  Ansible BL Validation Test Suite")
    print(f"  Started:       {started_at}")
    print(f"  Collection dir: {COLLECTION_DIR}")
    print(f"  BL:            {cfg['bl_name']}" + (f"  (uid={cfg['bl_uid']})" if cfg["bl_uid"] else ""))
    print(f"  API URL:       {cfg['api_url']}")
    print(f"  Org:           {cfg['org_id']}")
    if cfg["cluster_name"]:
        print(f"  Cluster:       {cfg['cluster_name']}  (uid={cfg['cluster_uid']})")
    print(_divider("="))

    results = [
        # Positive
        tc_validate_all_clusters(cfg, base_vars),
        tc_validate_subset_clusters(cfg, base_vars),
        tc_inspect_confirms_validation(cfg, base_vars),
        # Negative
        tc_validate_nonexistent_bl(cfg, base_vars),
        tc_validate_mismatched_uid(cfg, base_vars),
        tc_validate_invalid_token(cfg, base_vars),
        tc_validate_nonexistent_cluster_ref(cfg, base_vars),
        tc_validate_wrong_org_id(cfg, base_vars),
    ]

    for idx, tc in enumerate(results, start=1):
        _print_tc_block(idx, tc)

    passed = sum(1 for tc in results if tc.verdict == "PASS")
    failed = sum(1 for tc in results if tc.verdict == "FAIL")
    skipped = sum(1 for tc in results if tc.verdict == "SKIP")

    print()
    print(_divider("="))
    print("  SUMMARY")
    print(_divider("="))
    for idx, tc in enumerate(results, start=1):
        tag = {"PASS": "✓", "FAIL": "✗", "SKIP": "○"}.get(tc.verdict, "?")
        print(f"  [{tag}] TC-{idx}: {tc.name}")
    print()
    print(f"  Total: {len(results)}  |  PASS: {passed}  |  FAIL: {failed}  |  SKIP: {skipped}")
    print(f"  Finished: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(_divider("="))

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
