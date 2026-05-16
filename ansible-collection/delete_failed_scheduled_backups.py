#!/usr/bin/env python3
"""
Delete Failed VM backups associated with scheduled backups in PX-Backup.

Per-cluster, per-VM-schedule, this script:
  1. enumerates VirtualMachine-type schedules in the org
  2. for each schedule, enumerates VirtualMachine-type backups whose status is
     "Failed"
  3. sorts them by metadata.create_time ascending
  4. issues a DELETE for each (no polling for Deleting -> Done completion); the
     backup will move to Deleting, and may stall in DeletingPending until the
     dependency link is broken out-of-band -- that is intentionally NOT handled
     here.

Scope: VirtualMachine backups only (backup_object_type="VirtualMachine"). The
filter is applied server-side on both the schedule and backup enumerate calls.

Connection details come from a .env file next to the script. See .env.sample
for the schema.

Usage:
  python3 delete_failed_scheduled_backups.py [--dry-run]
                                             [--cluster-name NAME]
                                             [--schedule-name NAME]
                                             [--limit N]
                                             [--env-file PATH]
                                             [-v]

Validated against px-backup-api proto v2.11.0 (pkg/apis/v1/api.proto).
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import json
import logging
import os
import signal
import sys
from typing import Any, Dict, List, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_NOW_UTC = datetime.datetime.now(datetime.timezone.utc)
TIMESTAMP = _NOW_UTC.strftime("%Y%m%dT%H%M%SZ")
LOG_FILE = os.path.join(SCRIPT_DIR, f"delete-failed-scheduled-backups_{TIMESTAMP}.log")
REPORT_TXT = os.path.join(SCRIPT_DIR, f"delete-failed-scheduled-backups_{TIMESTAMP}.txt")
REPORT_JSON = os.path.join(SCRIPT_DIR, f"delete-failed-scheduled-backups_{TIMESTAMP}.json")
LOCK_FILE = os.path.join(SCRIPT_DIR, ".delete-failed-scheduled-backups.lock")

# Hard ceiling on pagination loop iterations as a safety net against a buggy
# server that ignores object_index and returns the same batch forever.
MAX_PAGINATION_ITERS = 10000

# Form keys to redact from any echoed server error body.
SENSITIVE_FORM_KEYS = ("password", "client_secret", "refresh_token", "code")


# ---------------------------------------------------------------------------
# Env loading (no python-dotenv dependency to keep install footprint minimal)
# ---------------------------------------------------------------------------
def load_env_file(path: str) -> None:
    """Parse a simple KEY=VALUE .env file and inject into os.environ.

    Shell environment wins over .env (setdefault semantics), but we WARN on
    each override so credential mix-ups are visible to the operator.
    """
    if not os.path.exists(path):
        logging.warning("env file not found at %s; relying on process env only", path)
        return
    overridden: List[str] = []
    with open(path, "r", encoding="utf-8") as fp:
        for lineno, raw in enumerate(fp, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                logging.warning("skipping malformed env line %d: %s", lineno, raw.rstrip())
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if key in os.environ and os.environ[key] != value:
                overridden.append(key)
            os.environ.setdefault(key, value)
    if overridden:
        logging.warning(
            "Shell env overrides .env for keys %s; using shell values. "
            "Unset them if you want %s to take effect.",
            overridden, path,
        )


def required_env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise SystemExit(f"Required env var {key!r} is missing from environment / .env")
    return val


def env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def env_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"env var {key}={raw!r} must be an integer")


# ---------------------------------------------------------------------------
# HTTP error redaction
# ---------------------------------------------------------------------------
def _safe_response_summary(resp: Optional[requests.Response]) -> str:
    """Build a logger-safe summary of an HTTP error response.

    Never echoes raw bodies that may contain request form data. Tries JSON,
    extracts only standard error fields. Falls back to status_code + content
    type + truncated head for HTML/text bodies.
    """
    if resp is None:
        return "no response"
    summary = f"status={resp.status_code}"
    ctype = resp.headers.get("Content-Type", "")
    if "json" in ctype.lower():
        try:
            j = resp.json()
            for key in ("error", "error_description", "message", "code"):
                if key in j:
                    summary += f" {key}={j[key]!r}"
            return summary
        except ValueError:
            pass
    summary += f" content_type={ctype!r} body_head={resp.text[:160]!r}"
    return summary


# ---------------------------------------------------------------------------
# HTTP / auth
# ---------------------------------------------------------------------------
def _build_session(verify: Any) -> requests.Session:
    """requests Session with retry on 5xx/connection errors.

    urllib3<1.26 uses method_whitelist; >=1.26 uses allowed_methods. Try the
    new name first and fall back to the old to stay compatible with whatever
    requests/urllib3 the customer has installed.
    """
    session = requests.Session()
    methods = frozenset(("GET", "POST", "DELETE"))
    common = dict(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(502, 503, 504),
        raise_on_status=False,
    )
    try:
        retry = Retry(allowed_methods=methods, **common)
    except TypeError:
        retry = Retry(method_whitelist=methods, **common)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify
    return session


class PXBackupClient:
    """Minimal HTTP client for PX-Backup API."""

    def __init__(
        self,
        api_url: str,
        token: str,
        session: requests.Session,
    ) -> None:
        if not api_url.startswith(("http://", "https://")):
            api_url = f"http://{api_url}"
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.session = session
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        logging.debug("HTTP %s %s", method, url)
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=self.headers,
                params=params,
                json=json_body,
                timeout=60,
            )
            response.raise_for_status()
            if not response.content:
                return {}
            try:
                return response.json()
            except ValueError as exc:
                raise RuntimeError(
                    f"{method} {url} returned non-JSON body "
                    f"(status={response.status_code}, "
                    f"content_type={response.headers.get('Content-Type','')!r}, "
                    f"body_head={response.text[:200]!r})"
                ) from exc
        except requests.exceptions.RequestException as exc:
            resp = getattr(exc, "response", None)
            raise RuntimeError(
                f"{method} {url} failed: {exc.__class__.__name__}: "
                f"{_safe_response_summary(resp)}"
            ) from exc


def request_bearer_token(
    central_url: str,
    client_id: str,
    username: str,
    password: str,
    token_duration: str,
    session: requests.Session,
) -> str:
    if not central_url.startswith(("http://", "https://")):
        central_url = f"http://{central_url}"
    url = f"{central_url.rstrip('/')}/auth/realms/master/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
        "token-duration": token_duration,
    }
    try:
        response = session.post(
            url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        resp = getattr(exc, "response", None)
        # NEVER include the raw response body here -- some proxies echo form
        # params back, which would leak the password into our logs.
        raise RuntimeError(
            f"auth POST {url} failed: {exc.__class__.__name__}: "
            f"{_safe_response_summary(resp)}"
        ) from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"auth POST {url} succeeded but returned non-JSON body "
            f"(status={response.status_code}, "
            f"content_type={response.headers.get('Content-Type','')!r})"
        ) from exc

    token = payload.get("access_token")
    if not token:
        raise RuntimeError("auth response did not contain access_token")
    return token


# ---------------------------------------------------------------------------
# PX-Backup API wrappers (proto: pkg/apis/v1/api.proto @ branch 2.11.0)
# ---------------------------------------------------------------------------
def enumerate_clusters(client: PXBackupClient, org_id: str) -> List[Dict[str, Any]]:
    """GET /v1/cluster/{org_id} -> ClusterEnumerateResponse"""
    resp = client.request("GET", f"v1/cluster/{org_id}")
    return resp.get("clusters", []) or []


def enumerate_schedules_for_cluster(
    client: PXBackupClient,
    org_id: str,
    cluster_name: str,
    cluster_uid: str,
    page_size: int,
) -> List[Dict[str, Any]]:
    """POST /v1/backupschedule/{org_id}/enumerate -- paginated via object_index."""
    schedules: List[Dict[str, Any]] = []
    offset = 0
    for it in range(MAX_PAGINATION_ITERS):
        body = {
            "org_id": org_id,
            "enumerate_options": {
                "cluster_name_filter": cluster_name,
                "cluster_uid_filter": cluster_uid,
                "backup_object_type": "VirtualMachine",
                "max_objects": page_size,
                "object_index": offset,
            },
        }
        resp = client.request(
            "POST", f"v1/backupschedule/{org_id}/enumerate", json_body=body
        )
        batch = resp.get("backup_schedules", []) or []
        schedules.extend(batch)
        if resp.get("complete") or not batch:
            return schedules
        offset += len(batch)
    logging.error(
        "Pagination cap (%d) hit while enumerating schedules for cluster %s; "
        "server may be ignoring object_index. Bailing with %d schedules.",
        MAX_PAGINATION_ITERS, cluster_name, len(schedules),
    )
    return schedules


def enumerate_failed_backups_for_schedule(
    client: PXBackupClient,
    org_id: str,
    cluster_name: str,
    cluster_uid: str,
    schedule_name: str,
    schedule_uid: str,
    page_size: int,
) -> List[Dict[str, Any]]:
    """POST /v1/backup/{org_id}/enumerate filtered by backup_schedule_ref + status=Failed."""
    backups: List[Dict[str, Any]] = []
    offset = 0
    for it in range(MAX_PAGINATION_ITERS):
        body = {
            "org_id": org_id,
            "enumerate_options": {
                "cluster_name_filter": cluster_name,
                "cluster_uid_filter": cluster_uid,
                "status": ["Failed"],
                "backup_object_type": "VirtualMachine",
                # EnumerateOptions.backup_schedule_ref is repeated ObjectRef -> must be an array
                "backup_schedule_ref": [
                    {"name": schedule_name, "uid": schedule_uid}
                ],
                "max_objects": page_size,
                "object_index": offset,
                "sort_option": {
                    "sortBy": {"type": "CreationTimestamp"},
                    "sortOrder": {"type": "Ascending"},
                },
            },
        }
        resp = client.request(
            "POST", f"v1/backup/{org_id}/enumerate", json_body=body
        )
        batch = resp.get("backups", []) or []
        backups.extend(batch)
        if resp.get("complete") or not batch:
            return backups
        offset += len(batch)
    logging.error(
        "Pagination cap (%d) hit while enumerating backups for schedule %s; "
        "server may be ignoring object_index. Bailing with %d backups.",
        MAX_PAGINATION_ITERS, schedule_name, len(backups),
    )
    return backups


def delete_backup(
    client: PXBackupClient,
    org_id: str,
    name: str,
    uid: str,
    cluster_ref: Dict[str, str],
) -> Dict[str, Any]:
    """DELETE /v1/backup/{org_id}/{name} with uid + cluster_ref query params."""
    params: Dict[str, Any] = {"uid": uid}
    if cluster_ref:
        if cluster_ref.get("name"):
            params["cluster_ref.name"] = cluster_ref["name"]
        if cluster_ref.get("uid"):
            params["cluster_ref.uid"] = cluster_ref["uid"]
    return client.request("DELETE", f"v1/backup/{org_id}/{name}", params=params)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
    )


def safe_get(d: Dict[str, Any], *path: str, default: Any = None) -> Any:
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur


def filter_clusters(
    clusters: List[Dict[str, Any]], cluster_name_filter: Optional[str]
) -> List[Dict[str, Any]]:
    if not cluster_name_filter:
        return clusters
    return [c for c in clusters if safe_get(c, "metadata", "name") == cluster_name_filter]


def filter_schedules(
    schedules: List[Dict[str, Any]], schedule_name_filter: Optional[str]
) -> List[Dict[str, Any]]:
    if not schedule_name_filter:
        return schedules
    return [s for s in schedules if safe_get(s, "metadata", "name") == schedule_name_filter]


def cluster_ref_from_backup(backup: Dict[str, Any]) -> Dict[str, str]:
    info = backup.get("backup_info", {}) or {}
    ref = info.get("cluster_ref", {}) or {}
    name = ref.get("name") or info.get("cluster") or ""
    uid = ref.get("uid") or ""
    if not name and not uid:
        logging.warning(
            "Backup %s has no cluster_ref.name and no cluster_ref.uid; "
            "DELETE may fail server-side validation.",
            safe_get(backup, "metadata", "name", default="<unknown>"),
        )
    elif not uid:
        logging.warning(
            "Backup %s has cluster_ref.name=%r but no uid; "
            "DELETE may be ambiguous in multi-cluster orgs.",
            safe_get(backup, "metadata", "name", default="<unknown>"), name,
        )
    return {"name": name, "uid": uid}


def write_reports(summary: Dict[str, Any], records: List[Dict[str, Any]]) -> None:
    """Write JSON + TXT reports. Safe to call from a finally block."""
    with open(REPORT_JSON, "w", encoding="utf-8") as fp:
        json.dump(summary, fp, indent=2, default=str)

    with open(REPORT_TXT, "w", encoding="utf-8") as fp:
        fp.write("*** Delete-Failed-Scheduled-Backups Summary ***\n")
        fp.write(f"timestamp_utc: {summary['timestamp_utc']}\n")
        fp.write(f"org_id: {summary['org_id']}\n")
        fp.write(f"dry_run: {summary['dry_run']}\n")
        for k, v in summary["filters"].items():
            fp.write(f"filter.{k}: {v}\n")
        fp.write("\n")
        for k, v in summary["totals"].items():
            fp.write(f"totals.{k}: {v}\n")
        fp.write("\n")
        for rec in records:
            fp.write(
                f"[{rec['status']}] cluster={rec['cluster']} schedule={rec['schedule']}"
                f" backup={rec['backup_name']} uid={rec['backup_uid']}"
                f" create_time={rec['create_time']}"
                + (f" error={rec.get('error')}" if rec.get("error") else "")
                + "\n"
            )


def acquire_singleton_lock() -> Any:
    """Acquire an exclusive non-blocking flock on LOCK_FILE.

    Returns the open fd (must stay open for the process lifetime). Raises
    SystemExit on contention.
    """
    fd = open(LOCK_FILE, "w")
    try:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fd.close()
        raise SystemExit(
            f"another instance is already running (lockfile {LOCK_FILE}). "
            "Wait for it to finish or remove the lockfile if you are sure no "
            "other run is in flight."
        )
    fd.write(str(os.getpid()))
    fd.flush()
    return fd


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Delete Failed VM backups associated with each scheduled backup across "
            "all clusters in the org. Connection details come from a .env file."
        )
    )
    parser.add_argument("--env-file", default=os.path.join(SCRIPT_DIR, ".env"))
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List backups that would be deleted without issuing any DELETE",
    )
    parser.add_argument(
        "--cluster-name",
        help="Limit run to this single cluster name (uid is auto-resolved)",
    )
    parser.add_argument(
        "--schedule-name",
        help="Limit run to this single schedule name (across selected clusters)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Safety cap: max number of deletions to issue this run (0 = unlimited)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    configure_logging(args.verbose)
    load_env_file(args.env_file)

    # Required env
    api_url = required_env("PX_BACKUP_API_URL")
    central_url = required_env("PX_CENTRAL_URL")
    client_id = required_env("PX_CENTRAL_CLIENT_ID")
    username = required_env("PXB_USERNAME")
    password = required_env("PXB_PASSWORD")

    # Optional env with defaults
    org_id = os.environ.get("ORG_ID", "default")
    token_duration = os.environ.get("TOKEN_DURATION", "365d")
    page_size = env_int("MAX_OBJECTS_PER_PAGE", 200)
    ssl_verify_env = env_bool("SSL_VERIFY", True)
    ca_cert_path = os.environ.get("CA_CERT_PATH") or None
    dry_run = args.dry_run or env_bool("DRY_RUN", False)

    if ca_cert_path:
        verify: Any = ca_cert_path
    else:
        verify = ssl_verify_env

    if verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    lock_fd = acquire_singleton_lock()
    del lock_fd  # keep reference alive via process; suppress unused-var lint
    # (do not close: closing releases the flock)

    logging.info("Logs at %s", LOG_FILE)
    logging.info(
        "Run mode: dry_run=%s cluster_filter=%s schedule_filter=%s limit=%d page_size=%d",
        dry_run, args.cluster_name, args.schedule_name, args.limit, page_size,
    )

    session = _build_session(verify)

    logging.info("Authenticating against %s", central_url)
    token = request_bearer_token(
        central_url, client_id, username, password, token_duration, session
    )
    client = PXBackupClient(api_url, token, session)

    report_records: List[Dict[str, Any]] = []
    total_attempted = 0
    total_succeeded = 0
    total_failed = 0
    aborted_by_limit = False
    aborted_by_signal = False
    clusters: List[Dict[str, Any]] = []

    def _build_summary() -> Dict[str, Any]:
        return {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "org_id": org_id,
            "dry_run": dry_run,
            "filters": {
                "cluster_name": args.cluster_name,
                "schedule_name": args.schedule_name,
                "limit": args.limit,
            },
            "totals": {
                "clusters_considered": len(clusters),
                "deletions_attempted": total_attempted,
                "deletions_succeeded": total_succeeded,
                "deletions_failed": total_failed,
                "dry_run_listed": sum(1 for r in report_records if r["status"] == "dry-run"),
                "aborted_by_limit": aborted_by_limit,
                "aborted_by_signal": aborted_by_signal,
            },
            "records": report_records,
        }

    interrupted = {"flag": False}

    def _sigint_handler(signum: int, frame: Any) -> None:
        interrupted["flag"] = True
        logging.warning("Received signal %s; will flush partial report and exit.", signum)

    signal.signal(signal.SIGINT, _sigint_handler)
    signal.signal(signal.SIGTERM, _sigint_handler)

    try:
        logging.info("Enumerating clusters in org_id=%s", org_id)
        clusters = enumerate_clusters(client, org_id)
        clusters = filter_clusters(clusters, args.cluster_name)
        logging.info("Clusters in scope: %d", len(clusters))

        for cluster in clusters:
            if interrupted["flag"]:
                aborted_by_signal = True
                break

            c_name = safe_get(cluster, "metadata", "name", default="<unknown>")
            c_uid = safe_get(cluster, "metadata", "uid", default="")
            logging.info("Cluster: %s (uid=%s)", c_name, c_uid)

            try:
                schedules = enumerate_schedules_for_cluster(
                    client, org_id, c_name, c_uid, page_size
                )
            except Exception as exc:
                logging.error("Failed to enumerate schedules for cluster %s: %s", c_name, exc)
                continue

            schedules = filter_schedules(schedules, args.schedule_name)
            logging.info("  Schedules in scope: %d", len(schedules))

            for sched in schedules:
                if interrupted["flag"]:
                    aborted_by_signal = True
                    break

                s_name = safe_get(sched, "metadata", "name", default="<unknown>")
                s_uid = safe_get(sched, "metadata", "uid", default="")
                try:
                    failed = enumerate_failed_backups_for_schedule(
                        client, org_id, c_name, c_uid, s_name, s_uid, page_size
                    )
                except Exception as exc:
                    logging.error(
                        "  Failed to enumerate backups for schedule %s/%s: %s",
                        c_name, s_name, exc,
                    )
                    continue

                # Defensive sort: server is asked to sort ascending, but normalize anyway.
                failed.sort(key=lambda b: safe_get(b, "metadata", "create_time", default=""))

                logging.info("  Schedule: %s -> Failed backups: %d", s_name, len(failed))

                for backup in failed:
                    if interrupted["flag"]:
                        aborted_by_signal = True
                        break
                    if args.limit and total_attempted >= args.limit:
                        aborted_by_limit = True
                        logging.warning(
                            "Reached --limit=%d; stopping further deletions",
                            args.limit,
                        )
                        break

                    b_name = safe_get(backup, "metadata", "name", default="<unknown>")
                    b_uid = safe_get(backup, "metadata", "uid", default="")
                    cref = cluster_ref_from_backup(backup)
                    create_time = safe_get(backup, "metadata", "create_time", default="")

                    record: Dict[str, Any] = {
                        "cluster": c_name,
                        "schedule": s_name,
                        "backup_name": b_name,
                        "backup_uid": b_uid,
                        "create_time": create_time,
                        "cluster_ref": cref,
                        "dry_run": dry_run,
                    }

                    if dry_run:
                        logging.info(
                            "    DRY-RUN would delete backup=%s uid=%s create_time=%s",
                            b_name, b_uid, create_time,
                        )
                        record["accepted"] = None
                        record["status"] = "dry-run"
                        report_records.append(record)
                        continue

                    total_attempted += 1
                    try:
                        delete_backup(client, org_id, b_name, b_uid, cref)
                        logging.info("    DELETED backup=%s uid=%s", b_name, b_uid)
                        record["accepted"] = True
                        record["status"] = "ok"
                        total_succeeded += 1
                    except Exception as exc:
                        logging.error(
                            "    DELETE failed for backup=%s uid=%s: %s", b_name, b_uid, exc
                        )
                        record["accepted"] = False
                        record["status"] = "error"
                        record["error"] = str(exc)
                        total_failed += 1
                    report_records.append(record)

                if aborted_by_limit or aborted_by_signal:
                    break
            if aborted_by_limit or aborted_by_signal:
                break
    finally:
        summary = _build_summary()
        try:
            write_reports(summary, report_records)
        except Exception as exc:
            logging.error("Failed to write reports: %s", exc)
        logging.info("Report (json): %s", REPORT_JSON)
        logging.info("Report (txt):  %s", REPORT_TXT)
        logging.info(
            "Done. attempted=%d succeeded=%d failed=%d aborted_by_limit=%s aborted_by_signal=%s",
            total_attempted, total_succeeded, total_failed,
            aborted_by_limit, aborted_by_signal,
        )

    if aborted_by_signal:
        return 130  # conventional SIGINT exit code
    return 0 if total_failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
