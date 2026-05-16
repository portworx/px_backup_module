# delete_failed_scheduled_backups.py

Standalone Python utility to clean up **Failed VM backups** under every
VM-schedule, across every cluster in a PX-Backup org.

Companion to `retry-failed-backups.py`. Does **not** use Ansible — single
script, single `pip install`, env-file driven.

## What it does

For each cluster in `ORG_ID`:
1. enumerate all `VirtualMachine` backup schedules in that cluster
2. for each schedule, enumerate its backups filtered server-side by
   `backup_object_type="VirtualMachine"` and `status=["Failed"]`
3. sort by `metadata.create_time` ascending
4. issue `DELETE /v1/backup/{org_id}/{name}` for each (fire-and-forget)

A timestamped summary (`.txt` + `.json`) is written next to the script.

## What it does NOT do

- It does **not** delete `PartialSuccess` backups (that is requirement #2,
  separate script).
- It does **not** poll for `Deleting → Done`. Per design, backups may move into
  `DeletingPending` and stay there until the dependency link is broken
  out-of-band — that workflow is intentionally out of scope.
- It does **not** suspend schedules.

## Prereqs

- Python 3.9+
- `pip install requests`
- Network access from the jump host to `PX_BACKUP_API_URL` and `PX_CENTRAL_URL`

## Setup

```sh
cp .env.sample .env
chmod 600 .env
# edit .env to set PX_BACKUP_API_URL, PX_CENTRAL_URL, credentials
```

## Run

```sh
# Always start with --dry-run on a single schedule
python3 delete_failed_scheduled_backups.py \
    --cluster-name <test-cluster> \
    --schedule-name <one-test-schedule> \
    --dry-run -v

# Same scope, real delete
python3 delete_failed_scheduled_backups.py \
    --cluster-name <test-cluster> \
    --schedule-name <one-test-schedule> -v

# Full org, throttled to first 50 deletions
python3 delete_failed_scheduled_backups.py --limit 50 -v

# Full org, no throttle
python3 delete_failed_scheduled_backups.py -v
```

## Exit codes

| Code | Meaning                                       |
|------|-----------------------------------------------|
| 0    | All attempted deletes returned 2xx (or dry-run only) |
| 2    | At least one DELETE failed (see report)       |
| !=0  | Hard failure (auth, env validation, etc.)     |

## Verifying a run

1. The script logs every accepted/rejected delete to console + log file.
2. Cross-check via `pxbackupctl backup get <name> --uid <uid>` — the affected
   backup should appear in `Deleting` state (or `DeletingPending` if the
   dependency-link condition is hit).
3. Re-run with `--dry-run` after a real run — the previously-deleted backups
   should no longer be enumerated as `Failed`.

## Sample run output

A real end-to-end run against a lab cluster (15 schedules, 85 Failed VM
backups, all deleted successfully) is committed alongside the script as a
reference. Three files form one matched set:

| File | Purpose |
|---|---|
| `delete-failed-scheduled-backups_20260516T143858Z.log` | Per-DELETE INFO log, one line per backup |
| `delete-failed-scheduled-backups_20260516T143858Z.txt` | Human-readable run summary + per-record listing |
| `delete-failed-scheduled-backups_20260516T143858Z.json` | Machine-readable: totals + every record (cluster, schedule, backup name/uid, create_time, status, error if any) |

Use these to see exactly what an operator will get on a normal run before
trusting it against production data.

## Notes for operators

- The script paginates enumerate calls via `enumerate_options.object_index`
  (proto: `EnumerateOptions.object_index`). Page size is `MAX_OBJECTS_PER_PAGE`
  (default 200).
- The filter `backup_schedule_ref` is sent as a JSON array because the proto
  field is `repeated ObjectRef` — passing a single object will be rejected by
  the API.
- The DELETE request encodes `cluster_ref.name` and `cluster_ref.uid` as query
  params, matching grpc-gateway's flattening of `BackupDeleteRequest.cluster_ref`.

## API references (px-backup-api branch 2.11.0)

- `pkg/apis/v1/api.proto`
  - `service Backup` — Enumerate (POST `/v1/backup/{org_id}/enumerate`), Delete
    (DELETE `/v1/backup/{org_id}/{name}`)
  - `service BackupSchedule` — Enumerate (POST
    `/v1/backupschedule/{org_id}/enumerate`)
  - `service Cluster` — Enumerate (GET `/v1/cluster/{org_id}`)
  - `message EnumerateOptions` — `cluster_name_filter`, `cluster_uid_filter`,
    `backup_object_type` (string "VirtualMachine"), `status[]`,
    `backup_schedule_ref[]`, `max_objects`, `object_index`, `sort_option`
