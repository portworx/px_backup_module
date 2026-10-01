# Worked example: PB-17269 — per-volume `start_time` / `finish_time`

API change on px-backup-api topic branch `PB-17269-3.3.0-fc1` (targets `3.3.0-fc1`; verify
merge state with `git log origin/3.3.0-fc1 --oneline | grep PB-17269` before claiming it
shipped). Diff that produced this example:

```bash
python3 scripts/swagger_diff.py /root/go/src/github.com/portworx/px-backup-api origin/3.3.0-fc1 PB-17269-3.3.0-fc1
```

If that output also lists many `removed` rows, the topic branch is behind its base
(happened here: `3.3.0-fc1` was rebased + regenerated at `94cb40df`). Ignore removals in
that case and sync only the `added` rows, or rebase the topic branch first.

```proto
// pkg/apis/v1/api.proto  — message BackupInfo { message Volume { ...
        // Reconcile-observation times, not data-mover timings. Either may be
        // unset, and finish_time can be set without start_time, so check both
        // before subtracting and never substitute a zero or epoch value.
        google.protobuf.Timestamp start_time = 19;
        google.protobuf.Timestamp finish_time = 20;

// message RestoreInfo { message Volume { ...
        google.protobuf.Timestamp start_time = 10;
        google.protobuf.Timestamp finish_time = 11;
```

Swagger (`BackupInfoVolume`, `RestoreInfoVolume`): `"start_time": {"type":"string","format":"date-time"}`, same for `finish_time`.

## Step 0 — classification table

| proto message.field | tag | type | JSON key | direction | ansible module | class |
|---|---|---|---|---|---|---|
| BackupInfo.Volume.start_time | 19 | Timestamp | `start_time` | response | backup | B |
| BackupInfo.Volume.finish_time | 20 | Timestamp | `finish_time` | response | backup | B |
| RestoreInfo.Volume.start_time | 10 | Timestamp | `start_time` | response | restore | B |
| RestoreInfo.Volume.finish_time | 11 | Timestamp | `finish_time` | response | restore | B |

Class B → module code unchanged (response passthrough is generic), `RETURN` + docs only.
No example playbook change, no inventory change. Say so in the final message.

## Step 1 — `plugins/modules/backup.py` `RETURN` block

The collection's `RETURN` blocks are `description:` + `sample:` dicts, not `contains:`
trees. Extend the `backup` entry's description and sample:

```yaml
backup:
    description:
        - Details of the backup
        - backup_info.volumes[].start_time / finish_time (PX-Backup >= 3.3.0) are reconcile-observation
          times in RFC3339; either may be absent, finish_time may appear without start_time
    type: dict
    returned: success
    sample: {
        "backup_info": {
            "volumes": [{
                "name": "pvc-1",
                "status": {"status": "Success"},
                "start_time": "2026-05-04T10:00:00Z",
                "finish_time": "2026-05-04T10:04:12Z"
            }]
        }
    }
```

`restore.py`: same under `restore_info.volumes` if a `RETURN` block exists; if the
module has no `RETURN`, docs only.

## Step 2 — `docs/modules/backup.md`

Under `## Return Values` → `### Backup Object Structure`, in the `backup_info.volumes`
entry list (or table), add two rows:

```
| backup_info.volumes[].start_time  | string | Volume backup start as observed by reconciler (RFC3339). May be absent. PX-Backup >= 3.3.0 |
| backup_info.volumes[].finish_time | string | Volume backup finish as observed by reconciler (RFC3339). May be present without start_time. PX-Backup >= 3.3.0 |
```

Same in `docs/modules/restore.md` under the restore object structure.

## Step 3 — examples / inventory

None. Optionally, if the user asks for a demonstration, add a `debug:` task to
`examples/backup/inspect_one.yaml`:

```yaml
    - name: Show per-volume timings
      debug:
        msg: "{{ item.name }}: {{ item.start_time | default('n/a') }} -> {{ item.finish_time | default('n/a') }}"
      loop: "{{ backup_result.backup.backup_info.volumes | default([]) }}"
      loop_control: { label: "{{ item.name | default('volume') }}" }
```

Do not add it unprompted; sync PRs stay minimal.

## Step 4 — verification

```bash
cd ansible-collection
python3 -m py_compile plugins/modules/backup.py plugins/modules/restore.py
ansible-doc -t module -M plugins/modules backup | grep -A3 start_time
```

## Step 5 — final message skeleton

```
Synced PB-17269 (BackupInfo.Volume / RestoreInfo.Volume start_time, finish_time) into collection.

Classification: 4 fields, all response-only (class B).

Edited:
- ansible-collection/plugins/modules/backup.py        RETURN: backup_info.volumes.{start_time,finish_time}
- ansible-collection/plugins/modules/restore.py       RETURN: restore_info.volumes.{start_time,finish_time}
- ansible-collection/docs/modules/backup.md           Return Values rows
- ansible-collection/docs/modules/restore.md          Return Values rows

Skipped: argument_spec, examples, inventory — fields are not user input.
Verified: py_compile ok; ansible-doc renders new keys.
Pre-existing drift noticed: <...>
```

## Contrast: if the same fields had been on a *request*

Had `start_time` been added to `BackupCreateRequest`, class A would apply:

- `DOCUMENTATION.options.start_time: {type: str, description: RFC3339 ...}`
- `module_args['start_time'] = dict(type='str', required=False)`
- append `'start_time'` to `optional_fields` in `build_backup_request`
- `docs/modules/backup.md` Backup Configuration Parameters row
- `examples/backup/create.yaml`: `start_time: "{{ item.start_time | default(omit) }}"`
- `inventory/group_vars/backup/create.yaml`: `start_time: "2026-01-02T15:04:05Z"  # optional` on one sample
