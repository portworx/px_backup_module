---
name: proto-sync
description: Propagate a px-backup-api proto/swagger change into the purepx.px_backup Ansible collection (module arg spec + payload builder, docs/modules/*.md, examples/*/*.yaml, inventory/group_vars sample). Use when given two px-backup-api refs to diff, a px-backup-api PR/commit, or a field description, and asked to "sync", "add the field", "update the ansible module for", or "do the needful for" an API change.
---

# proto-sync: px-backup-api change → Ansible collection

Collection root: `ansible-collection/` (namespace `purepx`, name `px_backup`).
API repo (local clone, default): `/root/go/src/github.com/portworx/px-backup-api`.
Override with `$PX_BACKUP_API_REPO` or a path the user gives.

Read `references/repo-conventions.md` before touching any file. Read
`references/proto-to-ansible-mapping.md` when deciding types/choices.
`references/worked-example-pb-17269.md` is a complete end-to-end run.

Run every Python/ansible command with `PYTHONDONTWRITEBYTECODE=1`. The repo tracks
`plugins/modules/__pycache__/*.pyc`; never delete or add pyc files.

## 0. Inputs → list of changed fields

Accept any of:

| Input | How to get the diff |
|---|---|
| Two refs (`3.2.0-fc1` → `3.3.0-fc1`, tags, SHAs) | `python3 scripts/swagger_diff.py <repo> <base> <head>` then `git -C <repo> diff <base>..<head> -- pkg/apis/v1/api.proto` for comments/tags |
| PR number / commit SHA | `gh pr diff <n> --repo portworx/px-backup-api -- pkg/apis/v1/api.proto` or `git -C <repo> show <sha> -- pkg/apis/v1/api.proto pkg/apis/v1/api.swagger.json` |
| Prose from user | Confirm against `api.proto` with grep; never invent field names |

Release branch names in px-backup-api are `<major.minor.patch>-fc1` and `-staging`
(e.g. `3.2.0-fc1`, `3.3.0-fc1`). Plain `3.3.0` does not exist. Fetch first
(`git -C <repo> fetch origin`; slow on this box, run in background or skip if refs are fresh).

`swagger_diff.py` output is the seed, not the answer. For every row:

1. **Expand new definitions.** A new definition (e.g. `BackupScheduleFilterOptions`) means
   every field inside it is new too. The script lists them under "New definitions" with
   their fields; carry each field into the table.
2. **Direction comes from reachability, not the name.** The script marks a definition
   `request` if any `*Request` definition reaches it through `$ref`, `response` if only
   `*Response`/`*Object`/`*Info` reach it, `both` if both. `BackupLocationInfo` is embedded in
   `BackupLocationCreateRequest`, so its new fields are **request** fields (class A), even
   though the name says Info. Trust the script's column; override only with proto evidence.
3. **Check existing coverage.** `grep -rn "<field>" ansible-collection/plugins/modules
   ansible-collection/docs ansible-collection/examples ansible-collection/inventory`. If the
   collection already has it, class becomes `extend` (fill gaps only) or `done`.
4. **Catch semantic-only changes.** The script lists properties whose description changed
   but type did not. If the meaning changed (e.g. `sync` went from federated-only to
   manual-mode-only), class H: refresh descriptions in module + docs, no code change.
5. **Read the proto diff** for tags, comments, enum value names, and which wrapper a
   field sits on (`BackupScheduleDeleteFilterOptions.status` is on the outer wrapper, not
   inside the inner `filter_options`).

Sanity-check the diff before trusting it:
- Many `removed` rows when diffing a topic branch against its base ⇒ topic branch is
  behind base (base rebased/regenerated). Use only `added` rows, or rebase first.
- Zero rows for a change you know exists ⇒ wrong ref pair (e.g. unmerged topic branch
  diffed as `base..base`). Diff `origin/<base>..<topic>` instead.
- Reference run, `origin/3.2.0-fc1..origin/3.3.0-fc1` (as of 2026-10-01): 5 new
  definitions, 8 top-level field rows; expanded ⇒ 13 fields, 1 enum, 1 semantic change.

Produce a table **before editing**:

```
| proto message.field | tag | type | JSON key | direction | ansible module | class |
```

`class` = one of the cases in §1 (plus `extend` / `done`). Show this table to the user,
then proceed.

## 1. Classify each change → what to touch ("decide per field")

Only touch the layers where the field actually surfaces to an Ansible user.

| Class | Example | Module `.py` | `docs/modules/<m>.md` | `examples/<m>/*.yaml` | `inventory/group_vars/<m>/*` |
|---|---|---|---|---|---|
| **A. New request field** (reachable from a `*Request`) | `BackupLocationInfo.sync_manual` | DOCUMENTATION option + `argument_spec` entry + payload builder (or query-param flattening for GET) | Parameter table row (+ sub-table if dict) + example snippet | `<field>: "{{ item.<field> \| default(omit) }}"` in every op playbook that sends it, unless the playbook already passes the parent dict through | Add to one sample entry in the relevant vars file, commented |
| **B. New response-only field** (`*Info`, `*Status`, `*Object`, Volume, etc., not reachable from any request) | `BackupInfo.Volume.cleanup_details` | `RETURN` block (if module has one): extend `description` and `sample`. Response passthrough is generic, no code change unless module filters keys | "Return Values" / "<Object> Structure" section | none | none |
| **C. New enum / enum value** | `BackupScheduleRunState` | `*_MAP` dict + `choices:` in DOCUMENTATION + argument_spec `choices` | Choices column of the param table | none unless sample should showcase it | optional sample |
| **D. New RPC on existing service** | `Backup.RetryBackupResources` | New `operation` choice + handler fn + endpoint literal + required-param validation | Operations table + params section + example | New `examples/<m>/<op>.yaml` | New vars file |
| **E. New service** | `ClusterDiscoveryConfig` | New `plugins/modules/<m>.py` (copy closest sibling) | New `docs/modules/<m>.md` + entry in `docs/README.md` index + Inventory Structure tree | New `examples/<m>/{create,update,delete,inspect_one,inspect_all}.yaml` | New `group_vars/<m>/` dir |
| **F. Deprecated field** (comment-only in proto; `[deprecated=true]` is not used there) | `cloud_credential` | Keep param. Add to "deprecated" comment group in argument_spec | Move row to "Deprecated Parameters" section | Leave | Leave |
| **G. Changed type / renamed field** | rare | Treat as F for old + A for new. Never silently rename an Ansible param (breaks user playbooks) | both | both | both |
| **H. Semantic-only change** (comment changed, type same) | `BackupLocationInfo.sync` | Refresh `description:` lines | Refresh row text / notes | none | none |

Rules:
- Ansible param name **= proto field name (snake_case)**. Swagger uses proto names;
  `gogoproto.jsontag` overrides do NOT change the wire JSON. Never camelCase.
- Nested refs (`ObjectRef`) → `type: dict`, suboptions `name`, `uid`. Lists of refs →
  `type: list, elements: dict` with the same suboptions.
- `google.protobuf.Timestamp` → request: `type: str` (RFC3339); response: documented as string date-time.
- `google.protobuf.BoolValue` (nullable bool) → `type: bool`, **no default**, builder uses
  `is not None` so an explicit `false` is sent and unset is omitted.
- Enums → Ansible accepts **short names** (`Running`, not `BackupScheduleRunStateRunning`);
  wire sends the **int** via a module-level `*_MAP`, matching `BACKUP_OBJECT_TYPE_MAP`.
  Never send `Invalid`/0 as a filter. Check the module's existing enum handling first.
- **Wrapper messages** (`XUpdateFilterOptions{ filter_options: XFilterOptions }`): keep the
  Ansible param flat (`filter_options.owners`), mirror the wire nesting in one builder
  helper, and put wrapper-specific fields (e.g. `status` on the delete wrapper) on the
  outer object, gated by operation.
- **Operation-specific fields** (UPDATE-only `suspend`, DELETE-only `status`): one shared
  `argument_spec`, gate in the builder by `operation`, say so in `description:`.
- GET enumerate filters → flattened dotted query params (`'enumerate_options.time_range.start_time'`), not JSON body. POST `/enumerate` variants take JSON body.
- Proto3 "server rejects unset on CREATE" comments: do **not** make the param required in
  `argument_spec` (breaks older servers). Document the server behaviour in `description:`.

## 2. Edit order (per module)

1. `plugins/modules/<m>.py`
   - `DOCUMENTATION` yaml: add option with `description`, `type`, `required: false`,
     `version_added: '<galaxy.yml version>'` (see §4), `choices`/`suboptions` as needed.
   - `argument_spec` dict in `run_module()`: mirror exactly (`type`, `elements`, `options=dict(...)`, `choices`, `no_log` for secrets).
   - Payload builder (`build_<m>_request` / `<m>_request_body`): append to `optional_fields` list if plain passthrough; otherwise explicit mapping block.
   - `RETURN` yaml (if present) for response fields: these blocks are `description` +
     `sample` dicts, not `contains:` trees. Add the key to the sample and mention it in
     the description.
   - `EXAMPLES` yaml (if present): one line showing the new param.
2. `docs/modules/<m>.md` — handwritten markdown, **not** generated. Match the column set of
   the surrounding table (some have `Supported Versions`, some `Default`, some `Choices`).
   If there is no `Supported Versions` column, append "PX-Backup >= X.Y.Z" to the
   description cell. Return-value sections are often YAML-ish code blocks, not tables;
   add the key there.
3. `examples/<m>/<op>.yaml` — add `<field>: "{{ item.<field> | default(omit) }}"` under the
   `# Optional parameters` comment. Use `default([])` / `default({})` only if existing
   siblings of same type do. Playbook names vary (`delete.yaml` vs `delete_schedule.yaml`);
   `ls examples/<m>/`.
4. `inventory/group_vars/<m>/*` — add field to **one** sample item, with a `# <short
   explanation>` comment. File names are inconsistent per module (`create.yaml` vs
   `create_vars.yaml`): open the example playbook's `vars_files` to find the real name.
5. If new module (class E): also `docs/README.md` (Module Reference + Inventory Structure tree) and `README.md` module list if it has one.

## 3. Verification (no live cluster needed)

```bash
cd ansible-collection
export PYTHONDONTWRITEBYTECODE=1
python3 -m py_compile plugins/modules/<m>.py                       # each edited module
ansible-doc -t module -M plugins/modules <m>                       # DOCUMENTATION + RETURN parse
for p in examples/<m>/<every edited playbook>.yaml; do ansible-playbook --syntax-check -i inventory/hosts "$p"; done
python3 ../.claude/skills/proto-sync/scripts/drift_check.py <m> [<m2> ...]
```

`drift_check.py` prints options present in DOCUMENTATION but not argument_spec and vice
versa, minus the baseline in `references/repo-conventions.md`. Report only new deltas.
Flag, do not auto-fix, pre-existing drift. `ansible-lint` is not installed here.

If the builder changed shape (wrapper/enum), exercise it directly:

```bash
python3 -c "import sys; sys.path.insert(0,'plugins/modules'); ..."   # or a tiny stub module
```

## 4. Versioning

- `galaxy.yml: version` = collection version. New options get `version_added: '<that
  version>'` unless the user names a different target. Do not bump `galaxy.yml`.
- Docs tables with a `Supported Versions` column: put the **PX-Backup server** version
  the field first appears in (from the api branch, e.g. `3.3.0`).
- `docs/README.md` "This collection integrates with PX-Backup API vX" — bump only when
  the user says this sync targets a new release.

## 5. Output to user

Final message must contain:
1. The classification table from §0 (expanded, with `extend`/`done` rows kept).
2. Per-file bullet list of edits (path only, one line each).
3. Anything skipped and why (e.g. response-only → no inventory change; playbook already
   passes parent dict).
4. Verification commands run and their result; if the shell was unavailable, say so explicitly.
5. New drift vs baseline, and any baseline entries that no longer apply.

Do not bump `galaxy.yml` or write CHANGELOG unless asked. Do not commit.
