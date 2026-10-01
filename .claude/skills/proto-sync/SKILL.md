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

Sanity-check the diff before trusting it:
- Many `removed` rows when diffing a topic branch against its base ⇒ topic branch is
  behind base (base rebased/regenerated). Use only `added` rows, or rebase first.
- Zero rows for a change you know exists ⇒ wrong ref pair (e.g. unmerged topic branch
  diffed as `base..base`). Diff `origin/<base>..<topic>` instead.
- Reference run, `origin/3.2.0-fc1..origin/3.3.0-fc1` (as of 2026-10-01): 5 new
  definitions, 8 fields, 6 response-only + 2 request (`BackupSchedule{Update,Delete}Request.filter_options`).

Produce a table **before editing**:

```
| proto message.field | tag | type | JSON key | direction | ansible module | class |
```

`direction` = request / response / both / enum / rpc / service.
`class` = one of the cases in §1. Show this table to the user, then proceed.

## 1. Classify each change → what to touch ("decide per field")

Only touch the layers where the field actually surfaces to an Ansible user.

| Class | Example | Module `.py` | `docs/modules/<m>.md` | `examples/<m>/*.yaml` | `inventory/group_vars/<m>/*` |
|---|---|---|---|---|---|
| **A. New request field** (in `*CreateRequest` / `*UpdateRequest` / `*EnumerateRequest` or a message they embed) | `BackupCreateRequest.keep_cr_status` | DOCUMENTATION option + `argument_spec` entry + payload builder (or query-param flattening for GET) | Parameter table row (+ sub-table if dict) + example snippet | `<field>: "{{ item.<field> \| default(omit) }}"` in every op playbook that sends it | Add to one sample entry in the relevant `*_vars.yaml` / `create.yaml`, commented |
| **B. New response-only field** (in `*Info`, `*Status`, `*Object`, Volume, etc.) | `BackupInfo.Volume.start_time` | `RETURN` block (if module has one). Response passthrough is generic, no code change unless module filters keys | "Return Values" / "<Object> Structure" section | none | none |
| **C. New enum value** | `BackupObjectType.Type = 3` | `*_MAP` dict + `choices:` in DOCUMENTATION + argument_spec `choices` | Choices column of the param table | none unless sample should showcase it | optional sample |
| **D. New RPC on existing service** | `Backup.RetryBackupResources` | New `operation` choice + handler fn + endpoint literal + required-param validation | Operations table + params section + example | New `examples/<m>/<op>.yaml` | New `group_vars/<m>/<op>_vars.yaml` |
| **E. New service** | `ClusterDiscoveryConfig` | New `plugins/modules/<m>.py` (copy closest sibling) | New `docs/modules/<m>.md` + entry in `docs/README.md` index + Inventory Structure tree | New `examples/<m>/{create,update,delete,inspect_one,inspect_all}.yaml` | New `group_vars/<m>/` dir |
| **F. Deprecated field** (comment-only in proto; `[deprecated=true]` is not used there) | `cloud_credential` | Keep param. Add to "deprecated" comment group in argument_spec | Move row to "Deprecated Parameters" section | Leave | Leave |
| **G. Changed type / renamed field** | rare | Treat as F for old + A for new. Never silently rename an Ansible param (breaks user playbooks) | both | both | both |

Rules:
- Ansible param name **= proto field name (snake_case)**. Swagger uses proto names;
  `gogoproto.jsontag` overrides do NOT change the wire JSON. Never camelCase.
- Nested refs (`ObjectRef`) → `type: dict`, suboptions `name`, `uid`.
- `google.protobuf.Timestamp` → request: `type: str` (RFC3339); response: documented as string date-time.
- Enums → string choices on the Ansible side, int on the wire, mapped via module-level `*_MAP` dict. Check whether this module already sends int or string for that enum before adding.
- Fields that only exist for UPDATE (e.g. `suspend`, `cluster_scope`) must be gated on `operation == 'UPDATE'` in the builder, matching existing pattern.
- GET enumerate filters → flattened dotted query params (`'enumerate_options.time_range.start_time'`), not JSON body. POST `/enumerate` variants take JSON body.

## 2. Edit order (per module)

1. `plugins/modules/<m>.py`
   - `DOCUMENTATION` yaml: add option with `description`, `type`, `required: false`,
     `version_added: '<collection version>'` (see §4), `choices`/`suboptions` as needed.
   - `argument_spec` dict in `run_module()`: mirror exactly (`type`, `options=dict(...)`, `choices`, `no_log` for secrets).
   - Payload builder (`build_<m>_request` / `<m>_request_body`): append to `optional_fields` list if plain passthrough; otherwise explicit mapping block.
   - `RETURN` yaml (if present) for response fields.
   - `EXAMPLES` yaml (if present): one line showing the new param.
2. `docs/modules/<m>.md` — handwritten markdown, **not** generated. Match column set of the surrounding table (some tables have `Supported Versions`, some `Default`, some `Choices`). Add to Examples section when it changes usage.
3. `examples/<m>/<op>.yaml` — add `<field>: "{{ item.<field> | default(omit) }}"` under the `# Optional parameters` comment. Use `default([])` / `default({})` only if existing siblings of same type do.
4. `inventory/group_vars/<m>/*` — add field to **one** sample item, with a `# <short explanation>` comment. File names are inconsistent per module (`create.yaml` vs `create_vars.yaml`): open the example playbook's `vars_files` to find the real name; never guess.
5. If new module (class E): also `docs/README.md` (Module Reference + Inventory Structure tree) and `README.md` module list if it has one.

## 3. Verification (no live cluster needed)

```bash
cd ansible-collection
python3 -m py_compile plugins/modules/<m>.py
python3 - <<'EOF'
import yaml,re,sys
src=open('plugins/modules/<m>.py').read()
doc=yaml.safe_load(re.search(r"DOCUMENTATION = r'''(.*?)'''",src,re.S).group(1))
print(sorted(doc['options']))
EOF
ansible-doc -t module -M plugins/modules <m>          # DOCUMENTATION parses
ansible-playbook --syntax-check -i inventory/hosts examples/<m>/create.yaml
ansible-lint examples/<m>/ 2>/dev/null || true
```

Then diff-check: every option in `DOCUMENTATION.options` must exist in `argument_spec`
and vice versa (script in `references/repo-conventions.md` §"Drift check").
Flag, do not auto-fix, pre-existing drift unrelated to the change.

## 4. Versioning

- `galaxy.yml: version` = collection version (read it; 3.1.1 on main). New options get
  `version_added: '<collection version this ships in>'`, not the PX-Backup server version.
- Docs tables with a `Supported Versions` column: put the **PX-Backup server** version
  the field first appears in (from the api branch, e.g. `3.3.0`).
- `docs/README.md` "This collection integrates with PX-Backup API vX" — bump when syncing to a new release branch.
- Mention PX-Backup minimum in module doc `## Requirements` only if the field is useless below that version.

## 5. Output to user

Final message must contain:
1. The classification table from §0.
2. Per-file bullet list of edits (path only, one line each).
3. Anything skipped and why (e.g. response-only → no inventory change).
4. Verification commands run and their result; if the shell was unavailable, say so explicitly.
5. Pre-existing drift noticed but not fixed.

Do not bump `galaxy.yml` version or write CHANGELOG unless asked.
