# proto-sync — developer guide

A [Claude Code](https://claude.com/claude-code) skill that turns a `px-backup-api`
proto/swagger change into the matching edits in the `purepx.px_backup` Ansible
collection: module argument spec and payload builder, `docs/modules/*.md`, example
playbooks, and sample inventory vars.

Claude reads `SKILL.md` and the files under `references/` when the skill is invoked.
You do not need to read them to use it, but they are the place to fix behaviour when
Claude gets something wrong.

## Prerequisites

- Claude Code CLI, run from the root of this repo (`px_backup_module/`).
- A local clone of `github.com/portworx/px-backup-api` with `origin` fetched.
  Default path: `/root/go/src/github.com/portworx/px-backup-api`.
  Override with `export PX_BACKUP_API_REPO=/path/to/px-backup-api` or tell Claude the path.
- `python3`, `ansible-doc`, `ansible-playbook` on `PATH` (for the verification step).
- `gh` CLI if you want to feed it a PR number instead of git refs.

## Usage

Start Claude Code in the repo root and invoke the skill with what changed.

Two release branches:

```
/proto-sync origin/3.2.0-fc1 origin/3.3.0-fc1
```

A topic branch against its base (typical for a single feature):

```
/proto-sync origin/3.3.0-fc1 PB-17269-3.3.0-fc1
```

A px-backup-api PR or commit:

```
/proto-sync PR 444
/proto-sync commit 0860ab19
```

Plain words (Claude will verify the field exists in `api.proto` first):

```
/proto-sync BackupCreateRequest got a new bool field keep_cr_status
```

Release branches in `px-backup-api` are named `X.Y.Z-fc1` and `X.Y.Z-staging`. There are
no plain `X.Y.Z` branches or tags for 3.x.

## What happens

1. Claude runs `scripts/swagger_diff.py` and the proto diff and shows you a table of
   every changed field with its direction (request / response / enum / rpc / service)
   and a class A–G that decides which files get touched.
2. It edits only the layers where the field is visible to an Ansible user:

   | Field is... | Module `.py` | `docs/modules/*.md` | `examples/` | `inventory/group_vars/` |
   |---|---|---|---|---|
   | in a Create/Update/Enumerate request | yes | yes | yes | yes |
   | response-only (`*Info`, `*Status`, Volume...) | `RETURN` block only | Return Values | no | no |
   | a new enum value | map + choices | choices column | no | optional |
   | a new RPC | new operation | ops table + example | new playbook | new vars file |
   | a new service | new module | new doc + index | new dir | new dir |
   | deprecated | kept, grouped as deprecated | moved to Deprecated section | no | no |

3. It runs `py_compile`, `ansible-doc`, `ansible-playbook --syntax-check` and a
   DOCUMENTATION-vs-argument_spec drift check, and reports results.
4. The final message lists every file edited, what was deliberately skipped and why,
   and any pre-existing problems it noticed but did not fix.

Nothing is committed. Review the diff and commit as usual. Claude will not bump
`galaxy.yml` or write a changelog unless you ask.

## Running the diff script by hand

```
python3 .claude/skills/proto-sync/scripts/swagger_diff.py <api-repo> <base-ref> <head-ref> [--json]
```

Prints added / removed / type-changed swagger properties per definition, new or removed
enum values, and new or removed REST paths. If a topic-branch diff shows many `removed`
rows, the topic branch is behind its base; rebase it or ignore the removals.

## Files

```
.claude/skills/proto-sync/
├── SKILL.md                                  entry point: inputs, classification, edit order, verify, report
├── README.md                                 this file
├── scripts/swagger_diff.py                   swagger diff between two git refs
└── references/
    ├── repo-conventions.md                   collection layout, module anatomy, naming quirks, drift check
    ├── proto-to-ansible-mapping.md           proto type -> ansible type table, request vs response rules
    └── worked-example-pb-17269.md            full run for BackupInfo.Volume start_time / finish_time
```

## Maintaining the skill

- New module or renamed vars file: update the layout and naming table in
  `references/repo-conventions.md`.
- New convention in how modules build payloads: update "Module anatomy" there and, if it
  changes what gets edited, the class table in `SKILL.md`.
- The "known drift" list in `repo-conventions.md` is a baseline so Claude does not
  re-report old undocumented params. Trim it when those params get documented.
- Keep `SKILL.md` short; put detail in `references/`. Claude loads references on demand.
