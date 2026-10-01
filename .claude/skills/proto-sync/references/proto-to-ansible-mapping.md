# Proto / swagger → Ansible argument_spec mapping

| Proto type | Swagger | Ansible `type` | Notes |
|---|---|---|---|
| `string` | string | `str` | `no_log=True` if secret/password/token/key |
| `bool` | boolean | `bool` | Builder must use `is not None` check, not truthiness, or `false` is dropped |
| `int32/int64/uint32/uint64` | integer / string(int64) | `int` | int64 arrives as string in JSON; cast in response docs only |
| `float/double` | number | `float` | |
| `repeated string` | array[string] | `list`, `elements='str'` | |
| `repeated Message` | array[object] | `list`, `elements='dict'`, `options=dict(...)` | Document entry format as a sub-table |
| `map<string,string>` | object additionalProperties | `dict` | e.g. `labels`, `label_selectors` |
| `ObjectRef` (`name`, `uid`) | object | `dict`, `options=dict(name=dict(type='str'), uid=dict(type='str'))` | Most `*_ref` fields |
| `google.protobuf.Timestamp` | string date-time | request: `str` (RFC3339 `2026-01-02T15:04:05Z`); response: doc as string | Never `int` |
| `google.protobuf.Duration` | string | `str` (e.g. `"3600s"`) | |
| `google.protobuf.BoolValue` / `Int32Value` / `StringValue` (nullable wrappers) | boolean / integer / string | `bool` / `int` / `str`, **no default** | Builder must use `is not None`; unset ⇒ omit key, so server sees null, not false/0 |
| enum `Foo.Type` | string enum of full value names (`BackupScheduleRunStateRunning`) | `str` with `choices=['Running','Suspended']` (short names, prefix stripped) | Wire = int via module-level `*_MAP = {'Running': 1, ...}`; never send `Invalid`/0 as a filter |
| `oneof` | multiple optional props | separate optional params + `mutually_exclusive=[[a,b]]` in `AnsibleModule(...)` | |
| nested message (non-ref) | object | `dict` with `options=dict(...)` mirroring sub-fields | Flattened swagger name `OuterInner` |
| wrapper message `XDeleteFilterOptions { XFilterOptions filter_options; Enum status; }` | object with one `$ref` + extras | one flat `dict` param (`filter_options`) whose suboptions are the inner fields **plus** the wrapper extras | Builder helper rebuilds wire nesting: `{"filter_options": {"filter_options": inner, "status": int}}`; wrapper-only fields gated by operation |

## Where a field lives decides who sees it

Direction is **$ref reachability**, computed by `scripts/swagger_diff.py`:

```
reachable from some *Request                       ──► user input  → class A   (BackupLocationInfo.sync_manual via BackupLocationCreateRequest)
XEnumerateRequest(.enumerate_options)              ──► INSPECT_ALL filters (query params or POST body) → class A
reachable only from *Response                       ──► response only → class B (BackupInfo.Volume.start_time)
`both`                                             ──► look at the listed request roots. BackupInfo is reachable via
                                                       MetricsCreateRequest, but users never set backup_info there → still class B.
Enum definitions                                   ──► class C
service rpc + google.api.http                      ──► class D (new op) / class E (new service)
description changed, type same                     ──► class H (semantic refresh)
```

Names lie: `*Info` messages are embedded in Create/Update requests for backup_location,
cluster, cloud_credential, schedule_policy, rule and more. Never classify by suffix.

Shared messages (`ObjectRef`, `Ownership`, `TimeRange`, `EnumerateOptions`,
`CreateMetadata`) are embedded in many requests: a change there fans out to every
module that embeds it. Grep the collection for the proto field name to find them all:

```bash
grep -rn "<field>" ansible-collection/plugins/modules ansible-collection/docs ansible-collection/examples ansible-collection/inventory
```

## Description text

Build the Ansible `description:` from the **proto comment** above the field (swagger
drops comments on any field after the first in a comment block). Strip internal notes
such as Jira ids or "tag N is taken by ..." remarks. Keep units and semantics
("reconcile-observation time, may be unset").

## Required-ness

Proto3 has no required. Default `required: false`. If the proto comment says the server
rejects an unset value on CREATE (e.g. `sync_manual`), **still do not enforce it** in the
module: older servers accept the omission and existing playbooks must keep working.
Document the server behaviour in `description:` instead. Enforce in
`validate_params(operation, required_params)` only for fields the server has always
required (`name`, `org_id`, refs) — never in `argument_spec` (operations share one spec).

## Defaults

Do not put server defaults in `argument_spec` `default=`; omit the key when the user
does not set it (the builders already skip `None`). Mention the server default in the
docs `Default` column instead.
