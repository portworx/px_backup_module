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
| enum `Foo.Type` | string enum | `str` with `choices=[...]` | Wire = int; add/extend module-level `*_MAP = {'Name': int}` |
| `oneof` | multiple optional props | separate optional params + `mutually_exclusive=[[a,b]]` in `AnsibleModule(...)` | |
| nested message (non-ref) | object | `dict` with `options=dict(...)` mirroring sub-fields | Flattened swagger name `OuterInner` |

## Where a field lives decides who sees it

```
XCreateRequest / XUpdateRequest / XDeleteRequest ──► user input  → class A
XEnumerateRequest(.enumerate_options)              ──► INSPECT_ALL filters (query params or POST body) → class A
XInspectRequest                                    ──► usually just name/uid/org_id; rarely changes
XObject / XInfo / XStatus / *Volume / *Resource    ──► response only → class B
Enum definitions                                   ──► class C
service rpc + google.api.http                      ──► class D (new op) / class E (new service)
```

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

Proto3 has no required. Decide from the server handler or from the create request
semantics; default `required: false` and, if the server rejects absence, enforce it
in the per-operation `validate_params(operation, required_params)` call, not in
`argument_spec` (operations share one spec).

## Defaults

Do not put server defaults in `argument_spec` `default=`; omit the key when the user
does not set it (the builders already skip `None`). Mention the server default in the
docs `Default` column instead.
