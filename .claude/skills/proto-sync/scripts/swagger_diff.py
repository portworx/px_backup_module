#!/usr/bin/env python3
"""Diff px-backup-api swagger definitions between two git refs.

Usage:
    swagger_diff.py <api-repo-path> <base-ref> <head-ref> [--json]

Prints, for the proto-sync classification table:
  * added / removed REST paths
  * new definitions, each expanded to its fields
  * added / removed / type-changed properties on existing definitions
  * description-only changes (type same, text changed) -> semantic review
  * added / removed enum values
Every row carries a direction computed by $ref reachability from the head
swagger: `request` if some *Request definition reaches it, `response` if only
non-request roots reach it, `both` if both, `orphan` if nothing references it.

Definitions are flattened proto message names (BackupInfo.Volume ->
BackupInfoVolume). Property names are proto snake_case, which are also the
Ansible parameter names.
"""
import json
import re
import subprocess
import sys
from collections import defaultdict

SWAGGER = "pkg/apis/v1/api.swagger.json"
PROTO = "pkg/apis/v1/api.proto"
REF_RE = re.compile(r"#/definitions/(\w+)")


def git_show(repo, ref, path):
    out = subprocess.run(
        ["git", "-C", repo, "show", f"{ref}:{path}"],
        check=True, capture_output=True, text=True,
    )
    return out.stdout


def load(repo, ref):
    return json.loads(git_show(repo, ref, SWAGGER))


def prop_sig(p):
    t = p.get("type") or ("$ref:" + p.get("$ref", "?").split("/")[-1])
    if "format" in p:
        t += f"({p['format']})"
    if t == "array":
        items = p.get("items", {})
        t = "array[" + (items.get("type") or items.get("$ref", "?").split("/")[-1]) + "]"
    return t


def refs_of(defn):
    return set(REF_RE.findall(json.dumps(defn)))


REQUEST_ROOTS = {}  # definition -> sorted list of *Request names that reach it


def build_direction(definitions):
    """Return {definition: 'request'|'response'|'both'|'orphan'} and fill REQUEST_ROOTS."""
    graph = {name: refs_of(d) for name, d in definitions.items()}
    reach_req = defaultdict(set)   # definition -> request roots
    reach_resp = set()

    def walk(start):
        seen = set()
        stack = [start]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            stack.extend(graph.get(n, ()))
        return seen

    for name in definitions:
        if name.endswith("Request"):
            for n in walk(name):
                reach_req[n].add(name)
        elif name.endswith("Response"):
            reach_resp |= walk(name)
    out = {}
    for name in definitions:
        r, s = name in reach_req, name in reach_resp
        out[name] = "both" if r and s else "request" if r else "response" if s else "orphan"
        REQUEST_ROOTS[name] = sorted(reach_req.get(name, ()))
    return out


def roots(name, limit=3):
    r = REQUEST_ROOTS.get(name, [])
    if not r:
        return ""
    extra = f" +{len(r) - limit}" if len(r) > limit else ""
    return " via " + ", ".join(r[:limit]) + extra


def diff_defs(base, head, direction):
    b = base.get("definitions", {})
    h = head.get("definitions", {})
    result = {
        "added_defs": [], "removed_defs": [], "fields": [],
        "desc_changed": [], "enum_values": [],
    }
    for name in sorted(set(h) - set(b)):
        d = h[name]
        entry = {"definition": name, "direction": direction.get(name, "?")}
        if "enum" in d:
            entry["enum"] = d["enum"]
        else:
            entry["fields"] = [
                {"field": f, "type": prop_sig(p),
                 "description": (p.get("description") or "").split("\n")[0]}
                for f, p in d.get("properties", {}).items()
            ]
        result["added_defs"].append(entry)
    for name in sorted(set(b) - set(h)):
        result["removed_defs"].append(name)
    for name in sorted(set(b) & set(h)):
        bd, hd = b[name], h[name]
        if "enum" in bd or "enum" in hd:
            be, he = set(bd.get("enum", [])), set(hd.get("enum", []))
            for v in sorted(he - be):
                result["enum_values"].append({"enum": name, "value": v, "change": "added"})
            for v in sorted(be - he):
                result["enum_values"].append({"enum": name, "value": v, "change": "removed"})
            continue
        bp, hp = bd.get("properties", {}), hd.get("properties", {})
        dirn = direction.get(name, "?")
        for f in sorted(set(hp) - set(bp)):
            result["fields"].append({
                "definition": name, "field": f, "change": "added", "direction": dirn,
                "type": prop_sig(hp[f]),
                "description": (hp[f].get("description") or "").split("\n")[0],
            })
        for f in sorted(set(bp) - set(hp)):
            result["fields"].append({
                "definition": name, "field": f, "change": "removed", "direction": dirn,
                "type": prop_sig(bp[f]), "description": "",
            })
        for f in sorted(set(bp) & set(hp)):
            if prop_sig(bp[f]) != prop_sig(hp[f]):
                result["fields"].append({
                    "definition": name, "field": f, "change": "type_changed", "direction": dirn,
                    "type": f"{prop_sig(bp[f])} -> {prop_sig(hp[f])}", "description": "",
                })
            elif (bp[f].get("description") or "") != (hp[f].get("description") or ""):
                result["desc_changed"].append({
                    "definition": name, "field": f, "direction": dirn,
                    "old": (bp[f].get("description") or "").split("\n")[0],
                    "new": (hp[f].get("description") or "").split("\n")[0],
                })
    return result


def diff_paths(base, head):
    bp, hp = base.get("paths", {}), head.get("paths", {})
    out = {"added": [], "removed": []}
    for p in sorted(set(hp) - set(bp)):
        out["added"].extend(f"{m.upper()} {p}" for m in hp[p])
    for p in sorted(set(bp) - set(hp)):
        out["removed"].extend(f"{m.upper()} {p}" for m in bp[p])
    for p in sorted(set(bp) & set(hp)):
        for m in set(hp[p]) - set(bp[p]):
            out["added"].append(f"{m.upper()} {p}")
        for m in set(bp[p]) - set(hp[p]):
            out["removed"].append(f"{m.upper()} {p}")
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if len(args) != 3:
        print(__doc__)
        sys.exit(2)
    repo, base, head = args
    b, h = load(repo, base), load(repo, head)
    direction = build_direction(h.get("definitions", {}))
    defs = diff_defs(b, h, direction)
    paths = diff_paths(b, h)

    if as_json:
        print(json.dumps({"definitions": defs, "paths": paths}, indent=2))
        return

    print(f"# swagger diff {base}..{head}\n")
    if paths["added"] or paths["removed"]:
        print("## REST paths")
        for p in paths["added"]:
            print(f"+ {p}")
        for p in paths["removed"]:
            print(f"- {p}")
        print()
    if defs["added_defs"]:
        print("## New definitions (every field inside is new)")
        for d in defs["added_defs"]:
            if "enum" in d:
                print(f"+ {d['definition']}  [enum, {d['direction']}]: {', '.join(d['enum'])}")
                continue
            print(f"+ {d['definition']}  [{d['direction']}{roots(d['definition'])}]")
            for f in d["fields"]:
                print(f"    .{f['field']}: {f['type']}  — {f['description'][:70]}")
        print()
    if defs["removed_defs"]:
        print("## Removed definitions")
        for d in defs["removed_defs"]:
            print(f"- {d}")
        print()
    if defs["enum_values"]:
        print("## Enum values")
        for e in defs["enum_values"]:
            sign = "+" if e["change"] == "added" else "-"
            print(f"{sign} {e['enum']}.{e['value']}")
        print()
    if defs["fields"]:
        print("## Fields on existing definitions")
        print("| definition.field | change | type | direction | description |")
        print("|---|---|---|---|---|")
        for f in defs["fields"]:
            print(f"| {f['definition']}.{f['field']} | {f['change']} | {f['type']} | "
                  f"{f['direction']}{roots(f['definition'])} | {f['description'][:80]} |")
        print()
    if defs["desc_changed"]:
        print("## Description-only changes (review for semantic change → class H)")
        for d in defs["desc_changed"]:
            print(f"* {d['definition']}.{d['field']} [{d['direction']}]")
            print(f"    - {d['old'][:90]}")
            print(f"    + {d['new'][:90]}")
        print()
    print("Direction = $ref reachability from *Request / *Response definitions in head swagger.")
    print("`both` rows: check the listed Request roots. A field reached only through a *Response-shaped")
    print("object embedded in a request (e.g. BackupInfo via BackupUpdateRequest) is still user-settable")
    print("only if the server honours it on that request; read the proto comment / server handler.")
    print("Next: confirm tags, comments and wrapper placement with")
    print(f"  git -C {repo} diff {base}..{head} -- {PROTO}")


if __name__ == "__main__":
    main()
