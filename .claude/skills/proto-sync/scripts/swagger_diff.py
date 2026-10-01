#!/usr/bin/env python3
"""Diff px-backup-api swagger definitions between two git refs.

Usage:
    swagger_diff.py <api-repo-path> <base-ref> <head-ref> [--json]

Prints added / removed / type-changed properties per swagger definition, plus
added or removed REST paths. Output is the seed for the proto-sync
classification table (SKILL.md section 0).

Definitions are the flattened proto message names (BackupInfo.Volume ->
BackupInfoVolume). Property names are the proto snake_case field names, which
are also the Ansible parameter names.
"""
import json
import subprocess
import sys

SWAGGER = "pkg/apis/v1/api.swagger.json"
PROTO = "pkg/apis/v1/api.proto"


def git_show(repo, ref, path):
    out = subprocess.run(
        ["git", "-C", repo, "show", f"{ref}:{path}"],
        check=True, capture_output=True, text=True,
    )
    return out.stdout


def load(repo, ref):
    return json.loads(git_show(repo, ref, SWAGGER))


def prop_sig(p):
    t = p.get("type") or ("$ref:" + p.get("$ref", "?"))
    if "format" in p:
        t += f"({p['format']})"
    if t == "array":
        items = p.get("items", {})
        t = "array[" + (items.get("type") or items.get("$ref", "?")) + "]"
    if "enum" in p:
        t += " enum" + json.dumps(p["enum"])
    return t


def diff_defs(base, head):
    b = base.get("definitions", {})
    h = head.get("definitions", {})
    result = {"added_defs": [], "removed_defs": [], "fields": [], "enum_values": []}
    for name in sorted(set(h) - set(b)):
        result["added_defs"].append(name)
    for name in sorted(set(b) - set(h)):
        result["removed_defs"].append(name)
    for name in sorted(set(b) & set(h)):
        bd, hd = b[name], h[name]
        # enum definitions
        if "enum" in bd or "enum" in hd:
            be, he = set(bd.get("enum", [])), set(hd.get("enum", []))
            for v in sorted(he - be):
                result["enum_values"].append({"enum": name, "value": v, "change": "added"})
            for v in sorted(be - he):
                result["enum_values"].append({"enum": name, "value": v, "change": "removed"})
            continue
        bp, hp = bd.get("properties", {}), hd.get("properties", {})
        for f in sorted(set(hp) - set(bp)):
            result["fields"].append({
                "definition": name, "field": f, "change": "added",
                "type": prop_sig(hp[f]), "description": hp[f].get("description", ""),
            })
        for f in sorted(set(bp) - set(hp)):
            result["fields"].append({
                "definition": name, "field": f, "change": "removed",
                "type": prop_sig(bp[f]),
            })
        for f in sorted(set(bp) & set(hp)):
            if prop_sig(bp[f]) != prop_sig(hp[f]):
                result["fields"].append({
                    "definition": name, "field": f, "change": "type_changed",
                    "type": f"{prop_sig(bp[f])} -> {prop_sig(hp[f])}",
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


def guess_direction(defn):
    d = defn.lower()
    if d.endswith("request"):
        return "request"
    if d.endswith("response"):
        return "response"
    if any(k in d for k in ("info", "status", "object", "volume", "resource")):
        return "response"
    return "shared?"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if len(args) != 3:
        print(__doc__)
        sys.exit(2)
    repo, base, head = args
    b, h = load(repo, base), load(repo, head)
    defs = diff_defs(b, h)
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
        print("## New definitions (possible new service/message)")
        for d in defs["added_defs"]:
            print(f"+ {d}")
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
        print("## Fields")
        print("| definition.field | change | type | direction (guess) | description |")
        print("|---|---|---|---|---|")
        for f in defs["fields"]:
            desc = (f.get("description") or "").split("\n")[0][:80]
            print(f"| {f['definition']}.{f['field']} | {f['change']} | {f['type']} | "
                  f"{guess_direction(f['definition'])} | {desc} |")
        print()
    print("Next: confirm direction/tag/comment with")
    print(f"  git -C {repo} diff {base}..{head} -- {PROTO}")


if __name__ == "__main__":
    main()
