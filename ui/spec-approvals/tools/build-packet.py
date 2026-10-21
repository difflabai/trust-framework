#!/usr/bin/env python3
"""Build a spec review packet manifest from its source file.

Usage:
  ui/spec-approvals/tools/build-packet.py --formalver PATH --trust-framework PATH \
      [--src ui/spec-approvals/packets/near-approval.src.json] [--out ...near-approval.json]

Every file is read with `git show <commit>:<path>` at the commit the source
file pins, so the working tree's checkout does not matter. For each reading
entry the manifest records the file's sha256 and, when the entry names
`from` / `to` (exclusive) / `through` (inclusive) regexes, the 1-based line
range they select. Properties, assumptions and findings are copied from
formalver's status.toml and strategy.md at the pinned commit.

Standard library only (Python 3.11+ for tomllib).
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover
    sys.exit("build-packet.py needs Python 3.11+ (tomllib)")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SRC = os.path.join(HERE, "..", "packets", "near-approval.src.json")


def git_show(repo_dir, commit, path):
    try:
        return subprocess.run(["git", "-C", repo_dir, "show", "%s:%s" % (commit, path)],
                              check=True, capture_output=True).stdout
    except subprocess.CalledProcessError as e:
        sys.exit("git show %s:%s in %s failed: %s" % (commit, path, repo_dir, e.stderr.decode().strip()))


def line_range(text, entry, where):
    lines = text.split("\n")
    start = None
    for i, line in enumerate(lines):
        if re.search(entry["from"], line):
            start = i
            break
    if start is None:
        sys.exit("%s: no line matches from=%r" % (where, entry["from"]))
    end_pat = entry.get("through") or entry.get("to")
    if end_pat is None:
        return start + 1, len(lines)
    for j in range(start + 1, len(lines)):
        if re.search(end_pat, lines[j]):
            return start + 1, (j + 1 if "through" in entry else j)
    sys.exit("%s: no line after %d matches %r" % (where, start + 1, end_pat))


def findings_table(strategy):
    """Rows of the '### Open' findings table: {id: {finding, resolution}}."""
    out = {}
    m = re.search(r"^### Open\n(.*?)^---", strategy, re.S | re.M)
    if not m:
        sys.exit("strategy.md: no '### Open' findings section")
    for row in m.group(1).splitlines():
        cells = [c.strip() for c in row.strip().strip("|").split(" | ")]
        if len(cells) >= 3 and re.fullmatch(r"F-\d+", cells[0]):
            out[cells[0]] = {"finding": cells[1], "resolution": cells[2]}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--formalver", required=True, help="a clone of difflabai/formalver")
    ap.add_argument("--trust-framework", required=True, help="a clone of difflabai/trust-framework")
    ap.add_argument("--src", default=DEFAULT_SRC)
    ap.add_argument("--out")
    a = ap.parse_args()
    out_path = a.out or re.sub(r"\.src\.json$", ".json", a.src)
    with open(a.src, encoding="utf-8") as f:
        src = json.load(f)

    packet = src["packet"]
    clones = {"formalver": a.formalver, "trust-framework": a.trust_framework}

    def show(source, path):
        s = packet["sources"][source]
        full = (s["root"] + "/" + path) if s["root"] else path
        return full, git_show(clones[source], s["commit"], full)

    fv = packet["sources"]["formalver"]
    status = tomllib.loads(show("formalver", "status.toml")[1].decode("utf-8"))
    strategy = show("formalver", "strategy.md")[1].decode("utf-8")

    properties = {}
    for module, m in status["modules"].items():
        for pid, p in m["properties"].items():
            properties[pid] = {
                "module": module,
                "layer": p.get("layer", ""),
                "evidence": p.get("evidence", ""),
                "status": p.get("status", ""),
                "description": p.get("description", ""),
                "assumptions": p.get("assumptions", []),
            }
    assumptions = {k: {"statement": v.get("statement", ""), "level": v.get("level", ""),
                       "status": v.get("status", ""), "checked_by": v.get("checked_by", [])}
                   for k, v in status["assumptions"].items()}
    findings = findings_table(strategy)

    items = []
    for it in src["items"]:
        item = {k: v for k, v in it.items() if k not in ("read", "properties", "assumptions", "findings")}
        reads = []
        for r in it["read"]:
            full, data = show(r["source"], r["path"])
            entry = {"source": r["source"], "path": full, "label": r["label"],
                     "sha256": hashlib.sha256(data).hexdigest()}
            if "from" in r:
                entry["lines"] = list(line_range(data.decode("utf-8"), r, "%s %s" % (it["id"], full)))
            reads.append(entry)
        item["read"] = reads

        sel = it.get("properties")
        if sel == "*":
            pids = list(properties)
        elif isinstance(sel, dict) and "ids" in sel:
            pids = sel["ids"]
        elif isinstance(sel, dict):
            (key, val), = sel.items()
            pids = [p for p, v in properties.items() if v[key] == val]
        else:
            pids = []
        missing = [p for p in pids if p not in properties]
        if missing:
            sys.exit("%s: unknown properties %s" % (it["id"], missing))
        item["properties"] = pids

        asel = it.get("assumptions", [])
        item["assumptions"] = list(assumptions) if asel == "*" else asel
        missing = [x for x in item["assumptions"] if x not in assumptions]
        if missing:
            sys.exit("%s: unknown assumptions %s" % (it["id"], missing))

        item["findings"] = it.get("findings", [])
        missing = [x for x in item["findings"] if x not in findings]
        if missing:
            sys.exit("%s: unknown findings %s" % (it["id"], missing))
        items.append(item)

    ids = [i["id"] for i in items]
    if len(set(ids)) != len(ids):
        sys.exit("duplicate item ids")
    manifest = {
        "format": "spec-packet/1",
        "packet": packet,
        "items": items,
        "properties": properties,
        "assumptions": assumptions,
        "findings": findings,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, ensure_ascii=False)
        f.write("\n")
    sys.stderr.write("wrote %s: %d items, %d properties, %d assumptions, %d findings (formalver %s)\n"
                     % (out_path, len(items), len(properties), len(assumptions), len(findings), fv["commit"][:7]))


if __name__ == "__main__":
    main()
