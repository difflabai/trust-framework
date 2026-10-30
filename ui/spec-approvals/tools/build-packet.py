#!/usr/bin/env python3
"""Build a spec review packet with one item per requirement/2 sentence.

Usage:
  ui/spec-approvals/tools/build-packet.py --formalver PATH --trust-framework PATH \
      [--src ui/spec-approvals/packets/requirements.src.json] [--out ...]

The source file pins the commits. Every file is read with
`git show <commit>:<path>`, so the working tree does not matter. The items
are R1–R6 and D1–D17 from prolog/requirements/approval_req.pl. Each item
carries the properties traceability.pl says discharge that sentence.

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
DEFAULT_SRC = os.path.join(HERE, "..", "packets", "requirements.src.json")
TITLE_RE = re.compile(r"^[ -~]{1,160}$")
FINDING_RE = re.compile(r"F-\d+")
REQ_RE = re.compile(r"""^requirement\('([A-Z][A-Z0-9]*)',\s*"(.*)"\)\.\s*$""")
TRACE_RE = re.compile(r"""^trace_row\('([A-Z][A-Z0-9]*)',\s*\[(.*)\]\)\.\s*$""")
EXPECTED = ["R%d" % i for i in range(1, 7)] + ["D%d" % i for i in range(1, 18)]


def git_show(repo_dir, commit, path):
    try:
        return subprocess.run(["git", "-C", repo_dir, "show", "%s:%s" % (commit, path)],
                              check=True, capture_output=True).stdout
    except subprocess.CalledProcessError as e:
        sys.exit("git show %s:%s in %s failed: %s" % (commit, path, repo_dir, e.stderr.decode().strip()))


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


def heading_span(lines, start_pat, end_pat, where):
    """1-based inclusive line range from a heading up to, but not including, the next."""
    start = end = None
    for i, line in enumerate(lines):
        if start is None and re.match(start_pat, line):
            start = i
        elif start is not None and re.match(end_pat, line):
            end = i
            break
    if start is None or end is None:
        sys.exit("strategy.md: %s" % where)
    return start + 1, end


def title_for(rid, sentence):
    text = " ".join(sentence.split()).rstrip(".")
    if len(text) > 160:
        cut = text[:157]
        space = cut.rfind(" ")
        if space > 40:
            cut = cut[:space]
        text = cut.rstrip(" ,:;-") + "..."
    if not TITLE_RE.fullmatch(text):
        sys.exit("%s: title is not 1-160 printable ASCII: %r" % (rid, text))
    return text


def minutes_for(n_properties):
    if n_properties > 8:
        return 12
    if n_properties > 4:
        return 8
    return 5


def mentioned_findings(*texts, known):
    """Open findings named in the texts, in order. A mention of a closed id is not a finding to accept."""
    ids = []
    for text in texts:
        for fid in FINDING_RE.findall(text or ""):
            if fid in ids or fid not in known:
                continue
            ids.append(fid)
    return ids


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

    packet = dict(src["packet"])
    clones = {"formalver": a.formalver, "trust-framework": a.trust_framework}
    shown = {}

    def show(source, path):
        key = (source, path)
        if key not in shown:
            s = packet["sources"][source]
            full = (s["root"] + "/" + path) if s["root"] else path
            shown[key] = (full, git_show(clones[source], s["commit"], full))
        return shown[key]

    def file_entry(source, path, label, start, end):
        full, data = show(source, path)
        entry = {"source": source, "path": full, "label": label,
                 "sha256": hashlib.sha256(data).hexdigest()}
        if start is not None:
            entry["lines"] = [start, end]
        return entry

    status = tomllib.loads(show("formalver", "status.toml")[1].decode("utf-8"))
    strategy_text = show("formalver", "strategy.md")[1].decode("utf-8")
    req_lines = show("formalver", "prolog/requirements/approval_req.pl")[1].decode("utf-8").split("\n")
    trace_lines = show("formalver", "prolog/requirements/traceability.pl")[1].decode("utf-8").split("\n")
    strategy_lines = strategy_text.split("\n")

    requirements = {}
    for i, line in enumerate(req_lines):
        m = REQ_RE.match(line)
        if not m:
            if line.startswith("requirement("):
                sys.exit("approval_req.pl:%d: requirement fact is not a single quoted line" % (i + 1))
            continue
        rid, sentence = m.group(1), m.group(2)
        if rid in requirements:
            sys.exit("approval_req.pl: duplicate requirement %s" % rid)
        requirements[rid] = {"sentence": sentence, "line": i + 1}
    got = list(requirements)
    if got != EXPECTED:
        missing = [r for r in EXPECTED if r not in requirements]
        extra = [r for r in got if r not in EXPECTED]
        sys.exit("approval_req.pl: want %s; missing %s; extra %s" % (EXPECTED, missing, extra))

    discharge = {rid: [] for rid in EXPECTED}
    trace_hits = {rid: [] for rid in EXPECTED}
    for i, line in enumerate(trace_lines):
        m = TRACE_RE.match(line)
        if not m:
            if line.startswith("trace_row("):
                sys.exit("traceability.pl:%d: trace_row is not a single line" % (i + 1))
            continue
        rid, body = m.group(1), m.group(2)
        if rid not in discharge:
            sys.exit("traceability.pl:%d: trace_row for unknown requirement %s" % (i + 1, rid))
        trace_hits[rid].append(i + 1)
        for pid in re.findall(r"'([^']+)'", body):
            if pid not in discharge[rid]:
                discharge[rid].append(pid)
    empty = [rid for rid in EXPECTED if not discharge[rid]]
    if empty:
        sys.exit("traceability.pl: no discharge for %s" % empty)

    properties = {}
    for module, mod in status["modules"].items():
        for pid, p in (mod.get("properties") or {}).items():
            if pid in properties:
                sys.exit("status.toml: property %s is in more than one module" % pid)
            rec = {
                "module": module,
                "layer": p.get("layer", ""),
                "evidence": p.get("evidence", ""),
                "status": p.get("status", ""),
                "description": p.get("description", ""),
                "assumptions": list(p.get("assumptions") or []),
            }
            if p.get("harness"):
                rec["harness"] = p["harness"]
            if p.get("cross"):
                rec["cross"] = list(p["cross"])
            if p.get("depends_on"):
                rec["depends_on"] = list(p["depends_on"])
            properties[pid] = rec
    missing = sorted({pid for ids in discharge.values() for pid in ids if pid not in properties})
    if missing:
        sys.exit("traceability.pl names properties not in status.toml: %s" % missing)

    assumptions = {k: {"statement": v.get("statement", ""), "level": v.get("level", ""),
                       "status": v.get("status", ""), "checked_by": v.get("checked_by", [])}
                   for k, v in status["assumptions"].items()}
    findings = findings_table(strategy_text)
    goals = heading_span(strategy_lines, r"^## 1\. ", r"^## 2\. ", "no section 1 before section 2")
    catalogue = heading_span(strategy_lines, r"^### 5\.12 ", r"^## 6\. ", "no section 5.12 before section 6")

    items = []
    used_properties = []
    used_assumptions = []
    used_findings = []
    for rid in EXPECTED:
        sentence = requirements[rid]["sentence"]
        pids = discharge[rid]
        asms = []
        for pid in pids:
            for asm in properties[pid]["assumptions"]:
                if asm not in assumptions:
                    sys.exit("%s: property %s names unknown assumption %s" % (rid, pid, asm))
                if asm not in asms:
                    asms.append(asm)
        finding_ids = mentioned_findings(
            sentence, *(properties[pid]["description"] for pid in pids),
            known=findings)
        checks = [
            "The sentence says what the contract is meant to do.",
            "It neither over-claims nor under-claims against the contract README.",
            "The properties listed are the right discharge: nothing the sentence promises is missing, and none is the wrong check.",
        ]
        if asms:
            checks.append("Each assumption the discharge rests on is acceptable for this deployment.")
        if finding_ids:
            checks.append("Each related finding is acceptable with the resolution given.")
        reads = [
            file_entry("formalver", "prolog/requirements/approval_req.pl",
                       "Requirement sentence", requirements[rid]["line"], requirements[rid]["line"]),
        ]
        for n, line_no in enumerate(trace_hits[rid], 1):
            label = "Discharge in traceability.pl" if len(trace_hits[rid]) == 1 else "Discharge row %d in traceability.pl" % n
            reads.append(file_entry("formalver", "prolog/requirements/traceability.pl", label, line_no, line_no))
        see = [
            file_entry("trust-framework", "contracts/approval/README.md", "Contract README", None, None),
            file_entry("formalver", "strategy.md", "What the requirements establish (§1)", goals[0], goals[1]),
            file_entry("formalver", "strategy.md", "Traceability table (§5.12)", catalogue[0], catalogue[1]),
        ]
        items.append({
            "id": rid,
            "title": title_for(rid, sentence),
            "minutes": minutes_for(len(pids)),
            "summary": "Sign this sentence, and that the properties below are what discharges it. You are not signing the property text as the requirement.",
            "statement": sentence,
            "check": checks,
            "read": reads,
            "see": see,
            "properties": pids,
            "assumptions": asms,
            "findings": finding_ids,
        })
        for pid in pids:
            if pid not in used_properties:
                used_properties.append(pid)
        for asm in asms:
            if asm not in used_assumptions:
                used_assumptions.append(asm)
        for fid in finding_ids:
            if fid not in used_findings:
                used_findings.append(fid)

    manifest = {
        "format": "spec-packet/1",
        "packet": packet,
        "items": items,
        "properties": {pid: properties[pid] for pid in used_properties},
        "assumptions": {k: assumptions[k] for k in used_assumptions},
        "findings": {k: findings[k] for k in used_findings},
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, ensure_ascii=False)
        f.write("\n")
    fv = packet["sources"]["formalver"]
    sys.stderr.write("wrote %s: %d requirements, %d properties, %d assumptions, %d findings (formalver %s)\n"
                     % (out_path, len(items), len(used_properties), len(used_assumptions), len(used_findings), fv["commit"][:7]))


if __name__ == "__main__":
    main()
