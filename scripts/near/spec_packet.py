#!/usr/bin/env python3
"""Spec review packets on the approval contract: one request per packet item.

Each item of a packet manifest (ui/spec-approvals/packets/*.json, built by
ui/spec-approvals/tools/build-packet.py) becomes one `request_action`. The
action names the packet, the item and the SHA-256 of the item's canonical
payload, so an approval on chain binds to the exact text the reviewer read.
ui/spec-approvals/spec-kit.js computes the same payload, hash and action;
`check` prints them so the two can be compared.

Canonical payload of item X (UTF-8 JSON, object keys sorted at every level,
separators "," and ":", non-ASCII characters written as themselves):

  {"format": manifest.format, "packet": manifest.packet, "item": X,
   "properties":  {id: manifest.properties[id]  for id in X.properties},
   "assumptions": {id: manifest.assumptions[id] for id in X.assumptions},
   "findings":    {id: manifest.findings[id]    for id in X.findings}}

Action (lines joined by "\\n", no trailing newline):

  spec-review/1
  packet: <packet.id> <packet.version>
  item: <X.id>
  title: <X.title>
  sha256: <hex of the canonical payload>

Commands (standard library only):
  check MANIFEST                       validate; print id, sha256, action bytes
  actions MANIFEST --out-dir DIR       write DIR/<id>.action; print id<TAB>sha256<TAB>path
  plan MANIFEST --requests FILE --agent ACCOUNT [--item ID ...]
                                       what to submit, given get_request JSON lines
"""
import argparse
import hashlib
import json
import os
import re
import sys

ACTION_HEADER = "spec-review/1"
MAX_ACTION_LEN = 2048
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
TITLE_RE = re.compile(r"^[ -~]{1,160}$")  # printable ASCII


class Fail(Exception):
    pass


MAX_SAFE_INT = 2**53 - 1


def portable(value, where="packet"):
    """Refuse what spec-kit.js would hash differently or not at all: floats
    (JSON.parse turns 1.0 into 1), integers beyond JavaScript's safe range,
    and object keys outside the BMP (JS sorts keys by UTF-16 code unit)."""
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise Fail("%s: integer %d is outside JavaScript's safe range" % (where, value))
        return
    if isinstance(value, float):
        raise Fail("%s: %r is not an integer; packets may only hold integers" % (where, value))
    if isinstance(value, list):
        for i, v in enumerate(value):
            portable(v, "%s[%d]" % (where, i))
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if any(ord(c) > 0xFFFF for c in k):
                raise Fail("%s: key %r has a character outside the BMP" % (where, k))
            portable(v, "%s.%s" % (where, k))
        return
    raise Fail("%s: unsupported value %r" % (where, value))


def canonical(value):
    portable(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load(path):
    with open(path, encoding="utf-8") as f:
        m = json.load(f)
    if m.get("format") != "spec-packet/1":
        raise Fail("%s: format must be spec-packet/1 (got %r)" % (path, m.get("format")))
    p = m.get("packet") or {}
    for k in ("id", "version"):
        if not isinstance(p.get(k), str) or not ID_RE.match(p[k]):
            raise Fail("packet.%s must match %s" % (k, ID_RE.pattern))
    seen = set()
    for it in m.get("items") or []:
        if not ID_RE.match(it.get("id", "")):
            raise Fail("item id %r must match %s" % (it.get("id"), ID_RE.pattern))
        if it["id"] in seen:
            raise Fail("duplicate item id %s" % it["id"])
        seen.add(it["id"])
        if not TITLE_RE.match(it.get("title", "")):
            raise Fail("item %s: title must be 1-160 printable ASCII characters" % it["id"])
        for key in ("properties", "assumptions", "findings"):
            table = m.get(key) or {}
            for ref in it.get(key) or []:
                if ref not in table:
                    raise Fail("item %s: %s %s is not in the manifest" % (it["id"], key, ref))
    if not seen:
        raise Fail("%s has no items" % path)
    return m


def payload(m, item):
    return {
        "format": m["format"],
        "packet": m["packet"],
        "item": item,
        "properties": {k: m["properties"][k] for k in item.get("properties") or []},
        "assumptions": {k: m["assumptions"][k] for k in item.get("assumptions") or []},
        "findings": {k: m["findings"][k] for k in item.get("findings") or []},
    }


def item_hash(m, item):
    return hashlib.sha256(canonical(payload(m, item))).hexdigest()


def action(m, item):
    text = "\n".join([
        ACTION_HEADER,
        "packet: %s %s" % (m["packet"]["id"], m["packet"]["version"]),
        "item: %s" % item["id"],
        "title: %s" % item["title"],
        "sha256: %s" % item_hash(m, item),
    ])
    if len(text.encode("utf-8")) > MAX_ACTION_LEN:
        raise Fail("item %s: action is longer than %d bytes" % (item["id"], MAX_ACTION_LEN))
    return text


def parse_action(text):
    """-> {packet_id, version, item, title, sha256} for a spec-review/1 action, else None."""
    lines = text.split("\n")
    if len(lines) != 5 or lines[0] != ACTION_HEADER:
        return None
    m = [re.fullmatch(r"packet: (\S+) (\S+)", lines[1]), re.fullmatch(r"item: (\S+)", lines[2]),
         re.fullmatch(r"title: (.+)", lines[3]), re.fullmatch(r"sha256: ([0-9a-f]{64})", lines[4])]
    if not all(m):
        return None
    return {"packet_id": m[0].group(1), "version": m[0].group(2), "item": m[1].group(1),
            "title": m[2].group(1), "sha256": m[3].group(1)}


def select(m, ids):
    if not ids:
        return m["items"]
    known = {it["id"]: it for it in m["items"]}
    bad = [i for i in ids if i not in known]
    if bad:
        raise Fail("unknown item(s): %s (known: %s)" % (", ".join(bad), ", ".join(known)))
    return [known[i] for i in ids]


def cmd_check(a):
    m = load(a.manifest)
    for it in m["items"]:
        act = action(m, it)
        print("%s\t%s\t%d" % (it["id"], item_hash(m, it), len(act.encode("utf-8"))))


def cmd_actions(a):
    m = load(a.manifest)
    os.makedirs(a.out_dir, exist_ok=True)
    for it in select(m, a.item):
        path = os.path.join(a.out_dir, it["id"] + ".action")
        with open(path, "wb") as f:
            f.write(action(m, it).encode("utf-8"))
        print("%s\t%s\t%s" % (it["id"], item_hash(m, it), path))


def cmd_plan(a):
    """One line per selected item: id, verdict, request ids, detail.

    verdict: submit (nothing on chain yet, or only void requests), or skip
    (a pending, approved or rejected request with this exact action from the
    agent exists). Requests for the same item with another hash are listed as
    stale: they were filed for an earlier text of the item.
    """
    m = load(a.manifest)
    reqs = []
    with open(a.requests, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                reqs.append(json.loads(line))
    for it in select(m, a.item):
        want = action(m, it)
        mine = [r for r in reqs if r.get("agent_account_id") == a.agent and r.get("action") == want]
        live = [r for r in mine if r.get("status") in ("pending", "approved", "rejected")]
        stale = []
        for r in reqs:
            p = parse_action(r.get("action") or "")
            if (p and p["packet_id"] == m["packet"]["id"] and p["item"] == it["id"]
                    and r.get("action") != want and r.get("status") == "pending"):
                stale.append(str(r["request_id"]))
        if live:
            r = live[-1]
            verdict, ids, detail = "skip", str(r["request_id"]), r["status"]
        else:
            verdict = "submit"
            ids = ",".join(str(r["request_id"]) for r in mine) or "-"
            detail = "only void requests" if mine else "not on chain"
        if stale:
            detail += "; pending requests for an earlier text: " + ",".join(stale)
        print("%s\t%s\t%s\t%s" % (it["id"], verdict, ids, detail))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("check")
    s.add_argument("manifest")
    s.set_defaults(fn=cmd_check)
    s = sub.add_parser("actions")
    s.add_argument("manifest")
    s.add_argument("--out-dir", required=True)
    s.add_argument("--item", action="append", default=[])
    s.set_defaults(fn=cmd_actions)
    s = sub.add_parser("plan")
    s.add_argument("manifest")
    s.add_argument("--requests", required=True)
    s.add_argument("--agent", required=True)
    s.add_argument("--item", action="append", default=[])
    s.set_defaults(fn=cmd_plan)
    a = ap.parse_args()
    try:
        a.fn(a)
    except (Fail, OSError, ValueError) as e:
        sys.stderr.write("spec_packet.py: %s\n" % e)
        sys.exit(1)


if __name__ == "__main__":
    main()
