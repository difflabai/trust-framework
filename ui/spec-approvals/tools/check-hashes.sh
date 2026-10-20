#!/usr/bin/env bash
# Usage: ui/spec-approvals/tools/check-hashes.sh [MANIFEST...]
#
# Check that scripts/near/spec_packet.py (which files the requests) and
# ui/spec-approvals/spec-kit.js (which the page uses to match them) compute
# the same hash and action for every item: on the given manifests (default:
# every packets/*.json) and on a generated manifest full of awkward strings
# (quotes, backslashes, control characters, non-ASCII, astral characters,
# U+2028). Needs python3 and node (18+).
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
UI=$(cd "$HERE/.." && pwd -P)
ROOT=$(cd "$UI/../.." && pwd -P)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

python3 - "$TMP/awkward.json" <<'PY'
import json, sys
s = 'quote " backslash \\ tab \t nl \n cr \r nul \x00 esc \x1b del \x7f é 漢 😀     ﻿ </script>'
m = {
  "format": "spec-packet/1",
  "packet": {"id": "awkward", "version": "v1", "title": s, "sources": {"x": {"repo": "a/b", "commit": "0" * 40, "root": ""}}},
  "items": [
    {"id": "Z", "title": "plain ASCII title", "summary": s, "minutes": 0, "nested": {"b": [1, -2, 9007199254740991], "a": None, "A": True, "_": False, "é": s},
     "read": [], "check": [s], "properties": ["P-1"], "assumptions": ["ASM-X"], "findings": ["F-1"]},
  ],
  "properties": {"P-1": {"description": s, "layer": "", "evidence": "", "status": "", "module": "", "assumptions": []}},
  "assumptions": {"ASM-X": {"statement": s, "level": "", "status": "", "checked_by": []}},
  "findings": {"F-1": {"finding": s, "resolution": s}},
}
json.dump(m, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False)
PY

cat >"$TMP/check.mjs" <<'JS'
import fs from "fs";
globalThis.window = {};
new Function(fs.readFileSync(process.argv[2], "utf8"))();
const K = window.SpecKit;
const m = K.validate(JSON.parse(fs.readFileSync(process.argv[3], "utf8")));
for (const it of m.items) {
  const h = await K.itemHash(m, it);
  console.log([it.id, h, Buffer.byteLength(K.actionText(m, it, h))].join("\t"));
}
JS

if [ $# -eq 0 ]; then set -- "$UI"/packets/*.json; fi
fail=0
for f in "$@" "$TMP/awkward.json"; do
  case $f in *.src.json) continue ;; esac
  python3 "$ROOT/scripts/near/spec_packet.py" check "$f" >"$TMP/py.txt"
  node "$TMP/check.mjs" "$UI/spec-kit.js" "$f" >"$TMP/js.txt"
  if diff -u "$TMP/py.txt" "$TMP/js.txt" >&2; then
    echo "ok: $(basename "$f"): $(wc -l <"$TMP/py.txt" | tr -d ' ') items agree" >&2
  else
    echo "MISMATCH: $f" >&2
    fail=1
  fi
done
exit "$fail"
