/*
 * Spec review packets in the browser: the canonical payload, its SHA-256 and
 * the request action for one packet item. Must agree byte for byte with
 * scripts/near/spec_packet.py, which files the requests; see that file's
 * docstring for the format. Defines window.SpecKit.
 */
(function () {
  "use strict";

  var HEADER = "spec-review/1";
  var ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;

  // JSON with object keys sorted at every level and no whitespace, as
  // Python's json.dumps(sort_keys=True, separators=(",", ":"),
  // ensure_ascii=False). Keys sort by UTF-16 code units in JS and by code
  // points in Python; the two agree for keys without astral characters,
  // which canonicalBytes refuses.
  function canonical(value) {
    if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) throw new Error("only safe integers are allowed in a packet");
      return String(value);
    }
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    if (typeof value === "object") {
      var keys = Object.keys(value).sort();
      keys.forEach(function (k) {
        if (/[\uD800-\uDFFF]/.test(k)) throw new Error("astral characters in a packet key");
      });
      return "{" + keys.map(function (k) { return JSON.stringify(k) + ":" + canonical(value[k]); }).join(",") + "}";
    }
    throw new Error("unsupported value in a packet: " + typeof value);
  }

  function pick(table, ids) {
    var out = {};
    (ids || []).forEach(function (id) {
      if (!table || !Object.prototype.hasOwnProperty.call(table, id)) throw new Error("manifest has no entry " + id);
      out[id] = table[id];
    });
    return out;
  }

  function payload(manifest, item) {
    return {
      format: manifest.format,
      packet: manifest.packet,
      item: item,
      properties: pick(manifest.properties, item.properties),
      assumptions: pick(manifest.assumptions, item.assumptions),
      findings: pick(manifest.findings, item.findings)
    };
  }

  async function sha256Hex(str) {
    var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(digest)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  async function itemHash(manifest, item) {
    return sha256Hex(canonical(payload(manifest, item)));
  }

  function actionText(manifest, item, hash) {
    return [
      HEADER,
      "packet: " + manifest.packet.id + " " + manifest.packet.version,
      "item: " + item.id,
      "title: " + item.title,
      "sha256: " + hash
    ].join("\n");
  }

  // {packetId, version, item, title, sha256} for a spec-review/1 action, else null.
  function parseAction(text) {
    var lines = String(text || "").split("\n");
    if (lines.length !== 5 || lines[0] !== HEADER) return null;
    var p = /^packet: (\S+) (\S+)$/.exec(lines[1]);
    var i = /^item: (\S+)$/.exec(lines[2]);
    var t = /^title: (.+)$/.exec(lines[3]);
    var h = /^sha256: ([0-9a-f]{64})$/.exec(lines[4]);
    if (!p || !i || !t || !h) return null;
    return { packetId: p[1], version: p[2], item: i[1], title: t[1], sha256: h[1] };
  }

  function validate(manifest) {
    if (!manifest || manifest.format !== "spec-packet/1") throw new Error("not a spec-packet/1 manifest");
    var p = manifest.packet || {};
    if (!ID_RE.test(p.id || "") || !ID_RE.test(p.version || "")) throw new Error("packet id or version is malformed");
    var seen = {};
    (manifest.items || []).forEach(function (it) {
      if (!ID_RE.test(it.id || "")) throw new Error("item id is malformed: " + it.id);
      if (seen[it.id]) throw new Error("duplicate item id " + it.id);
      seen[it.id] = true;
      if (!/^[ -~]{1,160}$/.test(it.title || "")) throw new Error("item " + it.id + ": title must be printable ASCII");
    });
    if (!Object.keys(seen).length) throw new Error("the packet has no items");
    return manifest;
  }

  // https://github.com/<repo>/blob/<commit>/<path>#L<a>-L<b>
  function sourceUrl(manifest, entry) {
    var src = manifest.packet.sources[entry.source];
    if (!src) return "";
    var url = "https://github.com/" + src.repo + "/blob/" + src.commit + "/" + entry.path.split("/").map(encodeURIComponent).join("/");
    if (entry.lines) url += "#L" + entry.lines[0] + "-L" + entry.lines[1];
    return url;
  }

  window.SpecKit = {
    HEADER: HEADER,
    canonical: canonical,
    payload: payload,
    itemHash: itemHash,
    actionText: actionText,
    parseAction: parseAction,
    validate: validate,
    sourceUrl: sourceUrl
  };
})();
