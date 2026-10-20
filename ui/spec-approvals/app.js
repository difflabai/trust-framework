/*
 * Spec approval page. Loads a spec review packet (packets/<id>.json), finds
 * the request filed for each item on the approval contract, and lets an
 * approver read the item's supporting material and sign approve or reject.
 *
 * Trust: the chain is the source of truth for what was filed and decided.
 * The packet file is checked against it: the page recomputes each item's
 * hash and action (spec-kit.js) and only offers to approve a request whose
 * action is exactly that text. Review progress and notes are kept in this
 * browser only (localStorage) and go into the export.
 */
(function () {
  "use strict";

  var K = window.ApprovalKit;
  var S = window.SpecKit;
  var el = K.el, text = K.text;
  var $ = function (id) { return document.getElementById(id); };
  var PACKET_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

  var params = new URLSearchParams(location.search);
  var cfg = K.readConfig(params);
  var api = K.client(cfg);
  var packetId = (params.get("packet") || "near-approval").trim();
  var agent = (params.get("agent") || defaultAgent(cfg.contract)).trim().toLowerCase();

  var manifest = null;
  var items = [];               // [{item, hash, action}]
  var requests = new Map();     // request id -> get_request view
  var scanned = 0;              // ids [0, scanned) have been read
  var requestCount = null;
  var decisions = new Map();    // request id -> {kind, account, at_ns, ...}
  var states = {};              // item id -> {current, exact, foreign, stale}
  var selected = params.get("item");
  var connector = null;
  var session = null;
  var signing = false;
  var inFlight = null;
  var pendingConfirm = null;
  var contractInfo = null;

  function defaultAgent(contract) {
    var parent = contract.indexOf("approvals.") === 0 ? contract.slice("approvals.".length) : contract;
    return "spec-agent." + parent;
  }

  function setBanner(message, kind, link) {
    var banner = $("banner");
    banner.hidden = !message;
    banner.className = "status" + (kind ? " " + kind : "");
    banner.replaceChildren(text(message || ""));
    if (link) banner.append(text(" "), el("a", { href: link.href }, [link.label]));
  }

  // ---------------------------------------------------------------- storage

  function storeKey(entry) {
    return "spec-review:" + manifest.packet.id + ":" + manifest.packet.version + ":" + entry.item.id + ":" + entry.hash;
  }

  function loadLocal(entry) {
    var blank = { reads: [], checks: [], note: "" };
    try {
      var raw = localStorage.getItem(storeKey(entry));
      if (!raw) return blank;
      var v = JSON.parse(raw);
      return { reads: Array.isArray(v.reads) ? v.reads : [], checks: Array.isArray(v.checks) ? v.checks : [], note: typeof v.note === "string" ? v.note : "" };
    } catch (e) {
      return blank;
    }
  }

  function saveLocal(entry, local) {
    try { localStorage.setItem(storeKey(entry), JSON.stringify(local)); } catch (e) { /* private mode: progress is not kept */ }
  }

  function ticks(entry) {
    var local = loadLocal(entry);
    var total = entry.item.read.length + entry.item.check.length;
    var done = 0;
    entry.item.read.forEach(function (_, i) { if (local.reads[i]) done++; });
    entry.item.check.forEach(function (_, i) { if (local.checks[i]) done++; });
    return { done: done, total: total, local: local };
  }

  // ----------------------------------------------------------------- packet

  async function loadPacket() {
    if (!PACKET_RE.test(packetId)) throw new Error("packet name is not valid: " + packetId);
    var res = await fetch("packets/" + encodeURIComponent(packetId) + ".json", { cache: "no-cache" });
    if (!res.ok) throw new Error("could not load packets/" + packetId + ".json (HTTP " + res.status + ")");
    manifest = S.validate(await res.json());
    items = [];
    for (var i = 0; i < manifest.items.length; i++) {
      var item = manifest.items[i];
      var hash = await S.itemHash(manifest, item);
      items.push({ item: item, hash: hash, action: S.actionText(manifest, item, hash) });
    }
    if (!selected || !items.some(function (e) { return e.item.id === selected; })) selected = items[0].item.id;
  }

  function renderPacketMeta() {
    var p = manifest.packet;
    document.title = "Spec review · " + p.title;
    $("packet-title").textContent = p.title;
    $("packet-summary").textContent = p.summary || "";
    var about = $("packet-about-body");
    about.replaceChildren();
    if (p.qualifies) about.append(el("p", {}, [el("strong", {}, ["Who may sign: "]), p.qualifies]));
    (p.why_a_day || []).forEach(function (para) { about.append(el("p", {}, [para])); });
    about.append(el("p", { class: "when" }, ["Approving an item signs its exact text on chain: the action carries the SHA-256 of the item, its properties, assumptions and findings, and the commits it was built from."]));
    $("meta-packet").textContent = p.id + " " + p.version + " · " + items.length + " items · about " + totalMinutes() + " min of reading";
    var sources = $("meta-sources");
    sources.replaceChildren();
    Object.keys(p.sources).forEach(function (name, i) {
      var s = p.sources[name];
      if (i) sources.append(text(" · "));
      sources.append(el("a", { href: "https://github.com/" + s.repo + "/tree/" + s.commit }, [s.repo + "@" + s.commit.slice(0, 7)]));
    });
  }

  function totalMinutes() {
    return items.reduce(function (n, e) { return n + (e.item.minutes || 0); }, 0);
  }

  // ------------------------------------------------------------------ chain

  function renderContract() {
    $("meta-contract").replaceChildren(el("a", { href: api.explorerAccount(cfg.contract) }, [cfg.contract]), text(" (" + cfg.network + ")"));
    $("meta-agent").replaceChildren(el("code", {}, [agent]));
    var code = $("meta-code");
    code.replaceChildren();
    if (!contractInfo) {
      code.textContent = "Checking…";
      return;
    }
    if (!contractInfo.hasCode) {
      code.append(el("span", { class: "bad" }, ["No contract code on this account."]));
    } else {
      code.append(el("code", { title: contractInfo.codeHash }, [contractInfo.codeHash.slice(0, 8) + "…" + contractInfo.codeHash.slice(-6)]), text(" "));
      if (!cfg.codeHash) code.append(el("span", { class: "bad" }, ["No expected hash set. Signing disabled."]));
      else if (contractInfo.codeOk) code.append(el("span", { class: "ok" }, ["matches"]));
      else code.append(el("span", { class: "bad" }, ["does not match " + cfg.codeHash + ". Signing disabled."]));
    }
    if (contractInfo.fullAccessKeys > 0) code.append(el("span", { class: "when" }, [" · " + contractInfo.fullAccessKeys + " full-access key(s) on the contract account; re-checked on each refresh"]));
    var owner = $("meta-owner");
    owner.replaceChildren(el("code", {}, [contractInfo.owner || ""]));
    if (cfg.contract === K.DEFAULT_CONTRACT && contractInfo.owner && contractInfo.owner !== K.DEFAULT_OWNER) {
      owner.append(el("span", { class: "warn" }, [" — expected " + K.DEFAULT_OWNER]));
    }
  }

  async function readRequests() {
    requestCount = await api.view("get_request_count", {});
    if (typeof requestCount !== "number") throw new Error("get_request_count did not return a number");
    var failed = 0;
    if (requestCount > scanned) {
      for (var from = scanned; from < requestCount; from += 50) {
        var to = Math.min(requestCount, from + 50);
        var got = await api.requestsRange(from, to);
        got.requests.forEach(function (r) { requests.set(r.request_id, r); });
        failed += got.failed;
        scanned = to;
        setBanner("Reading requests… " + scanned + " of " + requestCount, "");
      }
      setBanner("", "");
    }
    // Pending requests that concern this packet can change; re-read them.
    var watch = [];
    requests.forEach(function (r) {
      if (r.status === "pending" && S.parseAction(r.action)) watch.push(r.request_id);
    });
    await K.mapPool(watch, 4, function (id) {
      return api.view("get_request", { request_id: id }).then(function (r) { if (r) requests.set(id, r); }).catch(function () { failed++; });
    });
    return failed;
  }

  function computeStates() {
    states = {};
    items.forEach(function (entry) {
      var exact = [];
      var foreign = [];
      var stale = [];
      requests.forEach(function (r) {
        if (r.action === entry.action) {
          (r.agent_account_id === agent ? exact : foreign).push(r);
          return;
        }
        var p = S.parseAction(r.action);
        if (p && p.packetId === manifest.packet.id && p.item === entry.item.id && r.status === "pending" && r.agent_account_id === agent) stale.push(r);
      });
      var byId = function (a, b) { return a.request_id - b.request_id; };
      exact.sort(byId);
      // The request that counts: the newest live one (pending, approved or
      // rejected), else the newest void one.
      var live = exact.filter(function (r) { return r.status !== "void"; });
      var current = live.length ? live[live.length - 1] : (exact.length ? exact[exact.length - 1] : null);
      states[entry.item.id] = { current: current, exact: exact, foreign: foreign, stale: stale.sort(byId) };
    });
  }

  async function readDecisions() {
    var need = [];
    items.forEach(function (entry) {
      var c = states[entry.item.id].current;
      if (c && (c.status === "approved" || c.status === "rejected") && !decisions.has(c.request_id)) need.push(c);
    });
    await K.mapPool(need, 4, function (r) {
      var method = r.status === "approved" ? "get_approval" : "get_rejection";
      return api.view(method, { request_id: r.request_id }).then(function (d) {
        if (!d) return;
        decisions.set(r.request_id, r.status === "approved"
          ? { kind: "approved", account: d.approver_account_id, key: d.approver_public_key, at: d.approved_at_ns, block: d.approved_at_block, index: d.approval_index }
          : { kind: "rejected", account: d.approver_account_id, key: d.approver_public_key, at: d.rejected_at_ns, block: d.rejected_at_block });
      }).catch(function () { /* shown without the decider */ });
    });
  }

  function statusOf(entry) {
    var st = states[entry.item.id];
    if (!st || !st.current) return "unfiled";
    return st.current.status;
  }

  var STATUS_LABEL = { unfiled: "not filed", pending: "awaiting decision", approved: "approved", rejected: "rejected", void: "void" };

  function chip(status) {
    return el("span", { class: "chip s-" + status }, [STATUS_LABEL[status] || status]);
  }

  function refresh() {
    if (inFlight) return inFlight;
    inFlight = doRefresh().finally(function () { inFlight = null; });
    return inFlight;
  }

  async function doRefresh() {
    try {
      contractInfo = await api.readContract();
      renderContract();
      var failed = await readRequests();
      if (!cfg.codeOk) {
        setBanner(cfg.codeHash ? "Live code hash does not match the expected hash. Signing is disabled." : "Set the expected code hash before signing.", "bad");
      }
      computeStates();
      await readDecisions();
      render();
      $("checked").textContent = "Checked " + new Date().toLocaleTimeString() + " · " + requestCount + " requests on the contract" + (failed ? " · " + failed + " could not be read" : "") + ".";
    } catch (err) {
      setBanner(K.errorText(err), "bad");
    }
  }

  // ----------------------------------------------------------------- render

  function render() {
    renderProgress();
    renderList();
    renderDetail();
  }

  function renderProgress() {
    var counts = { approved: 0, rejected: 0, pending: 0, unfiled: 0, void: 0 };
    items.forEach(function (e) { counts[statusOf(e)] = (counts[statusOf(e)] || 0) + 1; });
    var bar = $("progress-bar");
    bar.replaceChildren();
    ["approved", "rejected", "pending"].forEach(function (k) {
      if (counts[k]) bar.append(el("span", { class: "s-" + k, style: "width:" + (100 * counts[k] / items.length) + "%" }));
    });
    bar.setAttribute("aria-label", counts.approved + " approved, " + counts.rejected + " rejected, " + counts.pending + " awaiting decision of " + items.length);
    var legend = $("progress-legend");
    legend.replaceChildren(
      el("span", {}, [counts.approved + " approved"]),
      el("span", {}, [counts.rejected + " rejected"]),
      el("span", {}, [counts.pending + " awaiting decision"]),
      el("span", {}, [(counts.unfiled + counts.void) + " not filed or void"]),
      el("span", {}, ["of " + items.length])
    );
  }

  function renderList() {
    var list = $("item-list");
    list.replaceChildren();
    items.forEach(function (entry) {
      var t = ticks(entry);
      var status = statusOf(entry);
      var b = el("button", {
        type: "button",
        "aria-current": entry.item.id === selected ? "true" : "false",
        onclick: function () { select(entry.item.id); }
      }, [
        el("span", { class: "iid" }, [entry.item.id]),
        el("span", { class: "ititle" }, [entry.item.title]),
        el("span", { class: "isub" }, [chip(status), text(" " + t.done + "/" + t.total + " ticked · " + (entry.item.minutes || 0) + " min")])
      ]);
      list.append(el("li", {}, [b]));
    });
  }

  function select(id) {
    selected = id;
    var q = new URLSearchParams(location.search);
    q.set("item", id);
    history.replaceState(null, "", "?" + q.toString());
    renderList();
    renderDetail();
    $("detail").scrollIntoView({ block: "start", behavior: "smooth" });
  }

  function entryById(id) {
    return items.filter(function (e) { return e.item.id === id; })[0];
  }

  function checklist(labels, done, onChange, render) {
    var ul = el("ul", { class: "checks" });
    labels.forEach(function (label, i) {
      var box = el("input", { type: "checkbox", checked: !!done[i] });
      box.addEventListener("change", function () { onChange(i, box.checked); });
      ul.append(el("li", {}, [el("label", {}, [box, el("span", {}, [render ? render(label, i) : label])])]));
    });
    return ul;
  }

  function table(headers, rows, filterable) {
    var wrap = el("div");
    var tbody = el("tbody");
    function fill(q) {
      tbody.replaceChildren();
      rows.filter(function (r) { return !q || r.join("\n").toLowerCase().indexOf(q) !== -1; }).forEach(function (r) {
        tbody.append(el("tr", {}, r.map(function (c, i) { return el("td", { class: i === 0 ? "id" : null }, [c]); })));
      });
    }
    if (filterable) {
      var input = el("input", { type: "search", placeholder: "Filter by id or text", autocomplete: "off", spellcheck: "false" });
      input.addEventListener("input", function () { fill(input.value.trim().toLowerCase()); });
      wrap.append(el("div", { class: "filters" }, [input, el("span", { class: "when" }, [rows.length + " rows"])]));
    }
    fill("");
    wrap.append(el("div", { class: "tablewrap" }, [el("table", {}, [
      el("thead", {}, [el("tr", {}, headers.map(function (h) { return el("th", {}, [h]); }))]),
      tbody
    ])]));
    return wrap;
  }

  function requestLine(r) {
    return [
      el("a", { href: "../approvals/?" + approvalsQuery(r.request_id) }, ["Request " + r.request_id]),
      text(" · filed by "), el("code", {}, [r.agent_account_id]),
      text(" · " + K.formatNs(r.requested_at_ns) + " · block " + r.requested_at_block + " · "),
      chip(r.status)
    ];
  }

  function approvalsQuery(id) {
    var q = new URLSearchParams();
    if (cfg.contract !== K.DEFAULT_CONTRACT) q.set("contract", cfg.contract);
    if (cfg.network !== "testnet") q.set("network", cfg.network);
    if (cfg.rpc !== K.defaultRpc(cfg.network)) q.set("rpc", cfg.rpc);
    if (params.has("code_hash")) q.set("code_hash", cfg.codeHash);
    if (id != null) q.set("request", String(id));
    return q.toString();
  }

  function renderDetail() {
    var root = $("detail");
    var entry = entryById(selected);
    if (!entry) {
      root.replaceChildren(el("p", { class: "empty" }, ["Pick an item."]));
      return;
    }
    var item = entry.item;
    var st = states[item.id] || { current: null, exact: [], foreign: [], stale: [] };
    var t = ticks(entry);
    var local = t.local;
    var status = statusOf(entry);
    var nodes = [];

    nodes.push(el("h2", {}, [item.id + " · " + item.title]));
    nodes.push(el("p", { class: "when" }, [chip(status), text(" · about " + (item.minutes || 0) + " min · " + t.done + " of " + t.total + " ticked")]));

    // On chain.
    var chain = el("div", { class: "stack" });
    if (st.current) {
      chain.append(el("p", {}, requestLine(st.current)));
      var d = decisions.get(st.current.request_id);
      if (d) {
        chain.append(el("p", { class: d.kind === "approved" ? "ok" : "bad" }, [
          (d.kind === "approved" ? "Approved" : "Rejected") + " by ", el("code", {}, [d.account || "unknown"]),
          text(" · " + K.formatNs(d.at) + (d.block != null ? " · block " + d.block : "") + (d.index != null ? " · approval " + d.index : ""))
        ]));
      }
      if (st.current.status === "void") chain.append(el("p", { class: "warn" }, ["The agent key that filed this request was revoked, so it can no longer be decided. Re-run submit-spec-packet.sh to file the item again."]));
    } else {
      chain.append(el("p", { class: "warn" }, ["Not filed on " + cfg.contract + " yet. The owner files it with: ", el("code", {}, ["scripts/near/submit-spec-packet.sh --item " + item.id])]));
    }
    if (st.foreign.length) {
      chain.append(el("p", { class: "warn" }, ["The same text was also filed by another agent (" + st.foreign.map(function (r) { return r.agent_account_id + " as request " + r.request_id; }).join(", ") + "). Only requests from " + agent + " count for this packet."]));
    }
    nodes.push(el("section", {}, [el("h3", {}, ["On chain"]), chain]));

    if (item.summary) nodes.push(el("p", {}, [item.summary]));

    // Reading.
    nodes.push(el("h3", {}, ["Read"]));
    nodes.push(checklist(item.read, local.reads, function (i, v) {
      local.reads[i] = v;
      saveLocal(entry, local);
      renderList();
      renderDetail();
    }, function (r) {
      var src = manifest.packet.sources[r.source] || {};
      var where = r.path + (r.lines ? " lines " + r.lines[0] + "–" + r.lines[1] : "");
      return el("span", { class: "reading" }, [
        el("a", { href: S.sourceUrl(manifest, r), target: "_blank", rel: "noopener" }, [r.label]),
        el("br"),
        el("span", { class: "when path" }, [(src.repo || r.source) + "@" + (src.commit || "").slice(0, 7) + " · " + where]),
        el("br"),
        el("span", { class: "when mono", title: "sha256 of the file at that commit" }, ["sha256 " + r.sha256.slice(0, 16) + "…"])
      ]);
    }));

    // Checks.
    nodes.push(el("h3", {}, ["Check"]));
    nodes.push(checklist(item.check, local.checks, function (i, v) {
      local.checks[i] = v;
      saveLocal(entry, local);
      renderList();
      renderDetail();
    }));

    // Supporting tables.
    if (item.properties.length) {
      nodes.push(el("h3", {}, ["Properties (" + item.properties.length + ")"]));
      nodes.push(table(["ID", "Statement", "Layer", "Evidence", "Status"], item.properties.map(function (id) {
        var p = manifest.properties[id];
        return [id, p.description, p.layer, p.evidence, p.status];
      }), item.properties.length > 8));
    }
    if (item.assumptions.length) {
      nodes.push(el("h3", {}, ["Assumptions (" + item.assumptions.length + ")"]));
      nodes.push(table(["ID", "Statement", "Level", "Status", "Checked by"], item.assumptions.map(function (id) {
        var a = manifest.assumptions[id];
        return [id, a.statement, a.level, a.status, (a.checked_by || []).join(", ")];
      }), item.assumptions.length > 8));
    }
    if (item.findings.length) {
      nodes.push(el("h3", {}, ["Findings (" + item.findings.length + ")"]));
      nodes.push(table(["ID", "Finding", "Resolution"], item.findings.map(function (id) {
        var f = manifest.findings[id];
        return [id, f.finding, f.resolution];
      }), false));
    }

    // Integrity.
    var integrity = el("details", {}, [
      el("summary", {}, ["What you sign"]),
      el("p", { class: "when" }, ["This page recomputed the item's SHA-256 from the packet file. Approve sends this exact action, and only for a request whose action is identical."]),
      el("pre", { class: "action" }, [entry.action])
    ]);
    if (st.current) integrity.append(el("p", { class: "ok" }, ["The filed request carries this action byte for byte."]));
    nodes.push(integrity);

    // Note and decision.
    var decision = el("div", { class: "decision" });
    decision.append(el("h3", {}, ["Decision"]));
    var noteId = "note-" + item.id;
    var note = el("textarea", { id: noteId, placeholder: "Objection, condition or note. Kept in this browser and included in the export. Required to reject." });
    note.value = local.note;
    note.addEventListener("input", function () {
      local.note = note.value;
      saveLocal(entry, local);
      updateButtons();
    });
    decision.append(el("label", { for: noteId }, ["Note"]), note);
    var why = el("p", { class: "when" });
    var approveBtn = el("button", { type: "button", class: "primary", onclick: function () { openConfirm(entry, st.current, "approve"); } }, ["Approve " + item.id]);
    var rejectBtn = el("button", { type: "button", class: "danger", onclick: function () { openConfirm(entry, st.current, "reject"); } }, ["Reject " + item.id]);
    decision.append(el("div", { class: "row" }, [approveBtn, rejectBtn]), why);

    function updateButtons() {
      var block = decisionBlock(entry, st.current);
      var ticked = ticks(entry);
      var approveWhy = block || (ticked.done < ticked.total ? "Tick every reading and check item to approve (" + ticked.done + " of " + ticked.total + ")." : "");
      var rejectWhy = block || (!note.value.trim() ? "Write a note saying why before rejecting." : "");
      approveBtn.disabled = !!approveWhy || signing;
      rejectBtn.disabled = !!rejectWhy || signing;
      approveBtn.title = approveWhy;
      rejectBtn.title = rejectWhy;
      var shown = block || [approveWhy, rejectWhy].filter(Boolean).join(" ");
      why.textContent = shown;
    }
    updateButtons();
    nodes.push(decision);

    if (st.stale.length) {
      var stale = el("div", { class: "stack" });
      stale.append(el("p", { class: "warn" }, ["These pending requests were filed for an earlier text of this item. Approving them would sign text that is not the packet you are reading. Reject them."]));
      st.stale.forEach(function (r) {
        var block = decisionBlock(entry, r);
        stale.append(el("p", {}, requestLine(r).concat([text(" "), el("button", {
          type: "button",
          class: "danger",
          disabled: !!block || signing,
          title: block,
          onclick: function () { openConfirm(entry, r, "reject", true); }
        }, ["Reject request " + r.request_id])])));
      });
      nodes.push(el("section", {}, [el("h3", {}, ["Outdated requests"]), stale]));
    }

    root.replaceChildren.apply(root, nodes);
  }

  // "" if this session may decide request r, else why not.
  function decisionBlock(entry, r) {
    if (!r) return "Nothing to decide until the item is filed.";
    if (r.status !== "pending") return "Request " + r.request_id + " is " + r.status + ".";
    var block = api.signingBlock(session);
    if (block) return block;
    if (session.accountId === r.agent_account_id) return "Your account filed this request. The contract will not let you decide it.";
    return "";
  }

  // ---------------------------------------------------------------- signing

  function openConfirm(entry, r, kind, outdated) {
    if (!r) return;
    pendingConfirm = { entry: entry, request: r, kind: kind, outdated: !!outdated };
    $("confirm-title").textContent = (kind === "approve" ? "Approve " : "Reject ") + (outdated ? "outdated request " + r.request_id : entry.item.id + " (request " + r.request_id + ")") + "?";
    $("confirm-lead").textContent = kind === "approve"
      ? "You will sign approve with this exact action. The wallet must show the same text. If it does not, reject the prompt."
      : "Reject does not include the action in the signed transaction: you are rejecting request id " + r.request_id + ". The contract records no reason; your note goes into the export.";
    $("confirm-meta").textContent = "Filed by " + r.agent_account_id + " · " + K.formatNs(r.requested_at_ns);
    $("confirm-action").textContent = r.action;
    var noteText = loadLocal(entry).note.trim();
    $("confirm-note").hidden = !noteText;
    $("confirm-note").textContent = noteText ? "Your note: " + noteText : "";
    $("confirm-go").textContent = kind === "approve" ? "Sign approve" : "Sign reject";
    $("confirm-go").className = kind === "approve" ? "primary" : "danger";
    $("confirm").showModal();
  }

  async function sign(p) {
    if (signing) return;
    var r = p.request;
    var block = decisionBlock(p.entry, r);
    if (block) {
      setBanner(block, "bad");
      return;
    }
    if (p.kind === "approve" && r.action !== p.entry.action) {
      setBanner("This request's action is not the packet's text for " + p.entry.item.id + ". Not signing.", "bad");
      return;
    }
    signing = true;
    renderDetail();
    setBanner("Checking the request, then asking the wallet to sign " + p.kind + "…", "");
    try {
      var out = await api.decide(connector, session, p.kind, r.request_id, r.action, function (m) { setBanner(m, ""); });
      if (out.request) requests.set(r.request_id, out.request);
      var settled = out.request && out.request.status !== "pending";
      var message = settled ? "Request " + r.request_id + " is " + out.request.status + "." : "The transaction was sent, but request " + r.request_id + " is still pending at finality. Refresh in a moment.";
      setBanner(message, settled ? "" : "warn", out.hash ? { href: api.explorerTx(out.hash), label: "Transaction" } : null);
      computeStates();
      await readDecisions();
    } catch (err) {
      if (K.isCancel(err)) setBanner("Wallet closed. Nothing was signed.", "");
      else setBanner(K.errorText(err), "bad");
    } finally {
      signing = false;
      render();
    }
  }

  // ----------------------------------------------------------------- wallet

  function renderSession(lines) {
    var node = $("wallet-status");
    node.replaceChildren();
    lines.forEach(function (line, i) {
      if (i) node.append(el("br"));
      node.append(text(line));
    });
    if (session && session.accountId === agent) {
      node.append(el("br"), el("span", { class: "warn" }, ["This is the agent account that files the items, so it cannot decide them."]));
    }
    $("connect").textContent = session ? "Disconnect" : "Connect wallet";
    if (manifest) renderDetail();
  }

  async function onSignedIn(account) {
    if (!account || !account.accountId) return;
    var described = await api.describeSession(account);
    session = described.session;
    renderSession(described.lines);
  }

  function onSignedOut() {
    session = null;
    renderSession(["Not connected. You can read the packet without a wallet."]);
  }

  async function connectWallet() {
    if (!connector) {
      setBanner("Wallet connector failed to load. Reads still work. Check the pinned script.", "bad");
      return;
    }
    if (session) {
      try { await connector.disconnect(); } catch (e) { /* already signed out */ }
      onSignedOut();
      return;
    }
    try {
      await connector.connect();
    } catch (err) {
      if (!K.isCancel(err)) setBanner(K.errorText(err), "bad");
    }
  }

  // ----------------------------------------------------------------- export

  function exportReview() {
    if (!manifest) return;
    var out = {
      format: "spec-review-export/1",
      exported_at: new Date().toISOString(),
      packet: { id: manifest.packet.id, version: manifest.packet.version, title: manifest.packet.title, sources: manifest.packet.sources },
      contract: { account_id: cfg.contract, network: cfg.network, code_hash: contractInfo ? contractInfo.codeHash : "", code_hash_matches: !!cfg.codeOk },
      agent: agent,
      reviewer: session ? { account_id: session.accountId, public_key: session.publicKey } : null,
      items: items.map(function (entry) {
        var st = states[entry.item.id] || {};
        var c = st.current;
        var d = c ? decisions.get(c.request_id) : null;
        var t = ticks(entry);
        return {
          id: entry.item.id,
          title: entry.item.title,
          sha256: entry.hash,
          status: statusOf(entry),
          request_id: c ? c.request_id : null,
          decided_by: d ? d.account : null,
          decided_at_ns: d ? d.at : null,
          approval_index: d && d.index != null ? d.index : null,
          ticked: t.done,
          of: t.total,
          note: t.local.note
        };
      })
    };
    var blob = new Blob([JSON.stringify(out, null, 2) + "\n"], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var a = el("a", { href: url, download: "spec-review-" + manifest.packet.id + "-" + manifest.packet.version + ".json" });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // ------------------------------------------------------------------ setup

  function fillSettings() {
    $("set-packet").value = packetId;
    $("set-agent").value = agent;
    $("set-contract").value = cfg.contract;
    $("set-network").value = cfg.network;
    $("set-rpc").value = cfg.rpc;
    $("set-hash").value = cfg.codeHash;
    $("approvals-link").href = "../approvals/" + (approvalsQuery(null) ? "?" + approvalsQuery(null) : "");
  }

  $("connect").addEventListener("click", connectWallet);
  $("refresh").addEventListener("click", function () { refresh(); });
  $("export").addEventListener("click", exportReview);
  $("confirm-cancel").addEventListener("click", function () { $("confirm").close(); });
  $("confirm-go").addEventListener("click", function () {
    var p = pendingConfirm;
    $("confirm").close();
    if (p) sign(p);
  });
  $("settings").addEventListener("submit", function (event) {
    event.preventDefault();
    var contract = $("set-contract").value.trim().toLowerCase();
    var network = $("set-network").value;
    var rpc = $("set-rpc").value.trim();
    var hash = $("set-hash").value.trim();
    var pkt = $("set-packet").value.trim();
    var ag = $("set-agent").value.trim().toLowerCase();
    if (!K.accountOk(contract) || !K.accountOk(ag)) return setBanner("Contract and agent must be valid account ids.", "bad");
    if (!K.rpcAllowed(rpc)) return setBanner("RPC must be HTTPS, or HTTP to localhost.", "bad");
    if (!PACKET_RE.test(pkt)) return setBanner("Packet name is not valid.", "bad");
    var q = new URLSearchParams();
    if (pkt !== "near-approval") q.set("packet", pkt);
    if (contract !== K.DEFAULT_CONTRACT) q.set("contract", contract);
    if (network !== "testnet") q.set("network", network);
    if (rpc !== K.defaultRpc(network)) q.set("rpc", rpc);
    if (hash !== (contract === K.DEFAULT_CONTRACT ? K.DEFAULT_HASH : "")) q.set("code_hash", hash);
    if (ag !== defaultAgent(contract)) q.set("agent", ag);
    location.search = q.toString();
  });

  (async function start() {
    fillSettings();
    renderContract();
    if (!K.accountOk(cfg.contract) || !K.accountOk(agent)) return setBanner("Contract or agent account id is not valid.", "bad");
    if (!K.rpcAllowed(cfg.rpc)) return setBanner("RPC must be HTTPS, or HTTP to localhost.", "bad");
    try {
      await loadPacket();
    } catch (err) {
      $("packet-summary").textContent = "";
      $("item-list").replaceChildren(el("li", { class: "empty" }, ["No packet."]));
      return setBanner(K.errorText(err), "bad");
    }
    renderPacketMeta();
    computeStates();
    render();
    connector = K.initConnector(cfg.network, { signIn: onSignedIn, signOut: onSignedOut });
    if (!connector) {
      $("connect").disabled = true;
      $("wallet-status").textContent = "Wallet connector did not load. You can still read the packet.";
    }
    await refresh();
    setInterval(function () { if (!document.hidden && !signing) refresh(); }, 30000);
    document.addEventListener("visibilitychange", function () { if (!document.hidden && !signing) refresh(); });
  })();
})();
