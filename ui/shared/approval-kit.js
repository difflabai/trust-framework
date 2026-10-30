/*
 * Shared pieces of the approval contract UIs (ui/approvals, ui/spec-approvals,
 * ui/spec-approvals-full).
 * A classic script: it defines window.ApprovalKit and nothing else. No build,
 * no dependencies. The wallet connector (NEAR Connect) is loaded by each page
 * with its own pinned <script integrity=...> tag; this file only uses
 * window.HOTConnect when it is there.
 *
 * Pure helpers are on ApprovalKit directly. Everything that talks to a
 * contract comes from ApprovalKit.client(cfg), where cfg is
 * {network, contract, rpc, codeHash} (ApprovalKit.readConfig builds it from
 * the query string). Chain data is only ever inserted as text.
 */
(function () {
  "use strict";

  // Testnet demonstration. Override with ?contract= (and ?code_hash= for any other account).
  var DEFAULT_CONTRACT = "approvals.difflabai.testnet";
  var DEFAULT_HASH = "5G334oPHzjDvPLXKUSstbaf3BzUPaj1sWZnDhy5Baauv";
  var DEFAULT_OWNER = "difflabai.testnet";
  var GAS = "30000000000000";
  var EMPTY_CODE_HASH = "11111111111111111111111111111111";
  var ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

  function readConfig(q) {
    var network = q.get("network") || "testnet";
    if (network !== "testnet" && network !== "mainnet") network = "testnet";
    var contract = (q.get("contract") || DEFAULT_CONTRACT).trim().toLowerCase();
    var rpc = (q.get("rpc") || defaultRpc(network)).trim();
    var codeHash = q.has("code_hash") ? q.get("code_hash").trim() : (contract === DEFAULT_CONTRACT ? DEFAULT_HASH : "");
    return { network: network, contract: contract, rpc: rpc, codeHash: codeHash };
  }

  function defaultRpc(network) {
    return network === "mainnet" ? "https://rpc.mainnet.near.org" : "https://test.rpc.fastnear.com";
  }

  function rpcAllowed(url) {
    try {
      var u = new URL(url);
      if (u.protocol === "https:") return true;
      return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
    } catch (e) {
      return false;
    }
  }

  function accountOk(id) {
    return id.length >= 2 && id.length <= 64 && ACCOUNT_RE.test(id);
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === "class") node.className = v;
        else if (k.slice(0, 2) === "on" && typeof v === "function") node.addEventListener(k.slice(2), v);
        else if (v === true) node.setAttribute(k, "");
        else node.setAttribute(k, String(v));
      });
    }
    (children || []).forEach(function (child) {
      node.append(child instanceof Node ? child : document.createTextNode(child == null ? "" : String(child)));
    });
    return node;
  }

  function text(s) { return document.createTextNode(s == null ? "" : String(s)); }

  function rpcError(err) {
    if (err == null) return "RPC error";
    if (typeof err === "string") return err;
    var data = err.data;
    if (typeof data === "string" && data) return data;
    if (err.cause && err.cause.name) return err.cause.name + (err.message ? ": " + err.message : "");
    return err.message || "RPC error";
  }

  function errorText(err) {
    if (err == null) return "Unknown error";
    if (typeof err === "string") return err;
    var raw = err instanceof Error ? err.message : "";
    var seen = new Set();
    var texts = [];
    function walk(v, depth) {
      if (v == null || depth > 6) return;
      if (typeof v === "string") {
        if (v && texts.indexOf(v) === -1) texts.push(v);
        return;
      }
      if (typeof v !== "object" || seen.has(v)) return;
      seen.add(v);
      ["message", "ExecutionError", "kind", "error", "panic_msg"].forEach(function (k) {
        if (v[k] != null) walk(v[k], depth + 1);
      });
      Object.keys(v).forEach(function (k) { walk(v[k], depth + 1); });
    }
    walk(err, 0);
    var panic = texts.filter(function (t) { return t.indexOf("Smart contract panicked") !== -1; })[0];
    if (panic) {
      var m = panic.match(/Smart contract panicked: ([^"]+)/);
      return m ? m[1] : panic;
    }
    return raw || texts[0] || "The wallet did not complete the transaction.";
  }

  function isCancel(err) {
    var raw = err instanceof Error ? err.message : (typeof err === "string" ? err : "");
    var t = raw.toLowerCase();
    return t === "user rejected" || t.indexOf("wallet closed") !== -1 || t.indexOf("user cancelled") !== -1 || t.indexOf("user canceled") !== -1 || t.indexOf("rejected by user") !== -1;
  }

  function formatNs(ns) {
    var s = String(ns == null ? "" : ns);
    if (!/^\d+$/.test(s)) return s || "unknown time";
    var ms = s.length > 6 ? Number(s.slice(0, -6)) : 0;
    var date = new Date(ms);
    if (Number.isNaN(date.getTime())) return s;
    return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function suspiciousCodePoints(action) {
    var found = [];
    for (var ch of action) {
      var cp = ch.codePointAt(0);
      var bad = (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff || cp === 0x00ad || cp === 0x2028 || cp === 0x2029;
      if (bad && found.indexOf(cp) === -1) found.push(cp);
    }
    return found;
  }

  function codePointList(cps) {
    return cps.map(function (cp) { return "U+" + cp.toString(16).toUpperCase().padStart(4, "0"); }).join(", ");
  }

  function hexDump(action) {
    var bytes = new TextEncoder().encode(action);
    var lines = [];
    for (var i = 0; i < bytes.length; i += 16) {
      var slice = bytes.slice(i, i + 16);
      var hex = Array.from(slice).map(function (b) { return b.toString(16).padStart(2, "0"); }).join(" ");
      lines.push(i.toString(16).padStart(4, "0") + "  " + hex);
    }
    return lines.join("\n");
  }

  function byteLength(action) {
    return new TextEncoder().encode(action).length;
  }

  function txHash(result) {
    if (!result) return null;
    if (typeof result === "string") return result;
    return (result.transaction && result.transaction.hash) || result.transactionHash || (result.transaction_outcome && result.transaction_outcome.id) || null;
  }

  function shortKey(key) {
    if (!key) return "";
    if (key.length <= 22) return key;
    return key.slice(0, 14) + "…" + key.slice(-6);
  }

  function mapPool(items, limit, fn) {
    var out = new Array(items.length);
    var next = 0;
    function worker() {
      if (next >= items.length) return Promise.resolve();
      var i = next++;
      return fn(items[i], i).then(function (value) {
        out[i] = value;
        return worker();
      });
    }
    var n = Math.min(limit, items.length);
    var workers = [];
    for (var w = 0; w < n; w++) workers.push(worker());
    return Promise.all(workers).then(function () { return out; });
  }

  async function copyText(value, button) {
    var original = button.textContent;
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = "Copied";
    } catch (e) {
      button.textContent = "Copy failed";
    }
    setTimeout(function () { button.textContent = original; }, 1500);
  }

  function permissionLabel(permission) {
    if (permission === "FullAccess" || (permission && permission.GasKeyFullAccess)) return "full-access";
    var fc = permission && (permission.FunctionCall || permission.GasKeyFunctionCall);
    if (fc) return "function-call key for " + fc.receiver_id + " (" + (fc.method_names || []).join(", ") + ")";
    return "unrecognized permission";
  }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  // Everything that reads or signs against one contract.
  function client(cfg) {
    function explorerHost() {
      return cfg.network === "mainnet" ? "https://nearblocks.io" : "https://testnet.nearblocks.io";
    }

    async function rpcQuery(params) {
      var res = await fetch(cfg.rpc, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "approvals-ui", method: "query", params: params }),
        signal: AbortSignal.timeout(20000)
      });
      if (!res.ok) throw new Error("RPC HTTP " + res.status);
      var json = await res.json();
      if (json.error) throw new Error(rpcError(json.error));
      return json.result;
    }

    async function view(method, args) {
      var result = await rpcQuery({
        request_type: "call_function",
        finality: "final",
        account_id: cfg.contract,
        method_name: method,
        args_base64: btoa(JSON.stringify(args))
      });
      var bytes = new Uint8Array(result.result || []);
      var decoded = new TextDecoder().decode(bytes);
      if (!decoded) return null;
      return JSON.parse(decoded);
    }

    // view_account, get_owner and the contract account's keys. Sets
    // cfg.codeOk; signing must stay disabled unless it is true.
    async function readContract() {
      var account = await rpcQuery({ request_type: "view_account", finality: "final", account_id: cfg.contract });
      var live = account && account.code_hash;
      var hasCode = !!live && live !== EMPTY_CODE_HASH;
      cfg.codeOk = hasCode && !!cfg.codeHash && live === cfg.codeHash;
      var owner = await view("get_owner", {});
      var keyList = await rpcQuery({ request_type: "view_access_key_list", finality: "final", account_id: cfg.contract });
      var fullAccess = (keyList.keys || []).filter(function (k) { return k.access_key && k.access_key.permission === "FullAccess"; }).length;
      return { codeHash: live || "", hasCode: hasCode, codeOk: cfg.codeOk, owner: owner, fullAccessKeys: fullAccess };
    }

    // All requests with ids in [from, to), fetched 4 at a time. Failed ids are counted, not thrown.
    async function requestsRange(from, to) {
      var ids = [];
      for (var i = from; i < to; i++) ids.push(i);
      var failed = 0;
      var got = await mapPool(ids, 4, function (id) {
        return view("get_request", { request_id: id }).catch(function () { failed += 1; return null; });
      });
      return { requests: got.filter(Boolean), failed: failed };
    }

    // The wallet account's key: its permission on the account and its
    // registration on this contract. Returns {session, lines}.
    async function describeSession(account) {
      var session = {
        accountId: account.accountId,
        publicKey: account.publicKey || "",
        principal: null,
        permission: null
      };
      var lines = ["Connected as " + account.accountId + "."];
      if (!account.publicKey) {
        lines.push("The wallet did not report a public key. approve will fail unless the key it signs with is already registered.");
        return { session: session, lines: lines };
      }
      lines.push("Signing key " + account.publicKey + ".");
      try {
        var access = await rpcQuery({
          request_type: "view_access_key",
          finality: "final",
          account_id: account.accountId,
          public_key: account.publicKey
        });
        session.permission = access.permission;
        lines.push("On the account this key is " + permissionLabel(access.permission) + ".");
        if (access.permission === "FullAccess") {
          lines.push("A full-access key can be registered with add-approver.sh --force. It is weaker than a key limited to approve and reject on this contract.");
        }
      } catch (err) {
        lines.push("Could not read that access key (" + errorText(err) + ").");
      }
      try {
        var principal = await view("get_principal", { public_key: account.publicKey });
        session.principal = principal;
        if (!principal) lines.push("Not registered on this contract. The owner has to add it before you can sign.");
        else if (principal.role !== "approver") lines.push("Registered as " + principal.role + ", not approver.");
        else if (principal.account_id !== account.accountId) lines.push("Registered to " + principal.account_id + ", not this account.");
        else lines.push("Registered approver, registration " + principal.registration_id + ".");
      } catch (err) {
        lines.push("Could not read get_principal (" + errorText(err) + ").");
      }
      return { session: session, lines: lines };
    }

    // "" when this session may sign approve/reject, else why not.
    function signingBlock(session) {
      if (!cfg.codeOk) return "Signing is disabled until the contract code hash matches the expected hash.";
      if (!session) return "Connect the wallet that holds your approver key.";
      if (!session.principal || session.principal.role !== "approver") return "This key is not a registered approver key.";
      if (session.principal.account_id !== session.accountId) return "The registered key is bound to a different account.";
      return "";
    }

    // Sign approve or reject for request id. approve carries the action
    // from a fresh get_request, and aborts if it differs from `action`
    // (what the approver was shown) or the request is no longer pending.
    // Returns {hash, request}: request is the post-state at finality, or
    // still pending if it did not settle within ~16 s.
    async function decide(connector, session, kind, id, action, onProgress) {
      var block = signingBlock(session);
      if (block) throw new Error(block);
      var fresh = await view("get_request", { request_id: id });
      if (!fresh) throw new Error("request not found");
      if (fresh.status !== "pending") throw new Error("request is no longer pending (" + fresh.status + ")");
      if (kind === "approve" && fresh.action !== action) throw new Error("action changed since you opened it; review it again");
      if (fresh.agent_account_id === session.accountId) throw new Error("approver and agent must be different accounts");
      var wallet = await connector.wallet();
      var args = kind === "approve" ? { request_id: id, action: fresh.action } : { request_id: id };
      var result = await wallet.signAndSendTransaction({
        receiverId: cfg.contract,
        actions: [{
          type: "FunctionCall",
          params: { methodName: kind, args: args, gas: GAS, deposit: "0" }
        }]
      });
      var hash = txHash(result);
      if (onProgress) onProgress("Signed. Waiting until the change is visible at finality…");
      var updated = fresh;
      for (var i = 0; i < 8; i++) {
        await sleep(2000);
        updated = (await view("get_request", { request_id: id })) || updated;
        if (updated.status !== "pending") break;
      }
      return { hash: hash, request: updated };
    }

    return {
      cfg: cfg,
      explorerAccount: function (id) { return explorerHost() + "/address/" + encodeURIComponent(id); },
      explorerTx: function (hash) { return explorerHost() + "/txns/" + encodeURIComponent(hash); },
      rpcQuery: rpcQuery,
      view: view,
      readContract: readContract,
      requestsRange: requestsRange,
      describeSession: describeSession,
      signingBlock: signingBlock,
      decide: decide
    };
  }

  // NEAR Connect without adding a function-call key; every decision is a
  // prompted signature. handlers: {signIn(account), signOut()}. Returns
  // null when the pinned connector script did not load.
  function initConnector(network, handlers) {
    if (!window.HOTConnect) return null;
    var connector = new window.HOTConnect.NearConnector({
      network: network,
      features: { signInWithoutAddKey: true, signAndSendTransaction: true }
    });
    connector.on("wallet:signIn", function (event) {
      var account = event.accounts && event.accounts[0];
      if (account) handlers.signIn(account);
    });
    connector.on("wallet:signOut", handlers.signOut);
    connector.wallet().then(function (wallet) {
      return wallet.getAccounts();
    }).then(function (accounts) {
      if (accounts && accounts.length) handlers.signIn(accounts[0]);
    }).catch(function () { /* no restored session */ });
    return connector;
  }

  window.ApprovalKit = {
    DEFAULT_CONTRACT: DEFAULT_CONTRACT,
    DEFAULT_HASH: DEFAULT_HASH,
    DEFAULT_OWNER: DEFAULT_OWNER,
    GAS: GAS,
    readConfig: readConfig,
    defaultRpc: defaultRpc,
    rpcAllowed: rpcAllowed,
    accountOk: accountOk,
    el: el,
    text: text,
    rpcError: rpcError,
    errorText: errorText,
    isCancel: isCancel,
    formatNs: formatNs,
    suspiciousCodePoints: suspiciousCodePoints,
    codePointList: codePointList,
    hexDump: hexDump,
    byteLength: byteLength,
    txHash: txHash,
    shortKey: shortKey,
    mapPool: mapPool,
    copyText: copyText,
    permissionLabel: permissionLabel,
    client: client,
    initConnector: initConnector
  };
})();
