#!/usr/bin/env python3
"""Stdlib-only helpers for scripts/near/*.sh.

Read-only NEAR JSON-RPC queries, base58, key files, code hashes and exact
yoctoNEAR arithmetic (integers only, never floats).

Secrets: a secret key is only ever read from stdin or from a key file, never
from argv, and is never printed. Commands that write secrets create files
with mode 0600.

Exit codes: 0 ok, 1 error, 2 usage, 3 account does not exist,
4 account has no contract code, 5 timed out waiting.
"""

import argparse
import ast
import base64
import hashlib
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
YOCTO_PER_NEAR = 10 ** 24
DEFAULT_STORAGE_PRICE = 10 ** 19  # yoctoNEAR per byte (testnet and mainnet today)
EMPTY_CODE_HASH = "1" * 32  # base58 of 32 zero bytes: "no contract"
USER_AGENT = "trust-framework-near-scripts/1"

EXIT_UNKNOWN_ACCOUNT = 3
EXIT_NO_CODE = 4
EXIT_TIMEOUT = 5

UINT_RE = re.compile(r"[0-9]+")
B58_HASH_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class Fail(Exception):
    def __init__(self, msg, code=1):
        super().__init__(msg)
        self.code = code


# ----------------------------------------------------------------- base58


def b58encode(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + out


def b58decode(text):
    n = 0
    for ch in text:
        i = B58.find(ch)
        if i < 0:
            raise ValueError("invalid base58 character")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\0" * pad + body


# ------------------------------------------------------------------- keys


def parse_secret_key(secret):
    """ed25519:<base58 of 64 bytes seed||pub> -> (secret_str, public_key_str)."""
    secret = secret.strip()
    if not secret.startswith("ed25519:"):
        if secret.startswith("secp256k1:"):
            raise Fail("secp256k1 secret keys are not supported here; use an ed25519 key")
        raise Fail("secret key must look like ed25519:<base58> (64 bytes)")
    try:
        raw = b58decode(secret[len("ed25519:"):])
    except ValueError:
        raise Fail("secret key is not valid base58")
    if len(raw) != 64:
        raise Fail("ed25519 secret key must decode to 64 bytes (seed || public key), got %d" % len(raw))
    return secret, "ed25519:" + b58encode(raw[32:])


def check_public_key(pk):
    m = re.match(r"^(ed25519|secp256k1):([1-9A-HJ-NP-Za-km-z]+)$", pk or "")
    if not m:
        raise Fail("public key must look like ed25519:<base58> or secp256k1:<base58>: %r" % pk)
    raw = b58decode(m.group(2))
    want = 32 if m.group(1) == "ed25519" else 64
    if len(raw) != want:
        raise Fail("%s public key must be %d bytes, got %d" % (m.group(1), want, len(raw)))
    return pk


def read_stdin_secret():
    data = sys.stdin.read()
    if not data.strip():
        raise Fail("no secret key on stdin")
    return data.strip()


def write_private_json(path, obj):
    """Write JSON to path with mode 0600 (atomically via a temp file)."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = "%s.tmp.%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_keyfile(path):
    """Return (account_id or None, public_key, secret) from a key file.

    Accepts near-cli access-key files ({account_id, public_key, private_key}),
    near-cli generated keypairs and neard validator/node key files
    ({account_id, public_key, secret_key}).
    """
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, ValueError) as e:
        raise Fail("cannot read key file %s: %s" % (path, e))
    secret = d.get("private_key") or d.get("secret_key")
    if not secret:
        raise Fail("key file %s has no private_key/secret_key" % path)
    secret, derived = parse_secret_key(secret)
    stated = d.get("public_key")
    if stated and stated != derived:
        raise Fail("key file %s: public_key does not match its secret key" % path)
    return d.get("account_id") or d.get("implicit_account_id"), derived, secret


# -------------------------------------------------------------------- RPC


def is_loopback_url(url):
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return False
    return host in LOOPBACK_HOSTS


_OPENERS = {}


def url_opener(url):
    """urllib opener; a loopback RPC (the sandbox) never goes through http(s)_proxy."""
    key = is_loopback_url(url)
    if key not in _OPENERS:
        _OPENERS[key] = (urllib.request.build_opener(urllib.request.ProxyHandler({})) if key
                         else urllib.request.build_opener())
    return _OPENERS[key]


def is_refused(e):
    reason = getattr(e, "reason", e)
    return getattr(reason, "errno", None) in (61, 111) or "Connection refused" in str(reason)


def rpc(url, method, params, retries=6):
    body = json.dumps({"jsonrpc": "2.0", "id": "scripts-near", "method": method, "params": params}).encode()
    delay = 1.0
    last = None
    opener = url_opener(url)
    for attempt in range(retries + 1):
        resp = None
        retryable = False
        try:
            req = urllib.request.Request(
                url, data=body, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
            with opener.open(req, timeout=30) as r:
                raw = r.read()
            try:
                resp = json.loads(raw)
            except ValueError:
                last = "non-JSON response from %s: %r" % (url, raw[:200])
                retryable = True
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                resp = json.loads(raw)
            except ValueError:
                resp = None
            if resp is None:
                last = "HTTP %d from %s: %s" % (e.code, url, raw[:200].decode("utf-8", "replace"))
                retryable = e.code == 429 or e.code >= 500
                if not retryable:
                    raise Fail(last)
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
            last = "cannot reach RPC %s: %s" % (url, getattr(e, "reason", e))
            # Nothing listens there (e.g. a stopped sandbox): retrying won't help.
            retryable = not is_refused(e)
        if resp is not None:
            if "error" in resp and resp["error"]:
                err = resp["error"]
                text = json.dumps(err)
                if "rate limit" in text.lower() or "TIMEOUT_ERROR" in text or "Too Many Requests" in text:
                    last = "RPC %s: %s" % (url, text[:300])
                    retryable = True
                else:
                    return None, err
            elif "result" in resp:
                return resp["result"], None
            else:
                last = "unexpected RPC response: %r" % (resp,)
                retryable = True
        if not retryable or attempt == retries:
            break
        sys.stderr.write("retrying RPC %s (%d/%d): %s\n" % (method, attempt + 1, retries, last))
        time.sleep(delay)
        delay = min(delay * 2, 10)
    raise Fail(last or "RPC request failed")


def err_name(err):
    if not err:
        return None
    cause = err.get("cause") or {}
    return cause.get("name") or err.get("name")


def err_text(err):
    if isinstance(err, str):
        return err
    data = err.get("data")
    cause = err.get("cause") or {}
    info = cause.get("info")
    parts = [p for p in [err_name(err), json.dumps(info) if info else None,
                         data if isinstance(data, str) else json.dumps(data) if data else None] if p]
    return ": ".join(parts) or json.dumps(err)


def is_unknown_account(err):
    return err_name(err) == "UNKNOWN_ACCOUNT" or "does not exist while viewing" in json.dumps(err)


def view_account(url, account_id):
    res, err = rpc(url, "query", {"request_type": "view_account", "finality": "final", "account_id": account_id})
    if err:
        if is_unknown_account(err):
            return None
        raise Fail("view_account %s: %s" % (account_id, err_text(err)))
    return res


def call_view(url, contract, method, args):
    params = {
        "request_type": "call_function",
        "finality": "final",
        "account_id": contract,
        "method_name": method,
        "args_base64": base64.b64encode(json.dumps(args, separators=(",", ":")).encode()).decode(),
    }
    res, err = rpc(url, "query", params)
    if err:
        if is_unknown_account(err):
            raise Fail("account %s does not exist" % contract, EXIT_UNKNOWN_ACCOUNT)
        text = err_text(err)
        if "CodeDoesNotExist" in text or err_name(err) == "NO_CONTRACT_CODE":
            raise Fail("account %s has no contract code" % contract, EXIT_NO_CODE)
        raise Fail("%s.%s: %s" % (contract, method, text))
    if res.get("error"):
        text = res["error"]
        if "CodeDoesNotExist" in text:
            raise Fail("account %s has no contract code" % contract, EXIT_NO_CODE)
        raise Fail("%s.%s: %s" % (contract, method, text))
    raw = bytes(res.get("result") or [])
    text = raw.decode("utf-8", "replace")
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text


def storage_price(url):
    res, err = rpc(url, "EXPERIMENTAL_protocol_config", {"finality": "final"})
    if err or not res:
        return DEFAULT_STORAGE_PRICE
    try:
        v = res["runtime_config"]["storage_amount_per_byte"]
    except (KeyError, TypeError):
        return DEFAULT_STORAGE_PRICE
    return require_uint("storage_amount_per_byte", v)


def require_uint(what, v):
    """An RPC-supplied integer (JSON number or decimal string) -> int, or Fail.

    The shell scripts feed these values into arithmetic, so anything but
    plain digits from a (possibly hostile) RPC must never get through."""
    if isinstance(v, bool) or not UINT_RE.fullmatch(str(v)):
        raise Fail("RPC returned a non-numeric %s: %r" % (what, v))
    return int(v)


def gas_price(url):
    res, err = rpc(url, "gas_price", [None])
    if err or not isinstance(res, dict):
        raise Fail("gas_price: %s" % (err_text(err) if err else "no result"))
    return require_uint("gas_price", res.get("gas_price"))


def access_key(url, account_id, public_key):
    res, err = rpc(url, "query", {"request_type": "view_access_key", "finality": "final",
                                   "account_id": account_id, "public_key": public_key})
    if err:
        name = err_name(err)
        text = json.dumps(err)
        if name == "UNKNOWN_ACCESS_KEY" or "does not exist" in text:
            if is_unknown_account(err):
                return {"exists": False, "account_exists": False}
            return {"exists": False}
        raise Fail("view_access_key %s: %s" % (account_id, err_text(err)))
    if res.get("error"):  # very old RPC style
        return {"exists": False}
    perm = res.get("permission")
    out = {"exists": True, "nonce": require_uint("nonce of %s on %s" % (public_key, account_id), res.get("nonce"))}
    if perm == "FullAccess":
        out["permission"] = "FullAccess"
    else:
        fc = (perm or {}).get("FunctionCall") or {}
        out["permission"] = "FunctionCall"
        out["receiver_id"] = fc.get("receiver_id")
        out["method_names"] = fc.get("method_names") or []
        allowance = fc.get("allowance")
        out["allowance"] = None if allowance is None else str(require_uint("allowance", allowance))
    return out


# --------------------------------------------------------------- amounts


def to_yocto(text):
    s = text.strip()
    m = re.match(r"^([0-9]+(?:\.[0-9]*)?|\.[0-9]+)\s*(near|yocto|yoctonear)?$", s, re.I)
    if not m:
        raise Fail("not an amount: %r (use e.g. 1.5, '1.5 NEAR' or '1000 yoctoNEAR')" % text)
    num, unit = m.group(1), (m.group(2) or "near").lower()
    if unit in ("yocto", "yoctonear"):
        if "." in num:
            raise Fail("yoctoNEAR amounts must be integers")
        return int(num)
    whole, _, frac = num.partition(".")
    if len(frac) > 24:
        raise Fail("too many decimal places (max 24): %r" % text)
    return int(whole or "0") * YOCTO_PER_NEAR + int((frac + "0" * 24)[:24] or "0")


def fmt_near(yocto, digits=5, rounding="down"):
    yocto = int(yocto)
    neg = yocto < 0
    y = -yocto if neg else yocto
    unit = 10 ** (24 - digits)
    q, r = divmod(y, unit)
    if r and rounding == "up" and not neg:
        q += 1
    whole, frac = divmod(q, 10 ** digits)
    s = str(whole)
    if digits:
        fs = str(frac).rjust(digits, "0").rstrip("0")
        if fs:
            s += "." + fs
    return ("-" if neg else "") + s + " NEAR"


_ALLOWED = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Compare, ast.Call, ast.Name, ast.Load,
            ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.Pow, ast.USub, ast.UAdd,
            ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq, ast.Constant)


def int_expr(expr):
    """Evaluate integer arithmetic: + - * // % ** comparisons, max(), min(), cdiv()."""
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED):
            raise Fail("unsupported expression element: %s" % type(node).__name__)
        if isinstance(node, ast.Constant) and not isinstance(node.value, int):
            raise Fail("only integer literals are allowed")
        if isinstance(node, ast.Name) and node.id not in ("max", "min", "cdiv"):
            raise Fail("unknown name %s" % node.id)
    env = {"max": max, "min": min, "cdiv": lambda a, b: -(-a // b), "__builtins__": {}}
    val = eval(compile(tree, "<expr>", "eval"), env)  # noqa: S307 - AST checked above
    if isinstance(val, bool):
        return int(val)
    return val


# ---------------------------------------------------------------- output


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# A 64-byte ed25519 secret key is ~86-88 base58 chars; public keys are 43-44.
SECRET_RE = re.compile(r"(ed25519:)[1-9A-HJ-NP-Za-km-z]{80,}")
NOISE_RE = [
    re.compile(r"^Note: .near. CLI configuration is stored in"),
    re.compile(r"CLI has a new update available"),
    re.compile(r"^To update .near. CLI use"),
    re.compile(r"^Here is your console command"),
    re.compile(r"^Server error\. It is currently possible to continue creating an account offline"),
    re.compile(r"^You can sign and send the created transaction later"),
]


def filter_cli(text):
    out = []
    skip_next = False
    for line in ANSI_RE.sub("", text).splitlines():
        line = SECRET_RE.sub(r"\1<redacted>", line)
        if skip_next:
            skip_next = False
            if line.startswith("    "):
                continue
        if any(r.search(line) for r in NOISE_RE):
            skip_next = line.startswith("Here is your console command")
            continue
        out.append(line.rstrip())
    # collapse runs of blank lines and trim
    res = []
    for line in out:
        if not line and (not res or not res[-1]):
            continue
        res.append(line)
    while res and not res[-1]:
        res.pop()
    return "\n".join(res) + ("\n" if res else "")


def cli_error(text):
    """The useful tail of a filtered near-cli error: logs and the error itself."""
    lines = text.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if line.startswith("--- Logs") or line.startswith("--- Transaction failed"):
            start = i
            break
    else:
        for i, line in enumerate(lines):
            if line.startswith("Error:"):
                start = i
                break
    out = []
    skip = False
    for line in lines[start:]:
        if skip:
            skip = False
            continue
        if line.startswith("To see the transaction in the transaction explorer"):
            skip = True
            continue
        if line.startswith("Location:"):
            skip = True
            continue
        if "RUST_BACKTRACE" in line or line.startswith("Backtrace omitted") or line.startswith("Run with COLORBT"):
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out) + ("\n" if out else "")


STORAGE_ACCT_RE = re.compile(r"An account which needs balance: <([^>]+)>")
STORAGE_AMT_RE = re.compile(r"Balance required to complete the action: <([0-9.]+) NEAR>")
TXCOST_RE = re.compile(r"Account <([^>]+)> does not have enough balance \(([0-9.]+) NEAR\) "
                       r"to cover TX cost \(([0-9.]+) NEAR\)")


def balance_error(text):
    """Parse near-cli's 'not enough balance' errors -> dict or None.

    top_up_near is the shortfall rounded up to 0.01 NEAR, plus 0.01 NEAR."""
    acct = req = None
    kind = None
    m1, m2 = STORAGE_ACCT_RE.search(text), STORAGE_AMT_RE.search(text)
    if m2 and "enough to cover storage" in text:
        acct, req, kind = (m1.group(1) if m1 else None), to_yocto(m2.group(1)), "storage"
    else:
        m = TXCOST_RE.search(text)
        if m:
            acct, kind = m.group(1), "the transaction cost"
            req = max(0, to_yocto(m.group(3)) - to_yocto(m.group(2)))
    if not acct or req is None:
        return None
    cent = YOCTO_PER_NEAR // 100
    top = -(-req // cent) * cent + cent
    return {"account_id": acct, "kind": kind, "required_near": fmt_near(req, 24).split()[0],
            "top_up_near": fmt_near(top, 2).split()[0]}


def json_get(obj, path):
    cur = obj
    if path in ("", "."):
        return cur
    for part in path.lstrip(".").split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def safe_print(text, ascii_fallback=None):
    """print(), falling back when stdout's encoding can't represent the text."""
    try:
        print(text)
    except UnicodeEncodeError:
        if ascii_fallback is not None:
            print(ascii_fallback)
        else:
            sys.stdout.flush()
            sys.stdout.buffer.write(text.encode("utf-8", "backslashreplace") + b"\n")


def print_value(v, pretty=False):
    if v is None:
        print("null")
    elif isinstance(v, str):
        safe_print(v)
    elif isinstance(v, bool):
        print("true" if v else "false")
    else:
        safe_print(json.dumps(v, indent=2 if pretty else None, ensure_ascii=False),
                   json.dumps(v, indent=2 if pretty else None, ensure_ascii=True))


# --------------------------------------------------------------- commands


def rpc_url(args):
    url = args.rpc or os.environ.get("NEAR_RPC_URL")
    if not url:
        raise Fail("no RPC URL (pass --rpc or set NEAR_RPC_URL)", 2)
    return url


def wait_loop(timeout, fn):
    """Call fn() until it returns a truthy value or timeout seconds pass."""
    deadline = time.time() + timeout
    while True:
        val = fn()
        if val:
            return val
        if time.time() >= deadline:
            return None
        time.sleep(1)


def cmd_account(a):
    url = rpc_url(a)

    def get():
        acc = view_account(url, a.account_id)
        if acc is None:
            return {"exists": False}
        out = {"exists": True}
        # Validated: the shell does arithmetic with these values.
        for k in ("amount", "locked"):
            out[k] = str(require_uint("%s of %s" % (k, a.account_id), acc.get(k)))
        for k in ("storage_usage", "block_height"):
            out[k] = require_uint("%s of %s" % (k, a.account_id), acc.get(k))
        code_hash = acc.get("code_hash")
        if not isinstance(code_hash, str) or not B58_HASH_RE.fullmatch(code_hash):
            raise Fail("RPC returned a malformed code_hash for %s: %r" % (a.account_id, code_hash))
        out["code_hash"] = code_hash
        out["has_code"] = code_hash != EMPTY_CODE_HASH
        return out

    if a.wait_exists or a.wait_code_hash:
        def ready():
            acc = get()
            if not acc["exists"]:
                return None
            if a.wait_code_hash and acc.get("code_hash") != a.wait_code_hash:
                return None
            return acc
        res = wait_loop(a.timeout, ready)
        if res is None:
            last = get()
            print_value(last)
            raise Fail("timed out after %ds waiting for %s (%s)" % (
                a.timeout, a.account_id, "code_hash " + a.wait_code_hash if a.wait_code_hash else "to exist"),
                EXIT_TIMEOUT)
        print_value(res)
        return
    res = get()
    if a.wait_gone:
        res = wait_loop(a.timeout, lambda: (lambda r: r if not r["exists"] else None)(get())) or get()
        if res["exists"]:
            print_value(res)
            raise Fail("timed out waiting for %s to be deleted" % a.account_id, EXIT_TIMEOUT)
    print_value(res)


def cmd_view(a):
    url = rpc_url(a)
    try:
        args = json.loads(a.args) if a.args else {}
    except ValueError as e:
        raise Fail("arguments are not valid JSON: %s" % e, 2)
    if not isinstance(args, dict):
        raise Fail("arguments must be a JSON object", 2)
    if a.wait_ok or a.wait_nonnull or a.wait_equals:
        holder = {}

        def attempt():
            try:
                v = call_view(url, a.contract, a.method, args)
            except Fail as e:
                if e.code == EXIT_UNKNOWN_ACCOUNT:
                    raise
                holder["err"] = e
                return None
            holder["val"] = v
            holder.pop("err", None)
            if a.wait_nonnull and v is None:
                return None
            if a.wait_equals is not None and json.dumps(v) != json.dumps(json.loads(a.wait_equals)):
                return None
            return {"v": v}
        res = wait_loop(a.timeout, attempt)
        if res is None:
            if "err" in holder:
                raise Fail("timed out after %ds; last error: %s" % (a.timeout, holder["err"]), EXIT_TIMEOUT)
            print_value(holder.get("val"), a.pretty)
            raise Fail("timed out after %ds waiting for %s.%s" % (a.timeout, a.contract, a.method), EXIT_TIMEOUT)
        print_value(res["v"], a.pretty)
        return
    print_value(call_view(url, a.contract, a.method, args), a.pretty)


def cmd_requests(a):
    """Requests from_index..from_index+limit-1 (clamped to get_request_count), one JSON per line."""
    url = rpc_url(a)
    count = require_uint("get_request_count", call_view(url, a.contract, "get_request_count", {}))
    if a.from_index is None:
        start = max(0, count - a.limit)
    else:
        start = a.from_index
    end = min(count, start + a.limit)
    for rid in range(start, end):
        r = call_view(url, a.contract, "get_request", {"request_id": rid})
        if r is None:
            continue
        if a.status and r.get("status") not in a.status:
            continue
        print(json.dumps(r, separators=(",", ":"), ensure_ascii=True))
    sys.stderr.write("requests %d..%d of %d (get_request_count)\n" % (start, max(start, end) - 1, count)
                     if end > start else "no requests in range (get_request_count %d)\n" % count)


def cmd_code(a):
    url = rpc_url(a)
    res, err = rpc(url, "query", {"request_type": "view_code", "finality": "final", "account_id": a.account_id})
    if err:
        if is_unknown_account(err):
            raise Fail("account %s does not exist" % a.account_id, EXIT_UNKNOWN_ACCOUNT)
        if "CodeDoesNotExist" in json.dumps(err) or err_name(err) == "NO_CONTRACT_CODE":
            raise Fail("account %s has no contract code" % a.account_id, EXIT_NO_CODE)
        raise Fail("view_code %s: %s" % (a.account_id, err_text(err)))
    code = base64.b64decode(res.get("code_base64") or "")
    print_value({"length": len(code), "code_hash": b58encode(hashlib.sha256(code).digest()),
                 "sha256": hashlib.sha256(code).hexdigest()})


def cmd_access_key(a):
    url = rpc_url(a)
    check_public_key(a.public_key)
    if a.wait or a.wait_gone:
        want = not a.wait_gone
        res = wait_loop(a.timeout, lambda: (lambda r: r if r["exists"] == want else None)(
            access_key(url, a.account_id, a.public_key)))
        if res is None:
            raise Fail("timed out after %ds waiting for key %s on %s to %s" % (
                a.timeout, a.public_key, a.account_id, "appear" if want else "disappear"), EXIT_TIMEOUT)
        print_value(res)
        return
    print_value(access_key(url, a.account_id, a.public_key))


def cmd_access_keys(a):
    url = rpc_url(a)
    res, err = rpc(url, "query", {"request_type": "view_access_key_list", "finality": "final",
                                   "account_id": a.account_id})
    if err:
        if is_unknown_account(err):
            raise Fail("account %s does not exist" % a.account_id, EXIT_UNKNOWN_ACCOUNT)
        raise Fail("view_access_key_list %s: %s" % (a.account_id, err_text(err)))
    keys = []
    for k in res.get("keys") or []:
        perm = (k.get("access_key") or {}).get("permission")
        item = {"public_key": k.get("public_key")}
        if perm == "FullAccess":
            item["permission"] = "FullAccess"
        else:
            fc = (perm or {}).get("FunctionCall") or {}
            item.update(permission="FunctionCall", receiver_id=fc.get("receiver_id"),
                        method_names=fc.get("method_names") or [], allowance=fc.get("allowance"))
        keys.append(item)
    print_value(keys, a.pretty)


def cmd_storage_price(a):
    print(storage_price(rpc_url(a)))


def cmd_gas_price(a):
    print(gas_price(rpc_url(a)))


def cmd_status(a):
    url = rpc_url(a)

    def get(retries=0):
        try:
            res, err = rpc(url, "status", [], retries=retries)
        except Fail as e:
            holder["err"] = str(e)
            return None
        if err or not res:
            holder["err"] = err_text(err) if err else "empty status"
            return None
        return res
    holder = {}
    res = wait_loop(a.wait, get) if a.wait else get(3)
    if not res:
        raise Fail("RPC %s is not responding (%s)" % (url, holder.get("err", "?")))
    sync = res.get("sync_info") or {}
    print_value({"chain_id": res.get("chain_id"), "protocol_version": res.get("protocol_version"),
                 "latest_block_height": sync.get("latest_block_height"),
                 "version": (res.get("version") or {}).get("version")})


def cmd_pubkey(a):
    _, pk = parse_secret_key(read_stdin_secret())
    print(pk)


def cmd_write_keyfile(a):
    secret, pk = parse_secret_key(read_stdin_secret())
    write_private_json(a.out, {"account_id": a.account, "public_key": pk, "private_key": secret})
    print(pk)


def cmd_convert_keyfile(a):
    _, pk, secret = load_keyfile(a.src)
    write_private_json(a.out, {"account_id": a.account, "public_key": pk, "private_key": secret})
    print(pk)


def cmd_keyfile_info(a):
    acct, pk, _ = load_keyfile(a.path)
    mode = os.stat(a.path).st_mode & 0o777
    with open(a.path) as f:
        d = json.load(f)
    print_value({"account_id": acct, "public_key": pk, "mode": "%04o" % mode,
                 "contract_id": d.get("contract_id"), "role": d.get("role"),
                 "registration_id": d.get("registration_id"), "methods": d.get("methods")})


ENV_PREFIX_RE = re.compile(r"[A-Z][A-Z0-9_]*")
ENV_SAFE_VALUE_RE = re.compile(r"[A-Za-z0-9:._-]+")


def env_line_name(line):
    """The variable a KEY=VALUE line of an env file sets, or None."""
    t = line.strip()
    if t.startswith("export "):
        t = t[len("export "):].lstrip()
    if t.startswith("#") or "=" not in t:
        return None
    return t.split("=", 1)[0].strip()


def cmd_env_append(a):
    """Append <PREFIX>_ACCOUNT_ID/_PUBLIC_KEY/_PRIVATE_KEY from a key file to an env file.

    The secret goes from the key file straight into the env file, which is
    rewritten atomically with mode 0600. Identical values already present:
    no change. Different ones: refused unless --replace, which drops the old
    lines (and this prefix's header comment) first.
    """
    if not ENV_PREFIX_RE.fullmatch(a.prefix):
        raise Fail("bad prefix %r (A-Z, 0-9 and _ only)" % a.prefix, 2)
    acct, pk, secret = load_keyfile(a.keyfile)
    if not acct:
        raise Fail("key file %s has no account_id" % a.keyfile)
    values = [(a.prefix + "_ACCOUNT_ID", acct), (a.prefix + "_PUBLIC_KEY", pk),
              (a.prefix + "_PRIVATE_KEY", secret)]
    for _, v in values:
        if not ENV_SAFE_VALUE_RE.fullmatch(v):
            raise Fail("refusing to write a value with unexpected characters for %s" % a.prefix)
    header = "# %s: %s" % (a.prefix, " ".join(a.comment.split()))
    names = dict(values)
    path = os.path.realpath(a.env_file)
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        mode = os.stat(path).st_mode & 0o777
    except FileNotFoundError:
        lines, mode = [], 0o600
    current = {}
    for line in lines:
        n = env_line_name(line)
        if n in names:
            current.setdefault(n, line.split("=", 1)[1].strip().strip("\"'"))
    if current:
        if len(current) == len(names) and all(current[n] == v for n, v in values):
            print("unchanged")
            return
        if not a.replace:
            raise Fail("%s already sets %s with other values; pass --replace to overwrite them"
                       % (path, ", ".join(sorted(current))))
        lines = [l for l in lines
                 if env_line_name(l) not in names and not l.startswith("# %s: " % a.prefix)]
    while lines and not lines[-1].strip():
        lines.pop()
    if lines:
        lines.append("")
    lines.append(header)
    lines.extend("%s=%s" % nv for nv in values)
    tmp = "%s.tmp.%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if mode & 0o077:
        sys.stderr.write("note: %s was mode %04o; it is now 0600\n" % (path, mode))
    print("replaced" if current else "appended")


def cmd_keyfile_set(a):
    """Add bookkeeping fields (contract_id, role, registration_id) to a key file, keeping it 0600."""
    load_keyfile(a.path)  # validates
    with open(a.path) as f:
        d = json.load(f)
    for k, v in parse_pairs(a.pairs).items():
        if k in ("account_id", "public_key", "private_key", "secret_key"):
            raise Fail("refusing to change %s" % k, 2)
        d[k] = v
    write_private_json(a.path, d)


def cmd_file_mode(a):
    print("%04o" % (os.stat(a.path).st_mode & 0o777))


def cmd_sandbox_env(a):
    _, pk, secret = load_keyfile(a.validator_key)
    acct = a.account
    lines = [
        "# Generated by scripts/near/sandbox.sh for a local near-sandbox node.",
        "# Throwaway sandbox key; do not reuse. Regenerated on 'sandbox.sh start'.",
        "NEAR_NETWORK=sandbox",
        "NEAR_RPC_URL=%s" % a.rpc_url,
        "NEAR_ACCOUNT_ID=%s" % acct,
        "NEAR_PUBLIC_KEY=%s" % pk,
        "NEAR_PRIVATE_KEY=%s" % secret,
        "NEAR_CREDENTIALS_DIR=%s" % a.credentials_dir,
        "NEAR_DEPLOYMENTS_DIR=%s" % a.deployments_dir,
        "",
    ]
    d = os.path.dirname(os.path.abspath(a.out))
    os.makedirs(d, exist_ok=True)
    tmp = "%s.tmp.%d" % (a.out, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines))
    os.replace(tmp, a.out)
    print(pk)


def cmd_hash_file(a):
    h = hashlib.sha256()
    size = 0
    with open(a.path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
            size += len(chunk)
    print_value({"size": size, "sha256": h.hexdigest(), "code_hash": b58encode(h.digest())})


def cmd_hex_to_b58(a):
    print(b58encode(bytes.fromhex(a.hex)))


def cmd_to_yocto(a):
    print(to_yocto(a.amount))


def cmd_fmt_near(a):
    print(fmt_near(int(a.yocto), a.digits, a.round))


def cmd_int(a):
    print(int_expr(a.expr))


def cmd_filter_cli(a):
    sys.stdout.write(filter_cli(sys.stdin.read()))


def cmd_cli_error(a):
    sys.stdout.write(cli_error(sys.stdin.read()))


def cmd_balance_error(a):
    res = balance_error(sys.stdin.read())
    if res:
        print_value(res)


def cmd_json_get(a):
    text = sys.stdin.read()
    try:
        obj = json.loads(text) if text.strip() else None
    except ValueError as e:
        raise Fail("input is not JSON: %s" % e)
    for p in a.paths:
        v = json_get(obj, p)
        if a.join is not None and isinstance(v, list):
            print(a.join.join(str(x) for x in v))
        else:
            print_value(v)


def cmd_json_pretty(a):
    text = sys.stdin.read()
    if not text.strip():
        return
    try:
        obj = json.loads(text)
    except ValueError:
        sys.stdout.write(text)
        return
    safe_print(json.dumps(obj, indent=2, ensure_ascii=False), json.dumps(obj, indent=2, ensure_ascii=True))


def check_utf8(obj, where="argument"):
    """Refuse strings carrying undecodable bytes (surrogate escapes from argv)."""
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError:
            raise Fail("%s is not valid UTF-8" % where, 2)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            check_utf8(k, where)
            check_utf8(v, "%s %s" % (where, k))
    elif isinstance(obj, list):
        for v in obj:
            check_utf8(v, where)


def parse_pairs(pairs):
    obj = {}
    for p in pairs:
        i = p.find("=")
        if i <= 0:
            raise Fail("expected key=value or key:=json, got %r" % p, 2)
        if p[i - 1] == ":":
            k, v = p[:i - 1], p[i + 1:]
            try:
                obj[k] = json.loads(v)
            except ValueError as e:
                raise Fail("%s: not JSON: %s" % (k, e), 2)
        else:
            obj[p[:i]] = p[i + 1:]
    return obj


def cmd_json_build(a):
    obj = parse_pairs(a.pairs)
    if a.file:
        k, _, path = a.file.partition("=")
        if not k or not path:
            raise Fail("--file needs key=PATH ('-' for stdin)", 2)
        try:
            if path == "-":
                data = sys.stdin.buffer.read()
            else:
                with open(path, "rb") as f:
                    data = f.read()
        except OSError as e:
            raise Fail("cannot read %s: %s" % (path, e))
        try:
            obj[k] = data.decode("utf-8")
        except UnicodeDecodeError:
            raise Fail("%s is not valid UTF-8" % ("stdin" if path == "-" else path), 2)
    check_utf8(obj)
    # ASCII output (\uXXXX escapes): independent of the locale's encoding.
    print(json.dumps(obj, separators=(",", ":"), ensure_ascii=True))


def cmd_record_deployment(a):
    rec = parse_pairs(a.pairs)
    prev = None
    if os.path.exists(a.out):
        try:
            with open(a.out) as f:
                prev = json.load(f)
        except (OSError, ValueError):
            prev = None
    if a.merge:
        if not isinstance(prev, dict):
            raise Fail("no deployment record to update: %s" % a.out)
        prev.update(rec)
        rec = prev
        tmp = "%s.tmp.%d" % (a.out, os.getpid())
        with open(tmp, "w") as f:
            json.dump(rec, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, a.out)
        return
    history = []
    if isinstance(prev, dict):
        history = list(prev.get("history") or [])
        prev = dict(prev)
        prev.pop("history", None)
        history.append(prev)
    rec["history"] = history
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    tmp = "%s.tmp.%d" % (a.out, os.getpid())
    with open(tmp, "w") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, a.out)


def cmd_check_proof(a):
    """Assert fields of a JSON object read from stdin: key=value (string compare) pairs."""
    obj = json.loads(sys.stdin.read() or "null")
    if not isinstance(obj, dict):
        raise Fail("expected a JSON object, got %s" % json.dumps(obj))
    bad = []
    expect = list(parse_pairs(a.pairs).items())
    if a.expect_json:
        try:
            extra = json.loads(a.expect_json)
        except ValueError as e:
            raise Fail("--expect-json is not JSON: %s" % e, 2)
        if not isinstance(extra, dict):
            raise Fail("--expect-json must be a JSON object", 2)
        expect += [(k, v) for k, v in extra.items() if not a.only or k in a.only]
    for k, want in expect:
        got = json_get(obj, k)
        if isinstance(want, str) and not isinstance(got, str) and got is not None:
            got = json.dumps(got)
        if got != want:
            bad.append("%s: expected %s, got %s" % (k, json.dumps(want), json.dumps(got)))
    if bad:
        raise Fail("assertion failed:\n  " + "\n  ".join(bad))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rpc", help="JSON-RPC URL (default: $NEAR_RPC_URL)")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("account", help="view_account at finality final -> JSON with 'exists'")
    s.add_argument("account_id")
    s.add_argument("--wait-exists", action="store_true")
    s.add_argument("--wait-gone", action="store_true")
    s.add_argument("--wait-code-hash")
    s.add_argument("--timeout", type=int, default=30)
    s.set_defaults(fn=cmd_account)

    s = sub.add_parser("view", help="call a view method -> JSON result")
    s.add_argument("contract")
    s.add_argument("method")
    s.add_argument("args", nargs="?", default="{}")
    s.add_argument("--pretty", action="store_true")
    s.add_argument("--wait-ok", action="store_true", help="retry until the call succeeds")
    s.add_argument("--wait-nonnull", action="store_true", help="retry until the result is not null")
    s.add_argument("--wait-equals", help="retry until the result equals this JSON")
    s.add_argument("--timeout", type=int, default=30)
    s.set_defaults(fn=cmd_view)

    s = sub.add_parser("requests", help="list requests of an approval contract, one JSON per line")
    s.add_argument("contract")
    s.add_argument("--from", dest="from_index", type=int)
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--status", action="append", help="only requests with this status (repeatable)")
    s.set_defaults(fn=cmd_requests)

    s = sub.add_parser("code", help="length and hashes of an account's deployed code")
    s.add_argument("account_id")
    s.set_defaults(fn=cmd_code)

    s = sub.add_parser("access-key", help="permission of one access key -> JSON")
    s.add_argument("account_id")
    s.add_argument("public_key")
    s.add_argument("--wait", action="store_true", help="wait until the key exists")
    s.add_argument("--wait-gone", action="store_true", help="wait until the key is gone")
    s.add_argument("--timeout", type=int, default=30)
    s.set_defaults(fn=cmd_access_key)

    s = sub.add_parser("access-keys", help="list an account's access keys")
    s.add_argument("account_id")
    s.add_argument("--pretty", action="store_true")
    s.set_defaults(fn=cmd_access_keys)

    s = sub.add_parser("storage-price", help="yoctoNEAR per byte of storage")
    s.set_defaults(fn=cmd_storage_price)

    s = sub.add_parser("gas-price", help="current gas price in yoctoNEAR per gas")
    s.set_defaults(fn=cmd_gas_price)

    s = sub.add_parser("status", help="node status")
    s.add_argument("--wait", type=int, default=0, help="seconds to wait for the RPC to come up")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("pubkey", help="public key of the ed25519 secret key read from stdin")
    s.set_defaults(fn=cmd_pubkey)

    s = sub.add_parser("write-keyfile", help="write a 0600 near-cli access-key file from a secret on stdin")
    s.add_argument("--account", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_write_keyfile)

    s = sub.add_parser("convert-keyfile", help="rewrite a key file as a 0600 near-cli access-key file")
    s.add_argument("--in", dest="src", required=True)
    s.add_argument("--account", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_convert_keyfile)

    s = sub.add_parser("keyfile-info", help="account id, public key and mode of a key file (no secret)")
    s.add_argument("path")
    s.set_defaults(fn=cmd_keyfile_info)

    s = sub.add_parser("keyfile-set", help="add key=value / key:=json bookkeeping fields to a key file")
    s.add_argument("path")
    s.add_argument("pairs", nargs="+")
    s.set_defaults(fn=cmd_keyfile_set)

    s = sub.add_parser("env-append", help="append a key file's account/public/private key to an env file (0600)")
    s.add_argument("--keyfile", required=True)
    s.add_argument("--env-file", required=True)
    s.add_argument("--prefix", required=True)
    s.add_argument("--comment", required=True)
    s.add_argument("--replace", action="store_true")
    s.set_defaults(fn=cmd_env_append)

    s = sub.add_parser("file-mode", help="octal permission bits of a file")
    s.add_argument("path")
    s.set_defaults(fn=cmd_file_mode)

    s = sub.add_parser("sandbox-env", help="write the sandbox .env (0600) from a validator key file")
    s.add_argument("--validator-key", required=True)
    s.add_argument("--account", required=True)
    s.add_argument("--rpc-url", required=True)
    s.add_argument("--credentials-dir", required=True)
    s.add_argument("--deployments-dir", required=True)
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_sandbox_env)

    s = sub.add_parser("hash-file", help="size, sha256 hex and NEAR code hash (base58 sha256) of a file")
    s.add_argument("path")
    s.set_defaults(fn=cmd_hash_file)

    s = sub.add_parser("hex-to-b58")
    s.add_argument("hex")
    s.set_defaults(fn=cmd_hex_to_b58)

    s = sub.add_parser("to-yocto", help="'1.5', '1.5 NEAR' or '10 yoctoNEAR' -> integer yoctoNEAR")
    s.add_argument("amount")
    s.set_defaults(fn=cmd_to_yocto)

    s = sub.add_parser("fmt-near", help="integer yoctoNEAR -> 'x.y NEAR'")
    s.add_argument("yocto")
    s.add_argument("--digits", type=int, default=5)
    s.add_argument("--round", choices=["down", "up"], default="down")
    s.set_defaults(fn=cmd_fmt_near)

    s = sub.add_parser("int", help="exact integer arithmetic; comparisons print 1/0")
    s.add_argument("expr")
    s.set_defaults(fn=cmd_int)

    s = sub.add_parser("filter-cli", help="strip ANSI, near-cli noise and secrets from stdin")
    s.set_defaults(fn=cmd_filter_cli)

    s = sub.add_parser("cli-error", help="the relevant part of filtered near-cli error output on stdin")
    s.set_defaults(fn=cmd_cli_error)

    s = sub.add_parser("balance-error", help="parse a near-cli 'not enough balance' error on stdin -> JSON (or nothing)")
    s.set_defaults(fn=cmd_balance_error)

    s = sub.add_parser("json-get", help="print fields (dotted paths) of the JSON on stdin")
    s.add_argument("paths", nargs="+")
    s.add_argument("--join", help="print a list value joined with this separator")
    s.set_defaults(fn=cmd_json_get)

    s = sub.add_parser("json-pretty", help="pretty-print the JSON on stdin")
    s.set_defaults(fn=cmd_json_pretty)

    s = sub.add_parser("json-build", help="build a JSON object from key=string / key:=json pairs")
    s.add_argument("pairs", nargs="*")
    s.add_argument("--file", help="key=PATH: add a string read from a file ('-': stdin), verbatim")
    s.set_defaults(fn=cmd_json_build)

    s = sub.add_parser("record-deployment", help="write a deployment record, keeping history")
    s.add_argument("--out", required=True)
    s.add_argument("--merge", action="store_true", help="add fields to the current record instead")
    s.add_argument("pairs", nargs="*")
    s.set_defaults(fn=cmd_record_deployment)

    s = sub.add_parser("assert-fields", help="assert key=value fields of the JSON object on stdin")
    s.add_argument("pairs", nargs="*")
    s.add_argument("--expect-json", help="also assert every field of this JSON object")
    s.add_argument("--only", action="append", help="with --expect-json: only this field (repeatable)")
    s.set_defaults(fn=cmd_check_proof)

    a = p.parse_args(argv)
    if not getattr(a, "fn", None):
        p.print_help(sys.stderr)
        return 2
    try:
        a.fn(a)
    except Fail as e:
        sys.stderr.write("%s\n" % e)
        return e.code
    except BrokenPipeError:
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
