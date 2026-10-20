# shellcheck shell=bash
# shellcheck disable=SC2034 # globals here are used by the scripts that source this file
# Shared configuration and helpers for scripts/near/*.sh. Source it, don't run it.
#
# Works under macOS /bin/bash 3.2 and Linux bash: no associative arrays, no
# mapfile, no ${var,,}, no `wait -n`.
#
# Conventions for every script:
#   - results (JSON, ids) go to stdout; progress, tx links and errors to stderr
#   - exit 0 ok, 1 failure, 2 usage error
#   - the private key never appears in argv, stdout or logs (not even under
#     bash -x: xtrace is suspended while it is handled): it is read from the
#     environment / .env and written only to 0600 files in a private temp dir
#     that is removed on exit (stale dirs left by a crash are swept by the
#     next run).

NEAR_SCRIPTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "$NEAR_SCRIPTS_DIR/../.." && pwd -P)
NEAR_UTIL_PY="$NEAR_SCRIPTS_DIR/near_util.py"
EMPTY_CODE_HASH=11111111111111111111111111111111
DEFAULT_WASM="$REPO_ROOT/contracts/approval/target/near/approval_contract/approval_contract.wasm"
# Fee margin reserved on top of computed storage costs (measured: create
# subaccount ~0.0072 NEAR, deploy+init ~0.0014 NEAR, function calls < 0.001).
TX_FEE_MARGIN_YOCTO=10000000000000000000000 # 0.01 NEAR
NEAR_CALL_GAS="30 Tgas"
# Since protocol 85 (near-parameters 85.yaml, min_gas_purchase_price) the
# gas attached to a function call is bought up front at max(gas_price, 1e9)
# yoctoNEAR per gas and the unused part refunded later: 30 Tgas holds
# 0.03 NEAR of the signer's balance while the call runs.
MIN_GAS_PURCHASE_PRICE=1000000000
# NEP-448: an account using at most this many bytes needs no storage stake
# (nearcore ZERO_BALANCE_ACCOUNT_STORAGE_LIMIT).
ZBA_STORAGE_LIMIT=770
ONE_NEAR_YOCTO=1000000000000000000000000
# Set by near_check_chain; never taken from the environment.
NEAR_CHAIN_ID=""

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[31m' C_YEL=$'\033[33m' C_GRN=$'\033[32m' C_BOLD=$'\033[1m' C_OFF=$'\033[0m'
else
  C_RED='' C_YEL='' C_GRN='' C_BOLD='' C_OFF=''
fi

log() { printf '%s\n' "$*" >&2; }

# xtrace_off / xtrace_on: suspend `set -x` around code that handles the
# private key, so `bash -x scripts/near/...` never prints it. Call as
# `{ xtrace_off; } 2>/dev/null` (hides the trace of the call itself). Not
# nestable.
NEAR_XTRACE=0
xtrace_off() {
  case $- in *x*)
    NEAR_XTRACE=1
    set +x
    ;;
  esac
}
xtrace_on() {
  if [ "$NEAR_XTRACE" = 1 ]; then
    NEAR_XTRACE=0
    set -x
  fi
}
info() { printf '%s==>%s %s\n' "$C_BOLD" "$C_OFF" "$*" >&2; }
ok() { printf '%sok:%s %s\n' "$C_GRN" "$C_OFF" "$*" >&2; }
warn() { printf '%swarning:%s %s\n' "$C_YEL" "$C_OFF" "$*" >&2; }
die() {
  printf '%serror:%s %s\n' "$C_RED" "$C_OFF" "$1" >&2
  shift
  local line
  for line in "$@"; do printf '       %s\n' "${line//$'\n'/$'\n'       }" >&2; done
  exit 1
}
usage_error() {
  printf 'error: %s\n' "$1" >&2
  printf "Run '%s --help' for usage.\n" "$(basename "$0")" >&2
  exit 2
}
# Print the leading comment block of the calling script (its usage text).
print_usage() {
  awk 'NR==1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

case $- in *x*) printf 'warning: xtrace is on; the scripts turn it off while they handle NEAR_PRIVATE_KEY\n' >&2 ;; esac

# require_uint WHAT VALUE: VALUE must be plain digits (before shell arithmetic).
require_uint() {
  case $2 in '' | *[!0-9]*) die "$1 is not a non-negative integer: '$2'" ;; esac
}

# ------------------------------------------------------------------ python

NEAR_PYTHON=${NEAR_PYTHON:-python3}
command -v "$NEAR_PYTHON" >/dev/null 2>&1 || die "python3 not found (needed for scripts/near/near_util.py, stdlib only)."
# near_util.py, isolated (-I: no PYTHONPATH, no user site, no cwd on sys.path),
# in UTF-8 mode (-X utf8: argv and stdio are UTF-8 whatever the locale).
nu() { "$NEAR_PYTHON" -I -X utf8 "$NEAR_UTIL_PY" "$@"; }
# near_util.py against the configured RPC.
nur() { "$NEAR_PYTHON" -I -X utf8 "$NEAR_UTIL_PY" --rpc "$NEAR_RPC_URL" "$@"; }
# jget JSON PATH... : print fields of a JSON string.
jget() {
  local json=$1
  shift
  printf '%s' "$json" | nu json-get "$@"
}
yocto() { nu to-yocto "$1"; }
fmt_near() { nu fmt-near "$@"; }
int_calc() { nu int "$1"; }

# ------------------------------------------------------------- temp/cleanup

NEAR_TMP=""
NEAR_CLI_HOME=""
near_cleanup() {
  local rc=$?
  if declare -F near_extra_cleanup >/dev/null 2>&1; then near_extra_cleanup || true; fi
  if [ -n "${NEAR_TMP:-}" ] && [ -d "$NEAR_TMP" ]; then rm -rf "$NEAR_TMP"; fi
  return "$rc"
}
# Remove temp dirs of earlier runs that died without cleaning up (kill -9,
# crash): ours, with a pid file whose process is gone. They can hold 0600
# copies of the signing key.
near_sweep_stale_tmp() {
  local base=$1 d pid
  for d in "$base"/near-ops.*; do
    [ -d "$d" ] && [ -O "$d" ] && [ -f "$d/pid" ] || continue
    pid=$(cat "$d/pid" 2>/dev/null || true)
    case $pid in '' | *[!0-9]*) continue ;; esac
    kill -0 "$pid" 2>/dev/null && continue
    rm -rf "$d"
  done
}
near_tmp_init() {
  [ -n "$NEAR_TMP" ] && return 0
  local base=${TMPDIR:-/tmp}
  base=${base%/}
  near_sweep_stale_tmp "$base"
  NEAR_TMP=$(umask 077 && mktemp -d "$base/near-ops.XXXXXXXX") || die "mktemp -d failed under $base"
  chmod 700 "$NEAR_TMP"
  printf '%s\n' "$$" >"$NEAR_TMP/pid"
  trap near_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  # Without this, a closed output pipe (`... | head`) kills the script
  # before the EXIT trap removes the temp dir.
  trap 'exit 141' PIPE
}

# ---------------------------------------------------------------- config

# Parse KEY=VALUE lines without evaluating anything. Accepts blank lines,
# # comments, an optional leading `export `, and single- or double-quoted
# values (taken literally). Only the settings in NEAR_ENV_KEYS are used;
# anything else in the file (other tools' settings) is ignored. Variables
# already set in the environment win over the file.
# NEAR_ALLOW_MAINNET and NEAR_ALLOW_INSECURE_RPC are deliberately not
# here: those opt-ins must come from the real environment.
NEAR_ENV_KEYS="NEAR_NETWORK NEAR_RPC_URL NEAR_EXPLORER_TX_URL NEAR_ACCOUNT_ID NEAR_PRIVATE_KEY
NEAR_PUBLIC_KEY NEAR_CREDENTIALS_DIR NEAR_DEPLOYMENTS_DIR NEAR_CLI_BIN NEAR_CACHE_DIR
APPROVAL_CONTRACT_ID APPROVAL_OWNER_ID APPROVAL_INITIAL_BALANCE APPROVAL_WASM APPROVAL_PRINCIPAL_BALANCE
SANDBOX_DIR SANDBOX_RPC_PORT NEAR_FAUCET_URL
APPROVAL_AGENT_ACCOUNT_ID APPROVAL_AGENT_PUBLIC_KEY APPROVAL_AGENT_PRIVATE_KEY
APPROVAL_APPROVER_ACCOUNT_ID APPROVAL_APPROVER_PUBLIC_KEY APPROVAL_APPROVER_PRIVATE_KEY"
NEAR_ENV_KEYS=$(printf '%s' "$NEAR_ENV_KEYS" | tr '\n' ' ')
NEAR_PRIVATE_KEY_FROM_FILE=0
load_env_file() {
  { xtrace_off; } 2>/dev/null
  _load_env_file "$@"
  xtrace_on
}
_load_env_file() {
  local file=$1 line key value n=0 q
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line=${line%$'\r'}
    line="${line#"${line%%[![:space:]]*}"}"
    case $line in '' | '#'*) continue ;; esac
    case $line in 'export '*)
      line=${line#export }
      line="${line#"${line%%[![:space:]]*}"}"
      ;;
    esac
    case $line in *=*) ;; *)
      warn "$file:$n: ignoring a line without '='"
      continue
      ;;
    esac
    key=${line%%=*}
    value=${line#*=}
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"
    case $key in '' | [0-9]* | *[!A-Za-z0-9_]*)
      warn "$file:$n: ignoring an invalid variable name"
      continue
      ;;
    esac
    case $value in
      \"* | \'*)
        q=${value:0:1}
        value=${value:1}
        case $value in *"$q"*) value=${value%"$q"*} ;; *)
          warn "$file:$n: unterminated quote for $key; ignoring the line"
          continue
          ;;
        esac
        ;;
      *)
        value=${value%%[[:space:]]#*}
        value="${value%"${value##*[![:space:]]}"}"
        ;;
    esac
    case " $NEAR_ENV_KEYS " in
      *" $key "*) ;;
      *)
        case $key in
          NEAR_ALLOW_MAINNET | NEAR_ALLOW_INSECURE_RPC) warn "$file:$n: $key is ignored in a file; set it in the environment" ;;
          NEAR_* | APPROVAL_* | SANDBOX_*) warn "$file:$n: unknown setting $key (ignored)" ;;
        esac
        continue
        ;;
    esac
    if [ -n "${!key+x}" ]; then continue; fi
    printf -v "$key" '%s' "$value"
    if [ "$key" = NEAR_PRIVATE_KEY ] && [ -n "$value" ]; then NEAR_PRIVATE_KEY_FROM_FILE=1; fi
  done <"$file"
}

ACCOUNT_ID_RE='^(([a-z0-9]+[-_])*[a-z0-9]+\.)*([a-z0-9]+[-_])*[a-z0-9]+$'
valid_account_id() {
  local id=$1
  [ "${#id}" -ge 2 ] && [ "${#id}" -le 64 ] && [[ $id =~ $ACCOUNT_ID_RE ]]
}
require_account_id() {
  valid_account_id "$2" || die "$1 is not a valid NEAR account id: '$2'"
}
abs_path() {
  case $1 in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$REPO_ROOT/$1" ;; esac
}
# config_path NAME VALUE: a path setting from the environment or ENV_FILE ->
# absolute path. Expands a leading ~ (nothing else: no $VARS, no `cmd`);
# relative paths are relative to the repo root.
config_path() {
  local name=$1 v=$2
  case $v in *'$'* | *'`'*) die "$name='$v': no variable or command expansion is performed in settings (use an absolute path or ~/...)." ;; esac
  # shellcheck disable=SC2088 # matching a literal ~ is the point
  case $v in
    '~') v=$HOME ;;
    '~/'*) v="${HOME:?HOME is not set}/${v#\~/}" ;;
    '~'*) die "$name='$v': only ~ and ~/ are expanded, not ~user." ;;
  esac
  abs_path "$v"
}
is_loopback_url() {
  local hostport=${1#*://}
  hostport=${hostport%%/*}
  case $hostport in
    127.0.0.1 | 127.0.0.1:* | localhost | localhost:* | '[::1]' | '[::1]:'*) return 0 ;;
  esac
  return 1
}

# Load ENV_FILE (default <repo>/.env) and apply defaults. Every script calls
# this first. Does not require a key; see near_require_signer.
near_load_config() {
  local default_env="$REPO_ROOT/.env"
  ENV_FILE=${ENV_FILE:-$default_env}
  if [ -f "$ENV_FILE" ]; then
    [ -r "$ENV_FILE" ] || die "cannot read $ENV_FILE"
    load_env_file "$ENV_FILE"
  elif [ "$ENV_FILE" != "$default_env" ]; then
    die "ENV_FILE=$ENV_FILE does not exist."
  fi

  NEAR_NETWORK=${NEAR_NETWORK:-testnet}
  local default_rpc default_explorer default_account
  case $NEAR_NETWORK in
    testnet)
      # rpc.testnet.near.org is deprecated and rate-limits after a few
      # dozen calls a minute, which a smoke test exceeds.
      default_rpc=https://test.rpc.fastnear.com
      default_explorer=https://testnet.nearblocks.io/txns/
      default_account=difflabai.testnet
      ;;
    mainnet)
      default_rpc=https://rpc.mainnet.near.org
      default_explorer=https://nearblocks.io/txns/
      default_account=""
      ;;
    sandbox)
      default_rpc=http://127.0.0.1:${SANDBOX_RPC_PORT:-3030}
      default_explorer=""
      default_account=test.near
      ;;
    *) die "NEAR_NETWORK must be testnet, mainnet or sandbox (got '$NEAR_NETWORK')." ;;
  esac
  NEAR_RPC_URL=${NEAR_RPC_URL:-$default_rpc}
  case $NEAR_RPC_URL in
    https://*) ;;
    http://*)
      if ! is_loopback_url "$NEAR_RPC_URL" && [ "${NEAR_ALLOW_INSECURE_RPC:-}" != 1 ]; then
        die "NEAR_RPC_URL=$NEAR_RPC_URL is plain http to a remote host; anyone on the path could feed the scripts false chain state." \
          "Use https://, or set NEAR_ALLOW_INSECURE_RPC=1 in the environment if you really mean it."
      fi
      ;;
    *) die "NEAR_RPC_URL must start with http:// or https:// (got '$NEAR_RPC_URL')." ;;
  esac
  case $NEAR_RPC_URL in *[[:space:]\"\\]*) die "NEAR_RPC_URL contains spaces, quotes or backslashes." ;; esac
  NEAR_EXPLORER_TX_URL=${NEAR_EXPLORER_TX_URL-$default_explorer}
  NEAR_ACCOUNT_ID=${NEAR_ACCOUNT_ID:-$default_account}
  [ -n "$NEAR_ACCOUNT_ID" ] || die "NEAR_ACCOUNT_ID is not set (no default on $NEAR_NETWORK)."
  require_account_id NEAR_ACCOUNT_ID "$NEAR_ACCOUNT_ID"
  APPROVAL_CONTRACT_ID=${APPROVAL_CONTRACT_ID:-approvals.$NEAR_ACCOUNT_ID}
  require_account_id APPROVAL_CONTRACT_ID "$APPROVAL_CONTRACT_ID"
  APPROVAL_OWNER_ID=${APPROVAL_OWNER_ID:-$NEAR_ACCOUNT_ID}
  require_account_id APPROVAL_OWNER_ID "$APPROVAL_OWNER_ID"
  NEAR_CREDENTIALS_DIR=$(config_path NEAR_CREDENTIALS_DIR "${NEAR_CREDENTIALS_DIR:-.near-credentials}")
  NEAR_DEPLOYMENTS_DIR=$(config_path NEAR_DEPLOYMENTS_DIR "${NEAR_DEPLOYMENTS_DIR:-scripts/near/deployments}")
  if [ -n "${APPROVAL_WASM:-}" ]; then APPROVAL_WASM=$(config_path APPROVAL_WASM "$APPROVAL_WASM"); fi
  case $NEAR_CREDENTIALS_DIR/ in
    "$REPO_ROOT"/*)
      if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1 &&
        ! git -C "$REPO_ROOT" check-ignore -q "$NEAR_CREDENTIALS_DIR/$NEAR_NETWORK/x.agent.json" 2>/dev/null; then
        warn "NEAR_CREDENTIALS_DIR=$NEAR_CREDENTIALS_DIR is inside the repo but not gitignored: key files there could be committed."
      fi
      ;;
  esac
  if [ "$NEAR_PRIVATE_KEY_FROM_FILE" = 1 ]; then
    local mode
    mode=$(nu file-mode "$ENV_FILE" 2>/dev/null || echo 0600)
    case $mode in *00) ;; *) warn "$ENV_FILE (mode $mode) holds NEAR_PRIVATE_KEY and is readable by others; run: chmod 600 '$ENV_FILE'" ;; esac
  fi

  if [ "$NEAR_NETWORK" = mainnet ] && [ "${NEAR_ALLOW_MAINNET:-}" != 1 ]; then
    die "NEAR_NETWORK=mainnet is refused unless NEAR_ALLOW_MAINNET=1 is set."
  fi
  local id
  for id in "$NEAR_ACCOUNT_ID" "$APPROVAL_CONTRACT_ID" "$APPROVAL_OWNER_ID"; do
    case "$NEAR_NETWORK:$id" in
      mainnet:*.testnet) die "Account $id looks like a testnet account but NEAR_NETWORK=mainnet." ;;
      testnet:*.near) die "Account $id looks like a mainnet account but NEAR_NETWORK=testnet." ;;
    esac
  done
  near_tmp_init
  near_check_chain
}

# near_check_chain: the node at NEAR_RPC_URL must serve the chain
# NEAR_NETWORK names (so a mainnet RPC under a testnet/sandbox label can't
# slip past the mainnet guard). Sets NEAR_CHAIN_ID.
near_check_chain() {
  [ -n "$NEAR_CHAIN_ID" ] && return 0
  local st
  st=$(nur status) || die "RPC $NEAR_RPC_URL is not responding (NEAR_NETWORK=$NEAR_NETWORK)."
  NEAR_CHAIN_ID=$(jget "$st" chain_id)
  case "$NEAR_NETWORK:$NEAR_CHAIN_ID" in
    mainnet:mainnet | testnet:testnet) ;;
    sandbox:mainnet | sandbox:testnet) die "NEAR_NETWORK=sandbox but $NEAR_RPC_URL serves chain '$NEAR_CHAIN_ID'." ;;
    sandbox:?*) ;;
    *) die "NEAR_NETWORK=$NEAR_NETWORK but $NEAR_RPC_URL serves chain '$NEAR_CHAIN_ID'." \
      "Fix NEAR_RPC_URL or NEAR_NETWORK in $ENV_FILE (mainnet also needs NEAR_ALLOW_MAINNET=1 in the environment)." ;;
  esac
}

# Print the effective configuration (never the key).
near_print_config() {
  log "network:   $NEAR_NETWORK ($NEAR_RPC_URL, chain_id $NEAR_CHAIN_ID)"
  log "account:   $NEAR_ACCOUNT_ID"
  log "contract:  $APPROVAL_CONTRACT_ID (owner $APPROVAL_OWNER_ID)"
  log "env file:  $ENV_FILE$([ -f "$ENV_FILE" ] || echo ' (not found)')"
}

# Sets NEAR_SIGNER_PUBLIC_KEY from NEAR_PRIVATE_KEY (if set). Returns 1 when
# no key is configured.
near_derive_signer() {
  NEAR_SIGNER_PUBLIC_KEY=""
  { xtrace_off; } 2>/dev/null
  local have=0
  [ -z "${NEAR_PRIVATE_KEY:-}" ] || have=1
  if [ "$have" = 1 ]; then
    NEAR_SIGNER_PUBLIC_KEY=$(printf '%s' "$NEAR_PRIVATE_KEY" | nu pubkey) || NEAR_SIGNER_PUBLIC_KEY=""
  fi
  xtrace_on
  [ "$have" = 1 ] || return 1
  [ -n "$NEAR_SIGNER_PUBLIC_KEY" ] || die "NEAR_PRIVATE_KEY is malformed (expected ed25519:<base58 of 64 bytes>)."
  if [ -n "${NEAR_PUBLIC_KEY:-}" ] && [ "$NEAR_PUBLIC_KEY" != "$NEAR_SIGNER_PUBLIC_KEY" ]; then
    die "NEAR_PUBLIC_KEY ($NEAR_PUBLIC_KEY) does not match the public key of NEAR_PRIVATE_KEY ($NEAR_SIGNER_PUBLIC_KEY)."
  fi
  return 0
}
near_require_signer() {
  near_derive_signer || die "NEAR_PRIVATE_KEY is not set." \
    "Put a full-access key of $NEAR_ACCOUNT_ID in $ENV_FILE (see .env.example):" \
    "  NEAR_PRIVATE_KEY=ed25519:..."
}

# ---------------------------------------------------------------- near-cli

# near-cli-rs runs hermetically: HOME/XDG_CONFIG_HOME point at a private
# temp dir holding a generated config with one network (NEAR_NETWORK ->
# NEAR_RPC_URL), so the user's own near-cli config and keychain are never
# read or written. Signing is always sign-with-access-key-file.
near_cli_init() {
  [ -n "${NEAR_CLI_HOME:-}" ] && return 0
  near_tmp_init
  # Resolve to an absolute path *before* HOME is overridden for near.
  NEAR_BIN=${NEAR_CLI_BIN:-}
  if [ -z "$NEAR_BIN" ]; then
    NEAR_BIN=$(command -v near 2>/dev/null || true)
    [ -n "$NEAR_BIN" ] || NEAR_BIN="${HOME:-/nonexistent}/.cargo/bin/near"
  fi
  [ -x "$NEAR_BIN" ] || die "near-cli-rs not found (looked for 'near' on PATH and in ~/.cargo/bin)." \
    "Install it (cargo install near-cli-rs) or set NEAR_CLI_BIN=/path/to/near."
  case $NEAR_BIN in /*) ;; *) NEAR_BIN="$(cd "$(dirname "$NEAR_BIN")" && pwd -P)/$(basename "$NEAR_BIN")" ;; esac
  local ver
  ver=$(env HOME="$NEAR_TMP" "$NEAR_BIN" --version </dev/null 2>/dev/null || true)
  case $ver in near-cli-rs*) NEAR_CLI_VERSION=${ver#near-cli-rs } ;; *) die "$NEAR_BIN is not near-cli-rs (--version: '$ver')." ;; esac

  NEAR_CLI_HOME="$NEAR_TMP/home"
  local rpc=$NEAR_RPC_URL explorer=${NEAR_EXPLORER_TX_URL:-http://127.0.0.1/no-explorer/} extra=""
  case $rpc in */) ;; *) rpc="$rpc/" ;; esac
  case $NEAR_NETWORK in
    testnet)
      # near-cli-rs's default faucet host (helper.nearprotocol.com) fails
      # TLS as of 2026-10; helper.testnet.near.org serves the same API.
      local faucet=${NEAR_FAUCET_URL:-https://helper.testnet.near.org/account}
      case $faucet in
        https://*[!A-Za-z0-9._~:/%-]*) die "NEAR_FAUCET_URL has unexpected characters: $faucet" ;;
        https://?*) ;;
        *) die "NEAR_FAUCET_URL must be an https:// URL (got '$faucet')." ;;
      esac
      extra="linkdrop_account_id = \"testnet\""$'\n'"faucet_url = \"$faucet\""
      ;;
    mainnet) extra='linkdrop_account_id = "near"' ;;
  esac
  # version "2" is the schema near-cli-rs 0.15 writes; newer releases migrate it.
  local cfg
  cfg=$(
    cat <<EOF
version = "2"
credentials_home_dir = "$NEAR_CLI_HOME/.near-credentials"

[network_connection.$NEAR_NETWORK]
network_name = "$NEAR_NETWORK"
rpc_url = "$rpc"
wallet_url = "https://example.invalid/"
explorer_transaction_url = "$explorer"
$extra
EOF
  )
  local d
  for d in "$NEAR_CLI_HOME/Library/Application Support/near-cli" "$NEAR_CLI_HOME/.config/near-cli"; do
    mkdir -p "$d"
    printf '%s\n' "$cfg" >"$d/config.toml"
  done
}

# near_run ARGS...: run near-cli hermetically, stdin from /dev/null so it can
# never prompt. Leaves filtered stdout/stderr in $NEAR_TMP/out and
# $NEAR_TMP/err (ANSI, update nags and anything shaped like a secret key
# removed). Returns near's exit code.
near_run() {
  near_cli_init
  local rc=0
  env -u NEAR_PRIVATE_KEY -u APPROVAL_AGENT_PRIVATE_KEY -u APPROVAL_APPROVER_PRIVATE_KEY HOME="$NEAR_CLI_HOME" XDG_CONFIG_HOME="$NEAR_CLI_HOME/.config" NO_COLOR=1 \
    "$NEAR_BIN" "$@" </dev/null >"$NEAR_TMP/out.raw" 2>"$NEAR_TMP/err.raw" || rc=$?
  nu filter-cli <"$NEAR_TMP/err.raw" >"$NEAR_TMP/err" || cp /dev/null "$NEAR_TMP/err"
  nu filter-cli <"$NEAR_TMP/out.raw" >"$NEAR_TMP/out" || cp /dev/null "$NEAR_TMP/out"
  rm -f "$NEAR_TMP/out.raw" "$NEAR_TMP/err.raw"
  return "$rc"
}

# near_tx_link HASH: explorer URL (empty on sandbox).
near_tx_link() {
  [ -z "$NEAR_EXPLORER_TX_URL" ] || printf '%s%s\n' "$NEAR_EXPLORER_TX_URL" "$1"
}

# near_tx LABEL KEYFILE NEAR-ARGS...: send a transaction signed with the
# access-key file. Sets NEAR_TX_HASH and NEAR_TX_RESULT (the method's return
# value from stdout). Checks near's exit code first: a failed transaction
# also prints a Transaction ID. Returns 1 on failure after printing near's
# error output.
NEAR_TX_HASH=""
NEAR_TX_RESULT=""
NEAR_TX_LOG=""
near_tx() {
  local label=$1 keyfile=$2 rc=0 attempt=1
  shift 2
  info "$label"
  while :; do
    rc=0
    near_run "$@" network-config "$NEAR_NETWORK" sign-with-access-key-file "$keyfile" send || rc=$?
    NEAR_TX_HASH=$(awk '/Transaction ID: / { print $NF; exit }' "$NEAR_TMP/err")
    # A rate-limited RPC refuses the request outright, before anything is
    # broadcast (no Transaction ID), so a retry can't send the tx twice.
    if [ "$rc" -ne 0 ] && [ -z "$NEAR_TX_HASH" ] && [ "$attempt" -le 3 ] &&
      grep -qiE 'rate limit|too many requests' "$NEAR_TMP/err"; then
      warn "$NEAR_RPC_URL is rate-limiting; retrying in $((attempt * 10)) s ($attempt/3)"
      sleep $((attempt * 10))
      attempt=$((attempt + 1))
      continue
    fi
    break
  done
  NEAR_TX_RESULT=$(cat "$NEAR_TMP/out")
  if [ -n "$NEAR_TX_HASH" ]; then
    log "    tx: $NEAR_TX_HASH"
    [ -z "$NEAR_EXPLORER_TX_URL" ] || log "    $(near_tx_link "$NEAR_TX_HASH")"
    NEAR_TX_LOG="$NEAR_TX_LOG$label: $NEAR_TX_HASH"$'\n'
  fi
  if [ "$rc" -ne 0 ]; then
    printf '%serror:%s %s failed (near exit %s). near-cli output:\n' "$C_RED" "$C_OFF" "$label" "$rc" >&2
    nu cli-error <"$NEAR_TMP/err" | sed 's/^/    | /' >&2
    near_balance_hint "$NEAR_TMP/err"
    return 1
  fi
  return 0
}

# near_balance_hint ERRFILE: when near-cli failed for lack of balance, say
# which transfer.sh command fixes it.
near_balance_hint() {
  local h acct amt
  h=$(nu balance-error <"$1" 2>/dev/null) || return 0
  [ -n "$h" ] || return 0
  acct=$(jget "$h" account_id)
  amt=$(jget "$h" top_up_near)
  [ -n "$acct" ] && [ "$acct" != null ] || return 0
  log "    $acct cannot pay for this (needs $(jget "$h" required_near) NEAR more for $(jget "$h" kind))."
  if [ "$acct" = "$NEAR_ACCOUNT_ID" ]; then
    near_fund_hint "$acct" | sed 's/^/    /' >&2
  else
    log "    Top it up:  scripts/near/transfer.sh $acct $amt --yes"
  fi
}

# near_signer_keyfile ACCOUNT: path of a 0600 access-key file for ACCOUNT
# holding NEAR_PRIVATE_KEY (the key is passed to python on stdin).
near_signer_keyfile() {
  local acct=$1 f="$NEAR_TMP/key.$1.json" rc=0
  if [ ! -f "$f" ]; then
    { xtrace_off; } 2>/dev/null
    printf '%s' "$NEAR_PRIVATE_KEY" | nu write-keyfile --account "$acct" --out "$f" >/dev/null || rc=1
    xtrace_on
    [ "$rc" = 0 ] || die "could not write a key file for $acct"
  fi
  printf '%s\n' "$f"
}

# near_call SIGNER KEYFILE METHOD JSON_ARGS [LABEL]: change call on the contract.
near_call() {
  local signer=$1 keyfile=$2 method=$3 args=$4 label=${5:-}
  near_tx "${label:-$signer -> $APPROVAL_CONTRACT_ID.$method}" "$keyfile" \
    contract call-function as-transaction "$APPROVAL_CONTRACT_ID" "$method" \
    json-args "$args" prepaid-gas "$NEAR_CALL_GAS" attached-deposit '0 NEAR' \
    sign-as "$signer"
}

# ---------------------------------------------------------- chain queries

# near_account ACCOUNT: JSON {exists, amount, locked, storage_usage, code_hash, has_code}.
near_account() { nur account "$1" || die "could not query account $1 via $NEAR_RPC_URL"; }

NEAR_STORAGE_PRICE=""
near_storage_price() {
  if [ -z "$NEAR_STORAGE_PRICE" ]; then
    NEAR_STORAGE_PRICE=$(nur storage-price) || die "could not query the protocol config via $NEAR_RPC_URL"
  fi
  printf '%s\n' "$NEAR_STORAGE_PRICE"
}

# near_gas_price: current gas price (yoctoNEAR per gas), cached.
NEAR_GAS_PRICE=""
near_gas_price() {
  if [ -z "$NEAR_GAS_PRICE" ]; then
    NEAR_GAS_PRICE=$(nur gas-price) || die "could not query the gas price via $NEAR_RPC_URL"
    require_uint gas_price "$NEAR_GAS_PRICE"
  fi
  printf '%s\n' "$NEAR_GAS_PRICE"
}
# near_gas_purchase_yocto "N Tgas": what attaching N Tgas to a function call
# holds of the signer's balance until the call finishes (see
# MIN_GAS_PURCHASE_PRICE; the unused part is refunded).
near_gas_purchase_yocto() {
  local tgas=${1%% *}
  require_uint "gas amount (Tgas)" "$tgas"
  int_calc "$tgas * 1000000000000 * max($(near_gas_price), $MIN_GAS_PURCHASE_PRICE)"
}

# near_storage_stake USAGE: yoctoNEAR locked for USAGE bytes of storage (0
# for a zero-balance account, NEP-448).
near_storage_stake() {
  require_uint storage_usage "$1"
  int_calc "$1 * $(near_storage_price) * ($1 > $ZBA_STORAGE_LIMIT)"
}

# near_available ACCOUNT_JSON: yoctoNEAR not locked for storage staking.
near_available() {
  local amount usage locked
  amount=$(jget "$1" amount)
  usage=$(jget "$1" storage_usage)
  locked=$(jget "$1" locked)
  require_uint amount "$amount"
  case $locked in null | '') locked=0 ;; esac
  require_uint locked "$locked"
  # A validator's locked stake counts toward its storage requirement.
  int_calc "max(0, $amount - max(0, $(near_storage_stake "$usage") - $locked))"
}

near_fund_hint() {
  case $NEAR_NETWORK in
    testnet) printf '%s\n' "Fund $1 on testnet: send NEAR from any funded testnet account, e.g." \
      "  near tokens <funded.testnet> send-near $1 '5 NEAR' network-config testnet sign-with-keychain send" \
      "or use a testnet faucet (https://docs.near.org/getting-started/faucet or https://near-faucet.io/). Then re-run." ;;
    sandbox)
      if [ "$1" = test.near ]; then
        printf '%s\n' "test.near is the sandbox's genesis account; use a smaller amount."
      else
        printf '%s\n' "Top it up from the genesis account: NEAR_ACCOUNT_ID=test.near scripts/near/transfer.sh $1 <amount> --yes"
      fi
      ;;
    *) printf '%s\n' "Transfer NEAR to $1, then re-run." ;;
  esac
}

# near_check_balance ACCOUNT ACCOUNT_JSON NEEDED_YOCTO WHAT [BASIS]: is the
# account's balance enough? BASIS "available" (default: amount minus storage
# staking) or "amount" (total balance, for a contract account whose own new
# storage is part of NEEDED). Prints needed vs available and how to fund it,
# and returns 1, when it is not.
near_check_balance() {
  local acct=$1 json=$2 need=$3 what=$4 basis=${5:-available} avail
  if [ "$basis" = amount ]; then avail=$(jget "$json" amount); else avail=$(near_available "$json"); fi
  [ "$(int_calc "$avail >= $need")" = 1 ] && return 0
  printf '%serror:%s %s has insufficient balance for %s.\n' "$C_RED" "$C_OFF" "$acct" "$what" >&2
  log "       needed:    $(fmt_near "$need" --round up) ($need yoctoNEAR)"
  if [ "$basis" = amount ]; then
    log "       available: $(fmt_near "$avail") ($avail yoctoNEAR, total balance)"
  else
    log "       available: $(fmt_near "$avail") ($avail yoctoNEAR, after storage staking)"
  fi
  log "       missing:   $(fmt_near "$(int_calc "$need - $avail")" --round up)"
  near_fund_hint "$acct" | sed 's/^/       /' >&2
  return 1
}
near_require_balance() { near_check_balance "$@" || exit 1; }

# near_key_permission ACCOUNT PUBLIC_KEY: JSON {exists, permission, ...}.
near_key_permission() { nur access-key "$1" "$2" || die "could not query access key of $1"; }

# near_require_full_access ACCOUNT: the .env key must be a FullAccess key of ACCOUNT.
near_require_full_access() {
  local acct=$1 j
  j=$(near_key_permission "$acct" "$NEAR_SIGNER_PUBLIC_KEY")
  if [ "$(jget "$j" exists)" != true ]; then
    die "The key in NEAR_PRIVATE_KEY ($NEAR_SIGNER_PUBLIC_KEY) is not an access key of $acct on $NEAR_NETWORK." \
      "Check NEAR_PRIVATE_KEY / NEAR_ACCOUNT_ID in $ENV_FILE, or list the account's keys:" \
      "  near account list-keys $acct network-config $NEAR_NETWORK now"
  fi
  [ "$(jget "$j" permission)" = FullAccess ] ||
    die "The key in NEAR_PRIVATE_KEY ($NEAR_SIGNER_PUBLIC_KEY) is a function-call key on $acct; a full-access key is needed."
}

# near_require_parent: parent account exists and the .env key controls it.
near_require_parent() {
  near_require_signer
  local j
  j=$(near_account "$NEAR_ACCOUNT_ID")
  [ "$(jget "$j" exists)" = true ] || die "$NEAR_ACCOUNT_ID does not exist on $NEAR_NETWORK."
  near_require_full_access "$NEAR_ACCOUNT_ID"
  NEAR_PARENT_JSON=$j
}

# near_require_contract: the contract account exists and has code.
near_require_contract() {
  local j
  j=$(near_account "$APPROVAL_CONTRACT_ID")
  [ "$(jget "$j" exists)" = true ] ||
    die "Contract account $APPROVAL_CONTRACT_ID does not exist on $NEAR_NETWORK. Deploy it first: scripts/near/deploy.sh"
  [ "$(jget "$j" has_code)" = true ] ||
    die "$APPROVAL_CONTRACT_ID has no contract code. Deploy it first: scripts/near/deploy.sh"
}

# near_view METHOD [JSON_ARGS] [near_util view flags...]
near_view() {
  local method=$1 args=${2:-'{}'}
  shift
  [ $# -gt 0 ] && shift
  nur view "$APPROVAL_CONTRACT_ID" "$method" "$args" "$@"
}

# near_require_owner: owner calls are signed by NEAR_ACCOUNT_ID, which must
# be APPROVAL_OWNER_ID and the contract's actual owner.
near_require_owner() {
  if [ "$APPROVAL_OWNER_ID" != "$NEAR_ACCOUNT_ID" ]; then
    die "Owner calls must be signed by the owner $APPROVAL_OWNER_ID, but these scripts sign as NEAR_ACCOUNT_ID=$NEAR_ACCOUNT_ID." \
      "Run with NEAR_ACCOUNT_ID=$APPROVAL_OWNER_ID and NEAR_PRIVATE_KEY set to a full-access key of $APPROVAL_OWNER_ID," \
      "or, if the owner is a multisig/DAO, submit the call through it."
  fi
  near_require_parent
  near_require_contract
  local owner
  owner=$(near_view get_owner) || die "could not read get_owner from $APPROVAL_CONTRACT_ID"
  [ "$owner" = "$APPROVAL_OWNER_ID" ] ||
    die "$APPROVAL_CONTRACT_ID is owned by $owner, not APPROVAL_OWNER_ID=$APPROVAL_OWNER_ID." \
      "Set APPROVAL_OWNER_ID/NEAR_ACCOUNT_ID/NEAR_PRIVATE_KEY for $owner."
}

# ------------------------------------------------------------- principals

# principal_account NAME|ACCOUNT -> full account id (NAME.<NEAR_ACCOUNT_ID>).
principal_account() {
  local a=$1
  case $a in *.*) ;; *) a="$a.$NEAR_ACCOUNT_ID" ;; esac
  valid_account_id "$a" || die "not a valid account id: '$a'"
  printf '%s\n' "$a"
}
principal_keyfile() { printf '%s/%s/%s.%s.json\n' "$NEAR_CREDENTIALS_DIR" "$NEAR_NETWORK" "$1" "$2"; }
role_methods() {
  case $1 in
    agent) echo request_action ;;
    approver) echo approve,reject ;;
    *) die "role must be agent or approver (got '$1')" ;;
  esac
}
# methods_norm LIST: comma-separated method names -> sorted, de-duplicated.
methods_norm() { printf '%s\n' "$1" | tr ',' '\n' | sed '/^$/d' | LC_ALL=C sort -u | paste -sd, -; }
# methods_subset ROLE LIST: is LIST a non-empty subset of ROLE's methods?
# (An empty method list on a NEAR function-call key allows every method.)
methods_subset() {
  local all list m
  all=$(role_methods "$1")
  list=$(methods_norm "$2")
  [ -n "$list" ] || return 1
  for m in $(printf '%s' "$list" | tr ',' ' '); do
    case ",$all," in *",$m,"*) ;; *) return 1 ;; esac
  done
  return 0
}
# role_scope ROLE [LIST]: the validated method list for ROLE's function-call
# key: all of the role's methods by default, or a subset of them (e.g. an
# approver key that may approve but not reject).
role_scope() {
  local list
  list=$(methods_norm "${2:-$(role_methods "$1")}")
  methods_subset "$1" "$list" || die "methods '${2:-}' are not a non-empty subset of the $1 methods ($(role_methods "$1"))"
  printf '%s\n' "$list"
}
# principal_env_prefix ROLE: prefix of the principal's settings in ENV_FILE
# (written by principal-env.sh).
principal_env_prefix() {
  case $1 in
    agent) echo APPROVAL_AGENT ;;
    approver) echo APPROVAL_APPROVER ;;
    *) die "role must be agent or approver (got '$1')" ;;
  esac
}
# principal_env_keyfile ACCOUNT ROLE: when ENV_FILE holds this principal's
# key (<PREFIX>_ACCOUNT_ID = ACCOUNT and <PREFIX>_PRIVATE_KEY), write it to a
# 0600 temp key file and print its path; return 1 otherwise.
principal_env_keyfile() {
  local p acct_var key_var pub_var f pk="" rc=0
  p=$(principal_env_prefix "$2")
  acct_var=${p}_ACCOUNT_ID key_var=${p}_PRIVATE_KEY pub_var=${p}_PUBLIC_KEY
  [ "${!acct_var:-}" = "$1" ] || return 1
  f="$NEAR_TMP/key.env.$2.json"
  { xtrace_off; } 2>/dev/null
  if [ -z "${!key_var:-}" ]; then
    rc=2
  else
    pk=$(printf '%s' "${!key_var}" | nu write-keyfile --account "$1" --out "$f") || rc=1
  fi
  xtrace_on
  [ "$rc" != 2 ] || return 1
  [ "$rc" = 0 ] || die "$key_var in $ENV_FILE is not a valid ed25519 secret key"
  if [ -n "${!pub_var:-}" ] && [ "${!pub_var}" != "$pk" ]; then
    die "$pub_var (${!pub_var}) does not match the public key of $key_var ($pk) in $ENV_FILE"
  fi
  printf '%s\n' "$f"
}
# require_principal_keyfile ACCOUNT ROLE [KEY_FILE] -> path of a near-cli
# access-key file for ACCOUNT (validated, no secret printed): KEY_FILE if
# given (a key held outside this repo, e.g. by an independent approver),
# else the stored <NEAR_CREDENTIALS_DIR>/<network>/<account>.<role>.json.
require_principal_keyfile() {
  local f=${3:-} info acct mode
  if [ -n "$f" ]; then
    [ -f "$f" ] || die "key file not found: $f"
    case $f in /*) ;; *) f="$PWD/$f" ;; esac
  else
    f=$(principal_keyfile "$1" "$2")
    if [ ! -f "$f" ]; then
      f=$(principal_env_keyfile "$1" "$2") ||
        die "No $2 key stored for $1 ($(principal_keyfile "$1" "$2"))." "Create it with: scripts/near/new-principal.sh $1 $2" \
          "or set $(principal_env_prefix "$2")_ACCOUNT_ID=$1 and $(principal_env_prefix "$2")_PRIVATE_KEY in $ENV_FILE (principal-env.sh)," \
          "or pass --key-file PATH (a near-cli access-key file {account_id, public_key, private_key})."
    fi
  fi
  info=$(nu keyfile-info "$f") || die "Key file $f is invalid."
  acct=$(jget "$info" account_id)
  [ "$acct" = null ] || [ "$acct" = "$1" ] || die "Key file $f is for $acct, not $1."
  mode=$(jget "$info" mode)
  case $mode in *00) ;; *) warn "$f has mode $mode; it holds a private key, run: chmod 600 '$f'" ;; esac
  printf '%s\n' "$f"
}

# near_require_owner_call_balance: the owner (NEAR_ACCOUNT_ID) can pay for
# one owner call, including the gas bought up front.
near_require_owner_call_balance() {
  near_require_balance "$NEAR_ACCOUNT_ID" "$(near_account "$NEAR_ACCOUNT_ID")" \
    "$(int_calc "$(near_gas_purchase_yocto "$NEAR_CALL_GAS") + $TX_FEE_MARGIN_YOCTO")" "${1:-the owner call}"
}

# register_principal ROLE ACCOUNT PUBLIC_KEY: owner-signed add_agent /
# add_approver, skipped when the key is already registered the same way.
# Caller must have run near_require_owner.
register_principal() {
  local role=$1 acct=$2 pk=$3 pkargs cur args
  pkargs=$(nu json-build public_key="$pk") || die "could not encode the public key"
  cur=$(near_view get_principal "$pkargs") || die "get_principal failed"
  if [ "$cur" != null ]; then
    if [ "$(jget "$cur" account_id)" = "$acct" ] && [ "$(jget "$cur" role)" = "$role" ]; then
      ok "$pk is already registered as $role of $acct (registration $(jget "$cur" registration_id))"
      PRINCIPAL_JSON=$cur
      return 0
    fi
    die "$pk is already registered as $(jget "$cur" role) of $(jget "$cur" account_id)." \
      "Revoke it first (scripts/near/revoke-key.sh $pk) or use another key."
  fi
  args=$(nu json-build account_id="$acct" public_key="$pk") || die "could not encode the arguments"
  near_require_owner_call_balance "add_$role"
  near_call "$NEAR_ACCOUNT_ID" "$(near_signer_keyfile "$NEAR_ACCOUNT_ID")" "add_$role" \
    "$args" "Register $role key of $acct (add_$role)" ||
    die "add_$role failed"
  PRINCIPAL_JSON=$(near_view get_principal "$pkargs" --wait-nonnull --timeout 60) ||
    die "the registration did not become visible at final"
  ok "registered $pk as $role of $acct (registration $(jget "$PRINCIPAL_JSON" registration_id))"
}

# check_principal_access_key ACCOUNT ROLE PUBLIC_KEY [METHODS]: is the key a
# function-call key of ACCOUNT scoped to the contract and to METHODS (if
# given), or else to a non-empty subset of the role's methods? Returns 0 if
# so, 1 if the key is not on the account, 2 if it is but differently scoped
# (after a warning). Sets PRINCIPAL_KEY_JSON and PRINCIPAL_KEY_METHODS.
check_principal_access_key() {
  local acct=$1 role=$2 pk=$3 want=${4:-} k methods expected
  k=$(near_key_permission "$acct" "$pk")
  PRINCIPAL_KEY_JSON=$k
  PRINCIPAL_KEY_METHODS=""
  if [ "$(jget "$k" exists)" != true ]; then
    return 1
  fi
  if [ "$(jget "$k" permission)" = FullAccess ]; then
    warn "$pk is a FULL-ACCESS key of $acct. Register only function-call keys scoped to $APPROVAL_CONTRACT_ID" \
      "(see contracts/approval/README.md, Authorization model); scripts/near/new-principal.sh sets that up."
    return 2
  fi
  methods=$(methods_norm "$(printf '%s' "$k" | nu json-get method_names --join ,)")
  PRINCIPAL_KEY_METHODS=$methods
  if [ -n "$want" ]; then
    expected="[$(methods_norm "$want")]"
  else
    expected="a non-empty subset of [$(role_methods "$role")]"
  fi
  if [ "$(jget "$k" receiver_id)" != "$APPROVAL_CONTRACT_ID" ] ||
    { [ -n "$want" ] && [ "$methods" != "$(methods_norm "$want")" ]; } ||
    { [ -z "$want" ] && ! methods_subset "$role" "$methods"; }; then
    warn "$pk on $acct is a function-call key for $(jget "$k" receiver_id) [${methods:-all methods}];" \
      "expected receiver $APPROVAL_CONTRACT_ID with methods $expected."
    return 2
  fi
  return 0
}

# require_key_can_call ACCOUNT KEYFILE METHOD: fail before sending when the
# key in KEYFILE is not an access key of ACCOUNT allowed to call METHOD on
# the contract (NEAR would reject the transaction).
require_key_can_call() {
  local acct=$1 info pk k methods
  info=$(nu keyfile-info "$2") || die "invalid key file $2"
  pk=$(jget "$info" public_key)
  k=$(near_key_permission "$acct" "$pk")
  [ "$(jget "$k" exists)" = true ] || die "$pk (from $2) is not an access key of $acct."
  [ "$(jget "$k" permission)" != FullAccess ] || return 0
  [ "$(jget "$k" receiver_id)" = "$APPROVAL_CONTRACT_ID" ] ||
    die "$pk of $acct is a function-call key for $(jget "$k" receiver_id), not $APPROVAL_CONTRACT_ID."
  methods=$(methods_norm "$(printf '%s' "$k" | nu json-get method_names --join ,)")
  case ",$methods," in
    ,, | *",$3,"*) return 0 ;;
  esac
  die "$pk of $acct may not call $3: it is scoped to [$methods] on $APPROVAL_CONTRACT_ID." \
    "Use a key whose scope includes $3."
}

# action_to_file ACTION_ARG ACTION_FILE: the action text, verbatim, in a
# private temp file (from --action-file PATH, '-' for stdin, else from the
# argument); prints the temp file's path. A file's trailing newline is part
# of the action. Checks the contract's 1..2048-byte limit.
action_to_file() {
  local arg=$1 src=$2 f n
  NEAR_ACTION_N=$((${NEAR_ACTION_N:-0} + 1))
  f="$NEAR_TMP/action.$NEAR_ACTION_N"
  if [ -n "$src" ]; then
    if [ "$src" = - ]; then
      cat >"$f" || die "could not read the action from stdin"
    else
      [ -f "$src" ] || die "action file not found: $src"
      cat "$src" >"$f" || die "could not read $src"
    fi
  else
    printf '%s' "$arg" >"$f"
  fi
  n=$(wc -c <"$f" | tr -d ' ')
  [ "$n" -ge 1 ] && [ "$n" -le 2048 ] || die "action must be 1 to 2048 bytes (got $n)"
  printf '%s\n' "$f"
}

# ------------------------------------------------------------------- misc

# confirm QUESTION: yes if ASSUME_YES=1, else ask on a terminal; refuse otherwise.
confirm() {
  [ "${ASSUME_YES:-0}" = 1 ] && return 0
  if [ ! -t 0 ]; then die "$1" "Refusing without --yes (stdin is not a terminal)."; fi
  local reply
  printf '%s [y/N] ' "$1" >&2
  read -r reply || reply=""
  case $reply in y | Y | yes | YES) return 0 ;; *) die "aborted." ;; esac
}

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
