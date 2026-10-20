#!/usr/bin/env bash
# Usage: scripts/near/sandbox.sh start|stop|status|env|reset
#
# Run a local near-sandbox node, so every script here can be exercised
# end to end without touching testnet. Uses the near-sandbox version the
# contract's own sandbox tests use (near-workspaces 0.23.0 -> near-sandbox
# crate 0.3.16 -> near-sandbox 2.13.4), checked against a sha256 recorded
# here (trust on first use: upstream publishes none, see pinned_sha256).
#
#   start   download the binary (cached in $SANDBOX_DIR/bin), init a node home
#           on first start, run the node in the background and write
#           $SANDBOX_DIR/.env (NEAR_NETWORK=sandbox, NEAR_ACCOUNT_ID=test.near
#           with the sandbox validator key, credentials and deployment records
#           under $SANDBOX_DIR). Idempotent.
#   stop    stop the node (its state is kept; `start` resumes it)
#   status  is it running, its RPC URL and latest block
#   env     print `export ENV_FILE=...` for: eval "$(scripts/near/sandbox.sh env)"
#   reset   stop the node and delete its chain state, .env, credentials and
#           deployment records (keeps the downloaded binary)
#
# Environment:
#   SANDBOX_DIR            state directory (default scripts/near/.sandbox)
#   SANDBOX_RPC_PORT       RPC port on 127.0.0.1 (default: the port this
#                          SANDBOX_DIR was last started on, else 3030); the
#                          p2p port is SANDBOX_RPC_PORT+21500, so sandboxes
#                          with different RPC ports and dirs can run side by
#                          side
#   SANDBOX_VERSION        near-sandbox version (default 2.13.4)
#   SANDBOX_ARTIFACT_URL   download this tarball instead (requires SANDBOX_SHA256)
#   NEAR_SANDBOX_BIN_PATH  use this near-sandbox binary instead of downloading
#   NEAR_SANDBOX_LOG       RUST_LOG filter for the node (default warn,chain=error)
#
# Then, for example:
#   ENV_FILE=scripts/near/.sandbox/.env scripts/near/deploy.sh
# (the contract id in the sandbox is approvals.test.near)
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"

case "${1:-}" in
  -h | --help | help)
    print_usage
    exit 0
    ;;
  start | stop | status | env | reset) CMD=$1 ;;
  '') usage_error "missing command (start|stop|status|env|reset)" ;;
  *) usage_error "unknown command '$1'" ;;
esac
shift
[ $# -eq 0 ] || usage_error "unexpected argument '$1'"

SANDBOX_VERSION=${SANDBOX_VERSION:-2.13.4}
SANDBOX_DIR=${SANDBOX_DIR:-$NEAR_SCRIPTS_DIR/.sandbox}
case $SANDBOX_DIR in /*) ;; *) SANDBOX_DIR="$PWD/$SANDBOX_DIR" ;; esac
PORT_FILE="$SANDBOX_DIR/rpc_port"
RECORDED_PORT=""
if [ -f "$PORT_FILE" ]; then
  RECORDED_PORT=$(cat "$PORT_FILE" 2>/dev/null || true)
  case $RECORDED_PORT in '' | *[!0-9]*) RECORDED_PORT="" ;; esac
fi
SANDBOX_RPC_PORT=${SANDBOX_RPC_PORT:-${RECORDED_PORT:-3030}}
case $SANDBOX_RPC_PORT in '' | *[!0-9]*) die "SANDBOX_RPC_PORT must be a number" ;; esac
[ "$SANDBOX_RPC_PORT" -ge 1024 ] && [ "$SANDBOX_RPC_PORT" -le 44000 ] ||
  die "SANDBOX_RPC_PORT must be between 1024 and 44000 (p2p uses RPC+21500)"
NET_PORT=$((SANDBOX_RPC_PORT + 21500))
RPC_URL="http://127.0.0.1:$SANDBOX_RPC_PORT"
HOME_DIR="$SANDBOX_DIR/home"
PID_FILE="$SANDBOX_DIR/sandbox.pid"
LOG_FILE="$SANDBOX_DIR/sandbox.log"
ENV_OUT="$SANDBOX_DIR/.env"

# sha256 of near-sandbox.tar.gz for 2.13.4, per platform. Upstream publishes
# no checksums (the near-sandbox crate downloads the tarball unverified);
# these were recorded from the S3 tarballs on 2026-10-19 (trust on first
# use). They pin the bytes, not their provenance. To move SANDBOX_VERSION,
# download the new tarball, verify it as well as you can, and add its hash
# here or pass SANDBOX_SHA256.
pinned_sha256() {
  case "$SANDBOX_VERSION:$1" in
    2.13.4:Darwin-arm64) echo 158cedb02e5a83d51b47c16e13cd04a84abf493f1f38688ee257cb0263450631 ;;
    2.13.4:Linux-x86_64) echo 5690a4635172263cf026683f75965cac09dd916912584f12709974fed620163f ;;
    2.13.4:Linux-aarch64) echo edd77d6d28b960852243fc6f45656c97a7976fc2b3cfe53cda89324a6804bd30 ;;
    *) echo "" ;;
  esac
}

platform() {
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64) echo Darwin-arm64 ;;
    Linux:x86_64) echo Linux-x86_64 ;;
    Linux:aarch64 | Linux:arm64) echo Linux-aarch64 ;;
    *) die "near-sandbox has no build for $(uname -s) $(uname -m) (Darwin-x86_64 is unsupported upstream)." ;;
  esac
}

ensure_binary() {
  if [ -n "${NEAR_SANDBOX_BIN_PATH:-}" ]; then
    [ -x "$NEAR_SANDBOX_BIN_PATH" ] || die "NEAR_SANDBOX_BIN_PATH=$NEAR_SANDBOX_BIN_PATH is not executable"
    SANDBOX_BIN=$NEAR_SANDBOX_BIN_PATH
    return
  fi
  local plat url sha
  plat=$(platform)
  SANDBOX_BIN="$SANDBOX_DIR/bin/near-sandbox-$SANDBOX_VERSION-$plat/near-sandbox"
  [ -x "$SANDBOX_BIN" ] && return
  if [ -n "${SANDBOX_ARTIFACT_URL:-}" ]; then
    url=$SANDBOX_ARTIFACT_URL
    sha=${SANDBOX_SHA256:-}
    [ -n "$sha" ] || die "SANDBOX_ARTIFACT_URL needs SANDBOX_SHA256 (the tarball's sha256)."
  else
    url="https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/$plat/$SANDBOX_VERSION/near-sandbox.tar.gz"
    sha=${SANDBOX_SHA256:-$(pinned_sha256 "$plat")}
    [ -n "$sha" ] || die "No pinned sha256 for near-sandbox $SANDBOX_VERSION on $plat; set SANDBOX_SHA256."
  fi
  local dl="$NEAR_TMP/sandbox-download" got
  mkdir -p "$dl"
  info "Downloading near-sandbox $SANDBOX_VERSION ($plat, ~30 MB)"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dl/near-sandbox.tar.gz" "$url" ||
    die "download failed: $url"
  got=$(sha256_hex "$dl/near-sandbox.tar.gz")
  [ "$got" = "$sha" ] || die "sha256 mismatch for $url" "expected $sha" "got      $got"
  mkdir -p "$dl/x"
  tar -xzf "$dl/near-sandbox.tar.gz" -C "$dl/x"
  local f
  f=$(find "$dl/x" -type f -name near-sandbox | head -n 1)
  [ -n "$f" ] || die "near-sandbox binary not found in the tarball"
  mkdir -p "$(dirname "$SANDBOX_BIN")"
  install -m 0755 "$f" "$SANDBOX_BIN"
  ok "installed $SANDBOX_BIN (sha256 of tarball verified)"
}

running_pid() {
  local pid
  [ -f "$PID_FILE" ] || return 1
  pid=$(cat "$PID_FILE" 2>/dev/null || true)
  case $pid in '' | *[!0-9]*) return 1 ;; esac
  kill -0 "$pid" 2>/dev/null || return 1
  case "$(ps -p "$pid" -o command= 2>/dev/null || true)" in
    *near-sandbox*) printf '%s\n' "$pid" ;;
    *) return 1 ;;
  esac
}

rpc_up() { nu --rpc "$RPC_URL" status >/dev/null 2>&1; }

write_env() {
  local acct
  acct=$(jget "$(cat "$HOME_DIR/validator_key.json")" account_id)
  [ -n "$acct" ] && [ "$acct" != null ] || acct=test.near
  # validator_key.json names the secret `secret_key`; near-cli access-key
  # files need `private_key`. near_util.py translates and writes 0600.
  nu sandbox-env --validator-key "$HOME_DIR/validator_key.json" --account "$acct" \
    --rpc-url "$RPC_URL" --credentials-dir "$SANDBOX_DIR/credentials" \
    --deployments-dir "$SANDBOX_DIR/deployments" --out "$ENV_OUT" >/dev/null
}

cmd_start() {
  local pid
  mkdir -p "$SANDBOX_DIR"
  chmod 700 "$SANDBOX_DIR"
  if pid=$(running_pid); then
    if [ -n "$RECORDED_PORT" ] && [ "$RECORDED_PORT" != "$SANDBOX_RPC_PORT" ]; then
      die "The sandbox in $SANDBOX_DIR is running on port $RECORDED_PORT (pid $pid)." \
        "Use SANDBOX_RPC_PORT=$RECORDED_PORT, or stop it first: SANDBOX_DIR=$SANDBOX_DIR $0 stop"
    fi
    rpc_up || die "The sandbox in $SANDBOX_DIR (pid $pid) does not answer on $RPC_URL." \
      "Stop it (SANDBOX_DIR=$SANDBOX_DIR $0 stop) and start it again."
    [ -n "$RECORDED_PORT" ] || printf '%s\n' "$SANDBOX_RPC_PORT" >"$PORT_FILE"
    ok "sandbox already running (pid $pid, $RPC_URL)"
    write_env
    log "ENV_FILE=$ENV_OUT"
    return 0
  fi
  rm -f "$PID_FILE"
  if rpc_up; then
    die "Something already answers on $RPC_URL." "Stop it or pick another port: SANDBOX_RPC_PORT=<port> $0 start"
  fi
  ensure_binary
  if [ ! -f "$HOME_DIR/config.json" ]; then
    info "Initializing sandbox home $HOME_DIR"
    "$SANDBOX_BIN" --home "$HOME_DIR" init --fast >>"$LOG_FILE" 2>&1 ||
      die "near-sandbox init failed; see $LOG_FILE"
    # Same overrides the near-sandbox crate applies.
    "$NEAR_PYTHON" -I -c '
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c.setdefault("rpc", {}).setdefault("limits_config", {})["json_payload_max_size"] = 1024 * 1024 * 1024
c.setdefault("store", {})["max_open_files"] = 3000
json.dump(c, open(p, "w"), indent=2)
' "$HOME_DIR/config.json"
  fi
  # neard wants many file descriptors (the contract tests use 65535).
  ulimit -n 65535 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null ||
    warn "could not raise the open-file limit (ulimit -n is $(ulimit -n))"
  info "Starting near-sandbox on $RPC_URL (p2p 127.0.0.1:$NET_PORT)"
  # Default log level hides neard's per-block flat-storage warnings, which
  # are expected on a single-node sandbox. Override with NEAR_SANDBOX_LOG.
  RUST_LOG=${NEAR_SANDBOX_LOG:-warn,chain=error} nohup "$SANDBOX_BIN" --home "$HOME_DIR" run --rpc-addr "127.0.0.1:$SANDBOX_RPC_PORT" \
    --network-addr "127.0.0.1:$NET_PORT" </dev/null >>"$LOG_FILE" 2>&1 &
  pid=$!
  printf '%s\n' "$pid" >"$PID_FILE"
  printf '%s\n' "$SANDBOX_RPC_PORT" >"$PORT_FILE"
  local i=0
  while ! rpc_up; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$PID_FILE"
      tail -n 20 "$LOG_FILE" >&2 || true
      die "near-sandbox exited during startup; see $LOG_FILE"
    fi
    i=$((i + 1))
    [ "$i" -le 90 ] || die "near-sandbox did not answer on $RPC_URL within 90 s; see $LOG_FILE"
    sleep 1
  done
  write_env
  local acct
  acct=$(jget "$(cat "$HOME_DIR/validator_key.json")" account_id)
  nu --rpc "$RPC_URL" account "$acct" --wait-exists --timeout 60 >/dev/null ||
    die "validator account $acct not visible at final; see $LOG_FILE"
  ok "sandbox running (pid $pid)"
  log "RPC:      $RPC_URL"
  log "account:  $acct (genesis-funded; key in $ENV_OUT)"
  log "ENV_FILE: $ENV_OUT"
  log ""
  log "Next: ENV_FILE=$ENV_OUT $NEAR_SCRIPTS_DIR/deploy.sh"
}

cmd_stop() {
  local pid i=0
  if ! pid=$(running_pid); then
    rm -f "$PID_FILE"
    log "sandbox is not running ($SANDBOX_DIR)"
    return 0
  fi
  kill "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 20 ]; then
      warn "near-sandbox did not stop after 20 s; killing it"
      kill -9 "$pid" 2>/dev/null || true
      break
    fi
    sleep 1
  done
  rm -f "$PID_FILE"
  ok "sandbox stopped (state kept in $HOME_DIR)"
}

cmd_status() {
  local pid
  if pid=$(running_pid); then
    log "running:  pid $pid"
    log "RPC:      $RPC_URL"
    if [ -n "$RECORDED_PORT" ] && [ "$RECORDED_PORT" != "$SANDBOX_RPC_PORT" ]; then
      warn "this sandbox was started on port $RECORDED_PORT, not $SANDBOX_RPC_PORT"
    fi
    nu --rpc "$RPC_URL" status 2>/dev/null || {
      warn "RPC not answering on $RPC_URL"
      return 1
    }
  else
    log "not running ($SANDBOX_DIR)"
  fi
  [ -f "$ENV_OUT" ] && log "ENV_FILE: $ENV_OUT"
  [ -n "${pid:-}" ]
}

cmd_env() {
  [ -f "$ENV_OUT" ] || die "$ENV_OUT does not exist; run: $0 start"
  # Single-quote for eval; the path has no single quotes in practice.
  case $ENV_OUT in *"'"*) die "SANDBOX_DIR must not contain single quotes" ;; esac
  printf "export ENV_FILE='%s'\n" "$ENV_OUT"
}

cmd_reset() {
  cmd_stop
  rm -rf "$HOME_DIR" "$SANDBOX_DIR/credentials" "$SANDBOX_DIR/deployments" "$ENV_OUT" "$LOG_FILE" "$PORT_FILE"
  ok "sandbox state removed (binary cache kept in $SANDBOX_DIR/bin)"
}

near_tmp_init
"cmd_$CMD"
