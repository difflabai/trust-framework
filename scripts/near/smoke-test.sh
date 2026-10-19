#!/usr/bin/env bash
# Usage: scripts/near/smoke-test.sh [--cleanup]
#
# End-to-end check of the deployed contract on the configured network:
#   1. ensure principals smoke-agent.<NEAR_ACCOUNT_ID> (agent) and
#      smoke-approver.<NEAR_ACCOUNT_ID> (approver) via new-principal.sh
#      (two accounts: an approver can't decide its own account's requests)
#   2. request a unique action, approve it, and check get_approval and
#      get_request: status approved, the action, both account ids and keys
#   3. request a second action, reject it, and check status rejected and
#      get_rejection
# Each run stores two small requests and one approval in the contract for
# good (~1 KB of the contract's storage balance).
#
#   --cleanup   instead of testing: revoke the smoke keys, delete the two
#               smoke accounts (balances return to NEAR_ACCOUNT_ID) and
#               their stored key files
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"

CLEANUP=0
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --cleanup) CLEANUP=1 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done

near_load_config
S=$NEAR_SCRIPTS_DIR
AGENT=smoke-agent.$NEAR_ACCOUNT_ID
APPROVER=smoke-approver.$NEAR_ACCOUNT_ID

if [ "$CLEANUP" = 1 ]; then
  near_require_parent
  CAN_REVOKE=0
  if [ "$(jget "$(near_account "$APPROVAL_CONTRACT_ID")" has_code)" = true ]; then
    near_require_owner
    CAN_REVOKE=1
  else
    warn "$APPROVAL_CONTRACT_ID has no contract; skipping key revocation"
  fi
  for pair in "$AGENT agent" "$APPROVER approver"; do
    acct=${pair% *}
    role=${pair#* }
    f=$(principal_keyfile "$acct" "$role")
    if [ -f "$f" ] && [ "$CAN_REVOKE" = 1 ]; then
      pk=$(jget "$(nu keyfile-info "$f")" public_key)
      "$S/revoke-key.sh" "$pk" >/dev/null 2>"$NEAR_TMP/revoke.log" ||
        { cat "$NEAR_TMP/revoke.log" >&2; die "revoking $pk failed"; }
      grep -E '^(==>|ok:|    tx: |    https?://)' "$NEAR_TMP/revoke.log" >&2 || true
    fi
    "$S/delete-account.sh" "$acct" --yes
  done
  ok "smoke principals cleaned up"
  exit 0
fi

near_require_owner
info "Principals"
"$S/new-principal.sh" smoke-agent agent >/dev/null
"$S/new-principal.sh" smoke-approver approver >/dev/null
AGENT_PK=$(jget "$(nu keyfile-info "$(principal_keyfile "$AGENT" agent)")" public_key)
APPROVER_PK=$(jget "$(nu keyfile-info "$(principal_keyfile "$APPROVER" approver)")" public_key)
log "    agent    $AGENT $AGENT_PK"
log "    approver $APPROVER $APPROVER_PK"

TAG="$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
fail() { die "SMOKE TEST FAILED: $*"; }
show_tx() { grep -E '^    (tx: |https?://)' "$1" >&2 || true; }

info "Approve path"
ACTION1="smoke-test approve $TAG"
ID1=$("$S/request-action.sh" smoke-agent "$ACTION1" 2>"$NEAR_TMP/req1.log") ||
  { cat "$NEAR_TMP/req1.log" >&2; fail "request_action"; }
log "    request $ID1: $ACTION1"
show_tx "$NEAR_TMP/req1.log"
"$S/approve.sh" smoke-approver "$ID1" "$ACTION1" >"$NEAR_TMP/proof.json" 2>"$NEAR_TMP/approve.log" ||
  { cat "$NEAR_TMP/approve.log" >&2; fail "approve"; }
show_tx "$NEAR_TMP/approve.log"
IDARGS=$(nu json-build request_id:="$ID1")
APPROVAL=$(near_view get_approval "$IDARGS" --wait-nonnull --timeout 60) || fail "get_approval($ID1) stayed null"
printf '%s' "$APPROVAL" | nu assert-fields request_id:="$ID1" action="$ACTION1" \
  agent_account_id="$AGENT" agent_public_key="$AGENT_PK" \
  approver_account_id="$APPROVER" approver_public_key="$APPROVER_PK" \
  agent_key_revoked_at:=null approver_key_revoked_at:=null || fail "get_approval($ID1) fields"
nu assert-fields request_id:="$ID1" action="$ACTION1" approver_account_id="$APPROVER" <"$NEAR_TMP/proof.json" ||
  fail "approve() return value"
REQ=$(near_view get_request "$IDARGS") || fail "get_request($ID1)"
printf '%s' "$REQ" | nu assert-fields status=approved action="$ACTION1" agent_account_id="$AGENT" \
  agent_public_key="$AGENT_PK" || fail "get_request($ID1) fields"
ok "request $ID1 approved; get_approval and get_request agree"

info "Reject path"
ACTION2="smoke-test reject $TAG"
ID2=$("$S/request-action.sh" smoke-agent "$ACTION2" 2>"$NEAR_TMP/req2.log") ||
  { cat "$NEAR_TMP/req2.log" >&2; fail "request_action"; }
log "    request $ID2: $ACTION2"
show_tx "$NEAR_TMP/req2.log"
"$S/reject.sh" smoke-approver "$ID2" >/dev/null 2>"$NEAR_TMP/reject.log" ||
  { cat "$NEAR_TMP/reject.log" >&2; fail "reject"; }
show_tx "$NEAR_TMP/reject.log"
IDARGS=$(nu json-build request_id:="$ID2")
REJ=$(near_view get_rejection "$IDARGS" --wait-nonnull --timeout 60) || fail "get_rejection($ID2) stayed null"
printf '%s' "$REJ" | nu assert-fields request_id:="$ID2" action="$ACTION2" approver_account_id="$APPROVER" \
  approver_public_key="$APPROVER_PK" agent_account_id="$AGENT" || fail "get_rejection($ID2) fields"
REQ=$(near_view get_request "$IDARGS") || fail "get_request($ID2)"
printf '%s' "$REQ" | nu assert-fields status=rejected action="$ACTION2" || fail "get_request($ID2) fields"
[ "$(near_view get_approval "$IDARGS")" = null ] || fail "get_approval($ID2) should be null"
ok "request $ID2 rejected; get_rejection and get_request agree"

ok "SMOKE TEST PASSED on $NEAR_NETWORK ($APPROVAL_CONTRACT_ID): requests $ID1 (approved), $ID2 (rejected)"
log "    Clean up the smoke accounts with: scripts/near/smoke-test.sh --cleanup"
