#!/usr/bin/env bash
# Usage: scripts/near/delete-account.sh <account_id> --yes [--delete-contract]
#
# Delete ACCOUNT_ID, a subaccount of NEAR_ACCOUNT_ID, sending its balance to
# NEAR_ACCOUNT_ID. Refuses NEAR_ACCOUNT_ID itself, anything that is not
# <...>.<NEAR_ACCOUNT_ID>, and runs only with --yes. Deleting the contract
# account (APPROVAL_CONTRACT_ID) also needs --delete-contract: it destroys
# every request, approval and registration, and verifiers lose the proofs.
#
# NEAR refuses to delete an account whose storage minus its code exceeds
# 10,000 bytes (DeleteAccountWithLargeState); that is checked first, so a
# used contract account can't be deleted. Stored principal key files of the
# account (including ones revoke-key.sh retired) are removed afterwards. Keys registered in the contract stay
# registered: revoke them first (scripts/near/revoke-key.sh).
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"

ACCT="" YES=0 DEL_CONTRACT=0
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --yes | -y) YES=1 ;;
    --delete-contract) DEL_CONTRACT=1 ;;
    -*) usage_error "unknown option '$1'" ;;
    *)
      [ -z "$ACCT" ] || usage_error "unexpected argument '$1'"
      ACCT=$1
      ;;
  esac
  shift
done
[ -n "$ACCT" ] || usage_error "missing <account_id>"
near_load_config
require_account_id account_id "$ACCT"
[ "$ACCT" != "$NEAR_ACCOUNT_ID" ] || die "refusing to delete NEAR_ACCOUNT_ID ($NEAR_ACCOUNT_ID) itself"
case $ACCT in
  *".$NEAR_ACCOUNT_ID") ;;
  *) die "refusing: $ACCT is not a subaccount of $NEAR_ACCOUNT_ID" ;;
esac
if [ "$ACCT" = "$APPROVAL_CONTRACT_ID" ] && [ "$DEL_CONTRACT" != 1 ]; then
  die "refusing: $ACCT is the approval contract (APPROVAL_CONTRACT_ID). Deleting it destroys all its records." \
    "Pass --delete-contract as well if you really mean it."
fi
[ "$YES" = 1 ] || die "refusing without --yes: this deletes $ACCT on $NEAR_NETWORK (balance goes to $NEAR_ACCOUNT_ID)."

near_require_parent
A=$(near_account "$ACCT")
if [ "$(jget "$A" exists)" != true ]; then
  ok "$ACCT does not exist on $NEAR_NETWORK; nothing to delete."
else
  near_require_full_access "$ACCT"
  usage=$(jget "$A" storage_usage)
  code_len=0
  if [ "$(jget "$A" has_code)" = true ]; then code_len=$(jget "$(nur code "$ACCT")" length); fi
  require_uint storage_usage "$usage"
  require_uint "code length" "$code_len"
  state=$(int_calc "$usage - $code_len")
  if [ "$(int_calc "$state > 10000")" = 1 ]; then
    die "$ACCT holds $state bytes of non-code state (> 10,000): NEAR refuses to delete it (DeleteAccountWithLargeState)."
  fi
  log "    $ACCT: balance $(fmt_near "$(jget "$A" amount)") -> $NEAR_ACCOUNT_ID"
  near_tx "Delete $ACCT (beneficiary $NEAR_ACCOUNT_ID)" "$(near_signer_keyfile "$ACCT")" \
    account delete-account "$ACCT" beneficiary "$NEAR_ACCOUNT_ID" || die "deleting $ACCT failed"
  nur account "$ACCT" --wait-gone --timeout 60 >/dev/null || die "$ACCT still exists at final"
  ok "deleted $ACCT"
fi
for role in agent approver; do
  f=$(principal_keyfile "$ACCT" "$role")
  if [ -f "$f" ]; then
    pk=$(jget "$(nu keyfile-info "$f")" public_key)
    c=$(near_account "$APPROVAL_CONTRACT_ID")
    if [ "$(jget "$c" has_code)" = true ] && [ "$ACCT" != "$APPROVAL_CONTRACT_ID" ] &&
      [ "$(near_view get_principal "$(nu json-build public_key="$pk")" 2>/dev/null || echo null)" != null ]; then
      warn "$pk ($role of $ACCT) is still registered in $APPROVAL_CONTRACT_ID: scripts/near/revoke-key.sh $pk"
    fi
    rm -f "$f"
    log "    removed $f"
  fi
done
# Key files retired by revoke-key.sh (<account>.<role>.revoked-<n>.json).
for f in "$NEAR_CREDENTIALS_DIR/$NEAR_NETWORK/$ACCT".*.revoked-*.json; do
  [ -f "$f" ] || continue
  rm -f "$f"
  log "    removed $f"
done
