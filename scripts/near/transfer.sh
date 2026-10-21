#!/usr/bin/env bash
# Usage: scripts/near/transfer.sh <receiver> <amount_NEAR> [--yes]
#
# Send NEAR from NEAR_ACCOUNT_ID to RECEIVER, e.g. to top up the contract's
# storage balance:  scripts/near/transfer.sh "$APPROVAL_CONTRACT_ID" 2
# AMOUNT is exact ("1.5", "1.5 NEAR" or "1000 yoctoNEAR"). Asks for
# confirmation on a terminal unless --yes. Refuses a named receiver that
# does not exist.
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"

POS=() ASSUME_YES=0
# shellcheck disable=SC2034 # ASSUME_YES is read by confirm() in lib.sh
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --yes | -y) ASSUME_YES=1 ;;
    *) POS+=("$1") ;;
  esac
  shift
done
[ "${#POS[@]}" -eq 2 ] || usage_error "expected <receiver> <amount_NEAR>"
near_load_config
RECEIVER=${POS[0]}
require_account_id receiver "$RECEIVER"
AMOUNT=$(yocto "${POS[1]}") || usage_error "bad amount '${POS[1]}'"
[ "$(int_calc "$AMOUNT > 0")" = 1 ] || usage_error "amount must be positive"
[ "$RECEIVER" != "$NEAR_ACCOUNT_ID" ] || usage_error "receiver is the sender"

near_require_parent
R=$(near_account "$RECEIVER")
if [ "$(jget "$R" exists)" != true ]; then
  if [ "${#RECEIVER}" -eq 64 ] && [ -z "${RECEIVER//[0-9a-f]/}" ]; then
    warn "$RECEIVER does not exist yet; the transfer creates this implicit account."
  else
    die "$RECEIVER does not exist on $NEAR_NETWORK (a transfer to it would fail)."
  fi
else
  log "    $RECEIVER balance $(fmt_near "$(jget "$R" amount)")"
fi
near_require_balance "$NEAR_ACCOUNT_ID" "$NEAR_PARENT_JSON" "$(int_calc "$AMOUNT + $TX_FEE_MARGIN_YOCTO")" "this transfer"
confirm "Send $(fmt_near "$AMOUNT" --digits 24) from $NEAR_ACCOUNT_ID to $RECEIVER on $NEAR_NETWORK?"
near_tx "Transfer $(fmt_near "$AMOUNT" --digits 24) to $RECEIVER" "$(near_signer_keyfile "$NEAR_ACCOUNT_ID")" \
  tokens "$NEAR_ACCOUNT_ID" send-near "$RECEIVER" "$AMOUNT yoctoNEAR" || die "transfer failed"
ok "sent"
printf '%s\n' "$NEAR_TX_HASH"
