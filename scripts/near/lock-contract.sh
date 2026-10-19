#!/usr/bin/env bash
# Usage: scripts/near/lock-contract.sh --yes [--dry-run]
#
# Lock the deployment: delete every access key of the contract account
# (APPROVAL_CONTRACT_ID), so nobody, including you, can redeploy its code,
# delete it or act as it again. This is step 3 of the verifier checklist in
# contracts/approval/README.md ("Verifying a proof"). IRREVERSIBLE: no more
# deploy.sh --upgrade or --fresh, no delete-account.sh; to change the code
# you deploy a new instance. Top-ups (transfer.sh) and all contract calls
# keep working.
#
# Checks first: the contract runs code, its code_hash matches the deployment
# record (<NEAR_DEPLOYMENTS_DIR>/<network>/<contract>.json), get_owner is
# APPROVAL_OWNER_ID (and not the contract itself), and NEAR_PRIVATE_KEY is a
# full-access key of the contract account (it signs the deletion). Records
# locked_at and the transaction in the deployment record.
#
# Options:
#   --yes       required: this cannot be undone
#   --dry-run   run the checks and show the keys that would be deleted
#   -h, --help
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"

YES=0 DRY_RUN=0
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --yes | -y) YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done

near_load_config
near_print_config
near_require_signer
CONTRACT=$APPROVAL_CONTRACT_ID
near_require_contract
C=$(near_account "$CONTRACT")
CODE_HASH=$(jget "$C" code_hash)
REC="$NEAR_DEPLOYMENTS_DIR/$NEAR_NETWORK/$CONTRACT.json"
[ -f "$REC" ] || die "No deployment record $REC." \
  "Lock only a deployment you recorded (scripts/near/deploy.sh writes it; commit it first)."
REC_HASH=$(jget "$(cat "$REC")" code_hash)
[ "$REC_HASH" = "$CODE_HASH" ] ||
  die "$CONTRACT runs code_hash $CODE_HASH but the deployment record says $REC_HASH. Resolve that before locking."
ok "code_hash $CODE_HASH matches $REC"
OWNER=$(near_view get_owner) || die "get_owner failed"
[ "$OWNER" = "$APPROVAL_OWNER_ID" ] || die "get_owner is $OWNER, not APPROVAL_OWNER_ID=$APPROVAL_OWNER_ID."
[ "$OWNER" != "$CONTRACT" ] || die "the contract owns itself; after locking nobody could register or revoke keys."
ok "owner $OWNER"

KEYS=$(nur access-keys "$CONTRACT") || die "could not list the access keys of $CONTRACT"
LIST=$(printf '%s' "$KEYS" | "$NEAR_PYTHON" -I -X utf8 -c '
import json, sys
for k in json.load(sys.stdin):
    print("%s %s" % (k["public_key"], k["permission"] if k["permission"] == "FullAccess"
                     else "FunctionCall(%s)" % k.get("receiver_id")))')
if [ -z "$LIST" ]; then
  ok "$CONTRACT has no access keys: it is already locked."
  exit 0
fi
info "Access keys of $CONTRACT to delete:"
printf '%s\n' "$LIST" | sed 's/^/    /' >&2
near_require_full_access "$CONTRACT"
PKS=$(printf '%s\n' "$LIST" | awk '{ print $1 }' | paste -sd, -)
if [ "$DRY_RUN" = 1 ]; then
  ok "Dry run: checks passed; would run (signed by $CONTRACT):"
  log "  near account delete-keys $CONTRACT public-keys $PKS network-config $NEAR_NETWORK sign-with-access-key-file <0600 key file> send"
  exit 0
fi
[ "$YES" = 1 ] || die "refusing without --yes: locking $CONTRACT on $NEAR_NETWORK is irreversible."

near_tx "Delete all access keys of $CONTRACT (lock)" "$(near_signer_keyfile "$CONTRACT")" \
  account delete-keys "$CONTRACT" public-keys "$PKS" || die "deleting the keys failed"
LOCK_TX=$NEAR_TX_HASH
i=0
while [ "$(nur access-keys "$CONTRACT")" != "[]" ]; do
  i=$((i + 1))
  [ "$i" -le 60 ] || die "$CONTRACT still has access keys at final after 60 s"
  sleep 1
done
ok "$CONTRACT is locked: no access keys left"
nu record-deployment --merge --out "$REC" locked_at="$(utc_now)" lock_tx_hash="$LOCK_TX" ||
  warn "could not update $REC"
log "    recorded in $REC (commit it)"
printf '%s\n' "$LOCK_TX"
