#!/usr/bin/env bash
# Usage: scripts/near/reject.sh <approver_account> <request_id> [--key-file PATH] [--skip-checks]
#
# Reject pending request REQUEST_ID, signed with the approver's function-call
# key (by default <NEAR_CREDENTIALS_DIR>/<network>/<account>.approver.json;
# --key-file PATH for a key kept elsewhere). Frees one of the agent key's 16
# pending slots. Prints the rejection JSON on stdout.
#
# Before sending, checks the request exists, is pending and was not made by
# the approver's own account. --skip-checks sends anyway.
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"

POS=() SKIP=0 KEY_FILE=""
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      # Only before the positional arguments: an action "-h" must not turn
      # into a successful help exit (pass it after --).
      [ "${#POS[@]}" -eq 0 ] || usage_error "unexpected '$1' after the arguments (an action starting with '-' goes after --)"
      print_usage
      exit 0
      ;;
    --skip-checks) SKIP=1 ;;
    --key-file)
      [ $# -gt 1 ] || usage_error "--key-file needs a path"
      KEY_FILE=$2
      shift
      ;;
    --)
      shift
      POS+=("$@")
      break
      ;;
    -*) usage_error "unknown option '$1'" ;;
    *) POS+=("$1") ;;
  esac
  shift
done
[ "${#POS[@]}" -eq 2 ] || usage_error "expected <approver_account> <request_id>"
near_load_config
ACCT=$(principal_account "${POS[0]}")
ID=${POS[1]}
case $ID in '' | *[!0-9]*) usage_error "request_id must be a number" ;; esac
KEYFILE=$(require_principal_keyfile "$ACCT" approver "$KEY_FILE")
near_require_contract
IDARGS=$(nu json-build request_id:="$ID") || die "could not encode the arguments"

if [ "$SKIP" = 0 ]; then
  REQ=$(near_view get_request "$IDARGS") || die "get_request failed"
  [ "$REQ" != null ] || die "request $ID does not exist"
  STATUS=$(jget "$REQ" status)
  [ "$STATUS" = pending ] || die "request $ID is $STATUS, not pending"
  [ "$(jget "$REQ" agent_account_id)" != "$ACCT" ] ||
    die "request $ID was made by $ACCT itself; separation of duties forbids deciding it with the same account"
fi

near_call "$ACCT" "$KEYFILE" reject "$IDARGS" "Reject request $ID as $ACCT" || die "reject failed"
near_view get_rejection "$IDARGS" --wait-nonnull --timeout 60 >/dev/null ||
  die "the rejection did not become visible at final"
ok "request $ID rejected"
printf '%s\n' "$NEAR_TX_RESULT" | nu json-pretty
