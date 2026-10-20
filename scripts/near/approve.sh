#!/usr/bin/env bash
# Usage: scripts/near/approve.sh <approver_account> <request_id> <action> [options]
#        scripts/near/approve.sh <approver_account> <request_id> --action-file PATH|- [options]
#        scripts/near/approve.sh <approver_account> <request_id> --action-from-request [options]
#
# Approve request REQUEST_ID, signed with the approver's function-call key:
# by default the one new-principal.sh stored in
# <NEAR_CREDENTIALS_DIR>/<network>/<account>.approver.json. ACTION must
# restate the requested action exactly: the contract refuses the approval
# otherwise, so the approver's own signed transaction names what was
# reviewed. Prints the approval proof JSON on stdout.
#
# Before sending, checks that the request exists, is pending, has exactly
# this action and was not made by the approver's own account (separation of
# duties), so a doomed transaction isn't sent.
#
# Options:
#   --action-file PATH     read the action from a file ('-': stdin), byte for
#                          byte (a trailing newline is part of the action)
#   --action-from-request  print the stored action to stderr and approve
#                          exactly that (only after you reviewed it!)
#   --key-file PATH        sign with this near-cli access-key file instead
#                          (e.g. a key the approver keeps outside this repo)
#   --skip-checks          send without the checks; the contract decides
#   --                     end of options (for an action starting with '-')
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

POS=() SKIP=0 ACTION_FILE="" KEY_FILE="" FROM_REQ=0
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
    --action-from-request) FROM_REQ=1 ;;
    --action-file)
      [ $# -gt 1 ] || usage_error "--action-file needs a path ('-' for stdin)"
      ACTION_FILE=$2
      shift
      ;;
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
    -*) usage_error "unknown option '$1' (an action starting with '-' goes after --)" ;;
    *) POS+=("$1") ;;
  esac
  shift
done
if [ -n "$ACTION_FILE" ] || [ "$FROM_REQ" = 1 ]; then
  [ -z "$ACTION_FILE" ] || [ "$FROM_REQ" = 0 ] || usage_error "--action-file and --action-from-request are exclusive"
  [ "${#POS[@]}" -eq 2 ] || usage_error "expected <approver_account> <request_id>"
  [ "$FROM_REQ" = 0 ] || [ "$SKIP" = 0 ] || usage_error "--action-from-request needs the checks (no --skip-checks)"
else
  [ "${#POS[@]}" -eq 3 ] || usage_error "expected <approver_account> <request_id> <action>"
fi
near_load_config
ACCT=$(principal_account "${POS[0]}")
ID=${POS[1]}
case $ID in '' | *[!0-9]*) usage_error "request_id must be a number" ;; esac
KEYFILE=$(require_principal_keyfile "$ACCT" approver "$KEY_FILE")
near_require_contract
IDARGS=$(nu json-build request_id:="$ID")

if [ "$SKIP" = 0 ]; then
  require_key_can_call "$ACCT" "$KEYFILE" approve
  REQ=$(near_view get_request "$IDARGS") || die "get_request failed"
  [ "$REQ" != null ] || die "request $ID does not exist (get_request_count is $(near_view get_request_count))"
  STATUS=$(jget "$REQ" status)
  [ "$STATUS" = pending ] || die "request $ID is $STATUS, not pending"
  [ "$(jget "$REQ" agent_account_id)" != "$ACCT" ] ||
    die "request $ID was made by $ACCT itself; separation of duties forbids deciding it with the same account"
fi
if [ "$FROM_REQ" = 1 ]; then
  ARGS=$(printf '%s' "$REQ" | "$NEAR_PYTHON" -I -X utf8 -c '
import json, sys
r = json.load(sys.stdin)
print(json.dumps({"request_id": r["request_id"], "action": r["action"]}, separators=(",", ":")))') ||
    die "could not read the stored action"
  log "    approving the stored action of request $ID (by $(jget "$REQ" agent_account_id)):"
  printf '%s\n' "$REQ" | nu json-get action | sed 's/^/    | /' >&2
else
  if [ -n "$ACTION_FILE" ]; then
    AFILE=$(action_to_file "" "$ACTION_FILE")
  else
    AFILE=$(action_to_file "${POS[2]}" "")
  fi
  ARGS=$(nu json-build request_id:="$ID" --file action="$AFILE") ||
    die "could not encode the action (it must be valid UTF-8)"
  if [ "$SKIP" = 0 ] && ! printf '%s' "$REQ" | nu assert-fields --expect-json "$ARGS" --only action 2>/dev/null; then
    die "the action does not match request $ID's stored action; the contract would refuse it." \
      "stored: $(printf '%s' "$REQ" | nu json-get action)" \
      "given:  $(nu json-get action <<<"$ARGS")"
  fi
fi

near_call "$ACCT" "$KEYFILE" approve "$ARGS" "Approve request $ID as $ACCT" || die "approve failed"
near_view get_approval "$IDARGS" --wait-nonnull --timeout 60 >/dev/null ||
  die "the approval did not become visible at final"
ok "request $ID approved"
printf '%s\n' "$NEAR_TX_RESULT" | nu json-pretty
