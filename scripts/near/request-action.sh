#!/usr/bin/env bash
# Usage: scripts/near/request-action.sh <agent_account> <action> [--key-file PATH]
#        scripts/near/request-action.sh <agent_account> --action-file PATH|- [--key-file PATH]
#
# Request approval for ACTION (1 to 2048 bytes; public and stored forever, so
# no secrets), signed with the agent's function-call key: by default the one
# new-principal.sh stored in <NEAR_CREDENTIALS_DIR>/<network>/<account>.agent.json.
# AGENT_ACCOUNT may be a short name (<name>.<NEAR_ACCOUNT_ID>).
# Prints the request id on stdout; the request itself and the transaction
# link go to stderr.
#
# Options:
#   --action-file PATH  read the action from a file ('-': stdin), byte for
#                       byte (a trailing newline is part of the action)
#   --key-file PATH     sign with this near-cli access-key file instead
#                       ({account_id, public_key, private_key}), e.g. a key
#                       the agent keeps outside this repo
#   --                  end of options (for an action starting with '-')
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

POS=() ACTION_FILE="" KEY_FILE=""
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      # Only before the positional arguments: an action "-h" must not turn
      # into a successful help exit (pass it after --).
      [ "${#POS[@]}" -eq 0 ] || usage_error "unexpected '$1' after the arguments (an action starting with '-' goes after --)"
      print_usage
      exit 0
      ;;
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
if [ -n "$ACTION_FILE" ]; then
  [ "${#POS[@]}" -eq 1 ] || usage_error "expected <agent_account> --action-file PATH"
else
  [ "${#POS[@]}" -eq 2 ] || usage_error "expected <agent_account> <action>"
fi
near_load_config
ACCT=$(principal_account "${POS[0]}")
if [ -n "$ACTION_FILE" ]; then
  AFILE=$(action_to_file "" "$ACTION_FILE")
else
  AFILE=$(action_to_file "${POS[1]}" "")
fi
KEYFILE=$(require_principal_keyfile "$ACCT" agent "$KEY_FILE")
near_require_contract
ARGS=$(nu json-build --file action="$AFILE") || die "could not encode the action (it must be valid UTF-8)"

near_call "$ACCT" "$KEYFILE" request_action "$ARGS" "Request action as $ACCT" || die "request_action failed"
ID=$(printf '%s' "$NEAR_TX_RESULT" | tr -d '[:space:]')
case $ID in '' | *[!0-9]*) die "unexpected request_action result: '$NEAR_TX_RESULT'" ;; esac
REQ=$(near_view get_request "$(nu json-build request_id:="$ID")" --wait-nonnull --timeout 60) ||
  die "request $ID did not become visible at final"
ok "request $ID is $(jget "$REQ" status)"
printf '%s\n' "$REQ" | nu json-pretty >&2
printf '%s\n' "$ID"
