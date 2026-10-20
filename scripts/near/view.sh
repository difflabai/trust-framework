#!/usr/bin/env bash
# Usage: scripts/near/view.sh <method> [json-args] [--contract ID] [--compact]
#
# Call a view method of the approval contract (read-only, finality final)
# and pretty-print the JSON result on stdout. Needs no key.
#
# Examples:
#   scripts/near/view.sh get_owner
#   scripts/near/view.sh get_request '{"request_id": 0}'
#   scripts/near/view.sh get_approvals '{"from_index": 0, "limit": 10}'
#   scripts/near/view.sh get_principal '{"public_key": "ed25519:..."}'
#
# Options:
#   --contract ID   another contract account (default APPROVAL_CONTRACT_ID)
#   --compact       one-line JSON
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

METHOD="" ARGS="" CONTRACT="" PRETTY=--pretty
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --contract)
      [ $# -gt 1 ] || usage_error "--contract needs an account id"
      CONTRACT=$2
      shift
      ;;
    --compact) PRETTY="" ;;
    -*) usage_error "unknown option '$1'" ;;
    *)
      if [ -z "$METHOD" ]; then
        METHOD=$1
      elif [ -z "$ARGS" ]; then
        ARGS=$1
      else
        usage_error "unexpected argument '$1'"
      fi
      ;;
  esac
  shift
done
[ -n "$METHOD" ] || usage_error "missing <method>"
case $METHOD in *[!A-Za-z0-9_]*) usage_error "invalid method name '$METHOD'" ;; esac

near_load_config
CONTRACT=${CONTRACT:-$APPROVAL_CONTRACT_ID}
require_account_id --contract "$CONTRACT"
[ -n "$ARGS" ] || ARGS='{}'
# shellcheck disable=SC2086 # $PRETTY is empty or one flag
nur view "$CONTRACT" "$METHOD" "$ARGS" $PRETTY
