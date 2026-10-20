#!/usr/bin/env bash
# Usage: scripts/near/list-requests.sh [--pending | --status S] [--from N] [--limit N]
#
# List requests of the approval contract (read-only, finality final, no
# key needed): one compact JSON object per line on stdout, as returned by
# get_request ({request_id, agent_account_id, agent_public_key, action,
# status, ...}). The contract has no paged request listing, so this calls
# get_request once per id.
#
# Options:
#   --pending      only pending requests (same as --status pending)
#   --status S     only requests with status S: pending, approved, rejected
#                  or void (repeatable)
#   --from N       first request id (default: the newest --limit requests)
#   --limit N      how many ids to look at (default 50, max 1000)
#   -h, --help
#
# Example: the actions waiting for review, oldest first:
#   scripts/near/list-requests.sh --pending --from 0 --limit 1000
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"

FROM="" LIMIT=50 STATUS_ARGS=()
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --pending) STATUS_ARGS+=(--status pending) ;;
    --status)
      [ $# -gt 1 ] || usage_error "--status needs a value"
      case $2 in pending | approved | rejected | void) ;; *) usage_error "unknown status '$2'" ;; esac
      STATUS_ARGS+=(--status "$2")
      shift
      ;;
    --from)
      [ $# -gt 1 ] || usage_error "--from needs a number"
      FROM=$2
      shift
      ;;
    --limit)
      [ $# -gt 1 ] || usage_error "--limit needs a number"
      LIMIT=$2
      shift
      ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done
case $FROM in *[!0-9]*) usage_error "--from must be a number" ;; esac
case $LIMIT in '' | *[!0-9]*) usage_error "--limit must be a number" ;; esac
[ "$LIMIT" -ge 1 ] && [ "$LIMIT" -le 1000 ] || usage_error "--limit must be 1 to 1000"

near_load_config
near_require_contract
set -- requests "$APPROVAL_CONTRACT_ID" --limit "$LIMIT"
[ -z "$FROM" ] || set -- "$@" --from "$FROM"
# "${arr[@]}" of an empty array is an error under set -u in bash 3.2.
[ "${#STATUS_ARGS[@]}" -eq 0 ] || set -- "$@" "${STATUS_ARGS[@]}"
nur "$@"
