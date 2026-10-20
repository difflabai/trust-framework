#!/usr/bin/env bash
# Usage: scripts/near/add-agent.sh <account_id> <public_key> [--force]
#
# Register PUBLIC_KEY as an agent key of ACCOUNT_ID (add_agent, signed by
# the owner). Skips the call if the key is already registered that way.
#
# The key must be a function-call access key of ACCOUNT_ID with receiver
# APPROVAL_CONTRACT_ID and method request_action (the contract's authorization model
# depends on it, see contracts/approval/README.md). A full-access key or a
# key scoped to another receiver or other methods is refused unless --force.
# A key that is not on the account yet is accepted with a warning (add it
# before using it). scripts/near/new-principal.sh creates such an account
# and key for you.
#
# Owner calls are signed by NEAR_ACCOUNT_ID, which must be APPROVAL_OWNER_ID.
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"
ROLE=agent

POS=() FORCE=0
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --force) FORCE=1 ;;
    -*) usage_error "unknown option '$1'" ;;
    *) POS+=("$1") ;;
  esac
  shift
done
[ "${#POS[@]}" -eq 2 ] || usage_error "expected <account_id> <public_key>"
ACCT=${POS[0]}
PK=${POS[1]}
near_load_config
require_account_id account_id "$ACCT"
nur access-key "$ACCT" "$PK" >/dev/null 2>"$NEAR_TMP/pk.err" ||
  die "$(cat "$NEAR_TMP/pk.err")"
near_require_owner
KRC=0
check_principal_access_key "$ACCT" "$ROLE" "$PK" || KRC=$?
case $KRC in
  0) ;;
  1) warn "$PK is not (yet) an access key of $ACCT. Add it as a function-call key for $APPROVAL_CONTRACT_ID" \
    "with method(s) $(role_methods "$ROLE") before using it, e.g. via scripts/near/new-principal.sh." ;;
  *)
    [ "$FORCE" = 1 ] || die "Refusing to register $PK: it is not a function-call key of $ACCT scoped to $APPROVAL_CONTRACT_ID [$(role_methods "$ROLE")] (see above)." \
      "Pass --force to register it anyway."
    warn "--force: registering it anyway."
    ;;
esac
register_principal "$ROLE" "$ACCT" "$PK"
printf '%s\n' "$PRINCIPAL_JSON" | nu json-pretty
