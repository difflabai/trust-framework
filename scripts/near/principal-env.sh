#!/usr/bin/env bash
# Usage: scripts/near/principal-env.sh <name|account_id> <agent|approver> [--replace]
#
# Append a principal's credentials, from the key file new-principal.sh
# stored, to ENV_FILE (default <repo>/.env) as
#   APPROVAL_AGENT_ACCOUNT_ID / _PUBLIC_KEY / _PRIVATE_KEY      (agent)
#   APPROVAL_APPROVER_ACCOUNT_ID / _PUBLIC_KEY / _PRIVATE_KEY   (approver)
# under a comment naming the account, contract, key scope and registration.
# request-action.sh, approve.sh and reject.sh then sign with them when no
# key file is stored for that account, so the .env alone is enough.
#
# Checks first that the key is a function-call key of the account scoped to
# APPROVAL_CONTRACT_ID and registered for that role. The secret goes from the
# key file into ENV_FILE without passing through argv or stdout; ENV_FILE is
# rewritten atomically with mode 0600. Re-running with the same key changes
# nothing; a different key for the same role is refused unless --replace.
#
# Options:
#   --replace   overwrite this role's existing entries
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

POS=() REPLACE=0
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --replace) REPLACE=1 ;;
    -*) usage_error "unknown option '$1'" ;;
    *) POS+=("$1") ;;
  esac
  shift
done
[ "${#POS[@]}" -eq 2 ] || usage_error "expected <name|account_id> <agent|approver>"
ROLE=${POS[1]}
case $ROLE in agent | approver) ;; *) usage_error "role must be agent or approver" ;; esac

near_load_config
ACCT=$(principal_account "${POS[0]}")
KEYFILE=$(principal_keyfile "$ACCT" "$ROLE")
[ -f "$KEYFILE" ] || die "No $ROLE key stored for $ACCT ($KEYFILE)." \
  "Create it first: scripts/near/new-principal.sh ${POS[0]} $ROLE"
INFO=$(nu keyfile-info "$KEYFILE") || die "stored key file $KEYFILE is invalid"
PK=$(jget "$INFO" public_key)
near_require_contract

# The key must be what the contract's authorization model expects, and live.
KRC=0
check_principal_access_key "$ACCT" "$ROLE" "$PK" || KRC=$?
case $KRC in
  0) ;;
  1) die "$PK is not an access key of $ACCT; run scripts/near/new-principal.sh ${POS[0]} $ROLE" ;;
  *) die "$PK on $ACCT is not a function-call key scoped to $APPROVAL_CONTRACT_ID and $ROLE methods (see above)." ;;
esac
P=$(near_view get_principal "$(nu json-build public_key="$PK")") || die "get_principal failed"
[ "$P" != null ] && [ "$(jget "$P" account_id)" = "$ACCT" ] && [ "$(jget "$P" role)" = "$ROLE" ] ||
  die "$PK is not registered as $ROLE of $ACCT in $APPROVAL_CONTRACT_ID; run scripts/near/new-principal.sh ${POS[0]} $ROLE"
REG=$(jget "$P" registration_id)
require_uint registration_id "$REG"

PREFIX=$(principal_env_prefix "$ROLE")
COMMENT="$ROLE $ACCT on $NEAR_NETWORK: function-call key for $APPROVAL_CONTRACT_ID [$PRINCIPAL_KEY_METHODS], registration $REG (scripts/near/principal-env.sh, $(utc_now))"
if [ "$REPLACE" = 1 ]; then
  RES=$(nu env-append --keyfile "$KEYFILE" --env-file "$ENV_FILE" --prefix "$PREFIX" --comment "$COMMENT" --replace) ||
    die "could not update $ENV_FILE"
else
  RES=$(nu env-append --keyfile "$KEYFILE" --env-file "$ENV_FILE" --prefix "$PREFIX" --comment "$COMMENT") ||
    die "could not update $ENV_FILE"
fi
case $RES in
  unchanged) ok "$ENV_FILE already has ${PREFIX}_* for $ACCT ($PK); nothing changed" ;;
  replaced) ok "replaced ${PREFIX}_ACCOUNT_ID, ${PREFIX}_PUBLIC_KEY, ${PREFIX}_PRIVATE_KEY in $ENV_FILE ($ACCT, $PK)" ;;
  *) ok "appended ${PREFIX}_ACCOUNT_ID, ${PREFIX}_PUBLIC_KEY, ${PREFIX}_PRIVATE_KEY to $ENV_FILE ($ACCT, $PK)" ;;
esac
