#!/usr/bin/env bash
# Usage: scripts/near/new-principal.sh <name|account_id> <agent|approver> [--balance NEAR]
#
# Set up an agent or approver end to end, idempotently:
#   1. ensure the account <name>.<NEAR_ACCOUNT_ID> exists (created by
#      NEAR_ACCOUNT_ID, funded with --balance for its own gas, default 0.5
#      NEAR or APPROVAL_PRINCIPAL_BALANCE; its full-access key is the parent's
#      key, so the .env key manages it)
#   2. generate a new ed25519 keypair (offline, near-cli) and store it in
#      <NEAR_CREDENTIALS_DIR>/<network>/<account>.<role>.json (mode 0600,
#      gitignored), or reuse the key already stored there
#   3. add it to the account as a function-call access key restricted to
#      APPROVAL_CONTRACT_ID and the role's methods (agent: request_action;
#      approver: approve, reject), unlimited gas allowance
#   4. register it with add_agent / add_approver (owner-signed), and note
#      the contract and registration id in the key file
# Prints {account_id, role, public_key, key_file, registration_id} on stdout.
#
# A stored key that was revoked is not re-registered: revoke-key.sh retires
# the key file, and a key file whose recorded registration was revoked is
# refused. Function-call keys are scoped to one contract, so use a separate
# NEAR_CREDENTIALS_DIR per contract instance.
#
# Separation of duties: an approver can't approve or reject requests made
# by an agent key of the same account, so use different accounts.
#
# Options:
#   --balance NEAR   initial balance if the account must be created (at
#                    least 0.05 NEAR: a principal pays its own gas)
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

NAME="" ROLE="" BALANCE_ARG=""
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --balance)
      [ $# -gt 1 ] || usage_error "--balance needs an amount"
      BALANCE_ARG=$2
      shift
      ;;
    -*) usage_error "unknown option '$1'" ;;
    *)
      if [ -z "$NAME" ]; then
        NAME=$1
      elif [ -z "$ROLE" ]; then
        ROLE=$1
      else
        usage_error "unexpected argument '$1'"
      fi
      ;;
  esac
  shift
done
[ -n "$NAME" ] && [ -n "$ROLE" ] || usage_error "expected <name|account_id> <agent|approver>"
case $ROLE in agent | approver) ;; *) usage_error "role must be agent or approver" ;; esac

near_load_config
ACCT=$(principal_account "$NAME")
LABEL=${ACCT%".$NEAR_ACCOUNT_ID"}
case $LABEL in
  "$ACCT" | *.*) die "$ACCT is not a direct subaccount of $NEAR_ACCOUNT_ID; new-principal.sh only manages <name>.$NEAR_ACCOUNT_ID." \
    "For an account you control elsewhere, add a function-call key yourself and run add-$ROLE.sh." ;;
esac
[ "$ACCT" != "$APPROVAL_CONTRACT_ID" ] || die "the contract account cannot be a principal"
METHODS=$(role_methods "$ROLE")
BALANCE=$(yocto "${BALANCE_ARG:-${APPROVAL_PRINCIPAL_BALANCE:-0.5}}") || usage_error "bad balance"
MIN_PRINCIPAL_BALANCE=$(yocto 0.05)
[ "$(int_calc "$BALANCE >= $MIN_PRINCIPAL_BALANCE")" = 1 ] ||
  usage_error "balance $(fmt_near "$BALANCE") is too small: a principal pays its own gas (minimum 0.05 NEAR)"
KEYFILE=$(principal_keyfile "$ACCT" "$ROLE")
# separate_dir_hint RECEIVER: how to run a second contract instance's principals.
separate_dir_hint() {
  printf '%s\n' "This key belongs to $1. Function-call keys are scoped to one contract, so for another" \
    "contract instance use its own credentials dir instead of deleting this file (it is still needed for $1), e.g." \
    "  NEAR_CREDENTIALS_DIR=.near-credentials-${APPROVAL_CONTRACT_ID%%.*} APPROVAL_CONTRACT_ID=$APPROVAL_CONTRACT_ID scripts/near/new-principal.sh $NAME $ROLE"
}

near_require_owner
OTHER=agent
[ "$ROLE" = agent ] && OTHER=approver
if [ -f "$(principal_keyfile "$ACCT" "$OTHER")" ]; then
  warn "$ACCT also has an $OTHER key. Separation of duties: its approver key can't decide its own agent's requests."
fi

# 1. the account
A=$(near_account "$ACCT")
CREATED=0
if [ "$(jget "$A" exists)" != true ]; then
  # The parent pays the new balance, then the registration call, which buys
  # its gas up front (refunded afterwards).
  near_require_balance "$NEAR_ACCOUNT_ID" "$NEAR_PARENT_JSON" \
    "$(int_calc "$BALANCE + $TX_FEE_MARGIN_YOCTO + $(near_gas_purchase_yocto "$NEAR_CALL_GAS")")" \
    "creating $ACCT with $(fmt_near "$BALANCE") and registering its key"
  near_tx "Create $ACCT ($(fmt_near "$BALANCE"))" "$(near_signer_keyfile "$NEAR_ACCOUNT_ID")" \
    account create-account fund-myself "$ACCT" "$BALANCE yoctoNEAR" \
    use-manually-provided-public-key "$NEAR_SIGNER_PUBLIC_KEY" sign-as "$NEAR_ACCOUNT_ID" ||
    die "creating $ACCT failed"
  nur account "$ACCT" --wait-exists --timeout 60 >/dev/null || die "$ACCT did not appear at final"
  nur access-key "$ACCT" "$NEAR_SIGNER_PUBLIC_KEY" --wait --timeout 60 >/dev/null ||
    die "the key of $ACCT did not appear at final"
  CREATED=1
else
  log "    $ACCT exists ($(fmt_near "$(jget "$A" amount)"), available $(fmt_near "$(near_available "$A")"))"
  if [ "$(int_calc "$(near_available "$A") < $TX_FEE_MARGIN_YOCTO")" = 1 ]; then
    warn "$ACCT has almost no balance left for its own gas; top it up: scripts/near/transfer.sh $ACCT 0.5 --yes"
  fi
fi

# 2. the keypair
if [ -f "$KEYFILE" ]; then
  INFO=$(nu keyfile-info "$KEYFILE") || die "stored key file $KEYFILE is invalid"
  PK=$(jget "$INFO" public_key)
  [ "$(jget "$INFO" account_id)" = "$ACCT" ] || die "$KEYFILE is for $(jget "$INFO" account_id), not $ACCT"
  [ "$(jget "$INFO" mode)" = 0600 ] || warn "$KEYFILE has mode $(jget "$INFO" mode); expected 0600"
  KF_CONTRACT=$(jget "$INFO" contract_id)
  KF_REG=$(jget "$INFO" registration_id)
  if [ "$KF_CONTRACT" != null ] && [ "$KF_CONTRACT" != "$APPROVAL_CONTRACT_ID" ]; then
    die "The stored key $KEYFILE was registered in $KF_CONTRACT, not $APPROVAL_CONTRACT_ID." "$(separate_dir_hint "$KF_CONTRACT")"
  fi
  if [ "$KF_CONTRACT" = "$APPROVAL_CONTRACT_ID" ] && [ "$KF_REG" != null ]; then
    require_uint "registration_id in $KEYFILE" "$KF_REG"
    REV=$(near_view get_revocation "$(nu json-build registration_id:="$KF_REG")") || die "get_revocation failed"
    if [ "$REV" != null ]; then
      die "The stored key $PK (registration $KF_REG) was revoked at block $(jget "$REV" block)." \
        "Remove or rename $KEYFILE to generate a new key (revoke-key.sh does that for you)."
    fi
  fi
  log "    reusing stored $ROLE key $PK ($KEYFILE)"
else
  near_cli_init
  GEN="$NEAR_TMP/generated"
  rm -rf "$GEN"
  # Offline. near-cli writes the file (with a seed phrase) 0644 by default:
  # keep it inside the private temp dir, under umask 077, and delete it.
  (umask 077 && near_run account create-account fund-later use-auto-generation save-to-folder "$GEN") ||
    die "near-cli keypair generation failed: $(cat "$NEAR_TMP/err")"
  set -- "$GEN"/*.json
  [ $# -eq 1 ] && [ -f "$1" ] || die "expected one generated key file in $GEN"
  mkdir -p "$(dirname "$KEYFILE")"
  chmod 700 "$NEAR_CREDENTIALS_DIR" "$(dirname "$KEYFILE")" 2>/dev/null || true
  PK=$(nu convert-keyfile --in "$1" --account "$ACCT" --out "$KEYFILE") || die "could not store the new key"
  rm -rf "$GEN"
  ok "generated $ROLE key $PK, stored in $KEYFILE (0600)"
fi

# 3. the function-call access key
KRC=0
check_principal_access_key "$ACCT" "$ROLE" "$PK" || KRC=$?
if [ "$KRC" = 0 ]; then
  log "    $PK is already a function-call key of $ACCT for $APPROVAL_CONTRACT_ID [$METHODS]"
elif [ "$KRC" = 2 ]; then
  RECV=$(jget "$PRINCIPAL_KEY_JSON" receiver_id)
  if [ "$(jget "$PRINCIPAL_KEY_JSON" permission)" = FunctionCall ] && [ "$RECV" != "$APPROVAL_CONTRACT_ID" ]; then
    die "$PK is already on $ACCT as a function-call key for $RECV." "$(separate_dir_hint "$RECV")"
  fi
  die "$PK is already on $ACCT with a different permission (see above)." \
    "Delete it (scripts/near/revoke-key.sh $PK --delete-access-key --account $ACCT) to generate a new key."
else
  if [ "$CREATED" = 0 ] && [ "$(int_calc "$(near_available "$(near_account "$ACCT")") < $TX_FEE_MARGIN_YOCTO")" = 1 ]; then
    die "$ACCT cannot pay for adding its key (available $(fmt_near "$(near_available "$(near_account "$ACCT")")"))." \
      "Top it up first: scripts/near/transfer.sh $ACCT 0.5 --yes"
  fi
  near_require_full_access "$ACCT"
  near_tx "Add function-call key to $ACCT ($APPROVAL_CONTRACT_ID: $METHODS)" "$(near_signer_keyfile "$ACCT")" \
    account add-key "$ACCT" grant-function-call-access --allowance unlimited \
    --contract-account-id "$APPROVAL_CONTRACT_ID" --function-names "$METHODS" \
    use-manually-provided-public-key "$PK" || die "adding the access key failed"
  nur access-key "$ACCT" "$PK" --wait --timeout 60 >/dev/null || die "the new key did not appear at final"
fi

# 4. the registration
register_principal "$ROLE" "$ACCT" "$PK"
REG=$(jget "$PRINCIPAL_JSON" registration_id)
require_uint registration_id "$REG"
# Bookkeeping in the key file (near-cli ignores extra fields): lets a later
# run notice that this registration was revoked.
nu keyfile-set "$KEYFILE" contract_id="$APPROVAL_CONTRACT_ID" role="$ROLE" registration_id:="$REG" ||
  warn "could not note the registration in $KEYFILE"

nu json-build account_id="$ACCT" role="$ROLE" public_key="$PK" key_file="$KEYFILE" \
  registration_id:="$(jget "$PRINCIPAL_JSON" registration_id)" | nu json-pretty
