#!/usr/bin/env bash
# Usage: scripts/near/revoke-key.sh <public_key> [--delete-access-key] [--account ACCOUNT]
#
# Revoke a registered agent/approver key (revoke_key, signed by the owner).
# Pending requests made with an agent key become void permanently; existing
# approvals stay but report the revocation (get_approval: *_key_revoked_at).
# Prints the revocation record ({block, ns}) on stdout (null if the key was
# not registered).
#
# The stored key file (<NEAR_CREDENTIALS_DIR>/<network>/<account>.<role>.json)
# is retired: renamed to <account>.<role>.revoked-<registration>.json, so the
# next new-principal.sh for that account generates a fresh key instead of
# re-registering the revoked one.
#
# revoke_key only changes the contract's registry: the key remains an access
# key of its account. With --delete-access-key the key is also deleted from
# that account (needs NEAR_PRIVATE_KEY to be a full-access key there, as for
# principals made by new-principal.sh) and its key file is removed instead
# of renamed. That also works for a key that is no longer registered: its
# account comes from --account, else from the stored key files.
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

PK="" DELETE_KEY=0 ACCT_ARG=""
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --delete-access-key) DELETE_KEY=1 ;;
    --account)
      [ $# -gt 1 ] || usage_error "--account needs an account id"
      ACCT_ARG=$2
      shift
      ;;
    -*) usage_error "unknown option '$1'" ;;
    *)
      [ -z "$PK" ] || usage_error "unexpected argument '$1'"
      PK=$1
      ;;
  esac
  shift
done
[ -n "$PK" ] || usage_error "missing <public_key>"
[ -z "$ACCT_ARG" ] || [ "$DELETE_KEY" = 1 ] || usage_error "--account only applies with --delete-access-key"

near_load_config
[ -z "$ACCT_ARG" ] || ACCT_ARG=$(principal_account "$ACCT_ARG")
near_require_owner
PKARGS=$(nu json-build public_key="$PK") || die "could not encode the public key"
CUR=$(near_view get_principal "$PKARGS") || die "get_principal failed (is '$PK' a valid public key?)"
CRED_DIR="$NEAR_CREDENTIALS_DIR/$NEAR_NETWORK"

# stored_keyfiles PK [ACCOUNT]: stored key files (current or retired) holding PK.
stored_keyfiles() {
  local f info
  [ -d "$CRED_DIR" ] || return 0
  for f in "$CRED_DIR"/*.json; do
    [ -f "$f" ] || continue
    info=$(nu keyfile-info "$f" 2>/dev/null) || continue
    [ "$(jget "$info" public_key)" = "$1" ] || continue
    [ -z "${2:-}" ] || [ "$(jget "$info" account_id)" = "$2" ] || continue
    printf '%s\n' "$f"
  done
}

# remove_keyfiles ACCOUNT: delete the stored key files holding PK for ACCOUNT.
remove_keyfiles() {
  local f
  stored_keyfiles "$PK" "$1" >"$NEAR_TMP/keyfiles"
  while IFS= read -r f; do
    rm -f "$f"
    ok "removed $f"
  done <"$NEAR_TMP/keyfiles"
}

# rotate_hint ACCOUNT ROLE: how to make the replacement key, keeping a
# narrowed scope (KEY_SCOPE, read before the key was deleted).
KEY_SCOPE=""
rotate_hint() {
  local m=""
  if [ -n "$KEY_SCOPE" ] && [ "$KEY_SCOPE" != "$(role_methods "$2")" ] && methods_subset "$2" "$KEY_SCOPE"; then
    m=" --methods $KEY_SCOPE"
  fi
  log "    (a new key: scripts/near/new-principal.sh $1 $2$m)"
}
# env_hint: warn when ENV_FILE still holds PK as a principal key; the
# signing scripts fall back to it.
env_hint() {
  local r pfx pv kv epk
  for r in agent approver; do
    pfx=$(principal_env_prefix "$r")
    pv=${pfx}_PUBLIC_KEY kv=${pfx}_PRIVATE_KEY
    epk=${!pv:-}
    if [ -z "$epk" ]; then
      { xtrace_off; } 2>/dev/null
      if [ -n "${!kv:-}" ]; then epk=$(printf '%s' "${!kv}" | nu pubkey 2>/dev/null || true); fi
      xtrace_on
    fi
    if [ "$epk" = "$PK" ]; then
      warn "$ENV_FILE still holds this key as ${pfx}_*. Remove those lines, or after new-principal.sh run" \
        "scripts/near/principal-env.sh <account> $r --replace"
    fi
  done
}
# delete_access_key ACCOUNT: delete PK from ACCOUNT's access keys.
delete_access_key() {
  local acct=$1 k
  k=$(near_key_permission "$acct" "$PK")
  if [ "$(jget "$k" permission)" = FunctionCall ]; then KEY_SCOPE=$(key_methods "$k"); fi
  if [ "$(jget "$k" exists)" = true ]; then
    near_require_full_access "$acct"
    near_tx "Delete access key $PK from $acct" "$(near_signer_keyfile "$acct")" \
      account delete-keys "$acct" public-keys "$PK" || die "deleting the access key failed"
    nur access-key "$acct" "$PK" --wait-gone --timeout 60 >/dev/null || die "the key is still on $acct at final"
    ok "deleted the access key from $acct"
  else
    log "    $PK is not an access key of $acct (nothing to delete)"
  fi
}

if [ "$CUR" = null ]; then
  ok "$PK is not registered in $APPROVAL_CONTRACT_ID; nothing to revoke."
  if [ "$DELETE_KEY" = 1 ]; then
    ACCT=$ACCT_ARG
    if [ -z "$ACCT" ]; then
      f=$(stored_keyfiles "$PK" | head -n 1)
      [ -z "$f" ] || ACCT=$(jget "$(nu keyfile-info "$f")" account_id)
    fi
    [ -n "$ACCT" ] && [ "$ACCT" != null ] ||
      die "--delete-access-key: no stored key file holds $PK, so its account is unknown." \
        "Pass it: scripts/near/revoke-key.sh $PK --delete-access-key --account <account>"
    delete_access_key "$ACCT"
    remove_keyfiles "$ACCT"
  fi
  env_hint
  printf 'null\n'
  exit 0
fi
ACCT=$(jget "$CUR" account_id)
ROLE=$(jget "$CUR" role)
REG=$(jget "$CUR" registration_id)
require_uint registration_id "$REG"
[ -z "$ACCT_ARG" ] || [ "$ACCT_ARG" = "$ACCT" ] || die "$PK is registered for $ACCT, not --account $ACCT_ARG."
log "    $PK: $ROLE of $ACCT, registration $REG, pending $(jget "$CUR" pending)"
near_require_owner_call_balance revoke_key
near_call "$NEAR_ACCOUNT_ID" "$(near_signer_keyfile "$NEAR_ACCOUNT_ID")" revoke_key "$PKARGS" \
  "Revoke $ROLE key of $ACCT" || die "revoke_key failed"
near_view get_principal "$PKARGS" --wait-equals null --timeout 60 >/dev/null ||
  die "the revocation did not become visible at final"
REV=$(near_view get_revocation "$(nu json-build registration_id:="$REG")")
ok "revoked registration $REG of $ACCT at block $(jget "$REV" block)"

if [ "$DELETE_KEY" = 1 ]; then
  delete_access_key "$ACCT"
  remove_keyfiles "$ACCT"
  rotate_hint "$ACCT" "$ROLE"
else
  F=$(principal_keyfile "$ACCT" "$ROLE")
  if [ -f "$F" ] && [ "$(jget "$(nu keyfile-info "$F")" public_key)" = "$PK" ]; then
    R="${F%.json}.revoked-$REG.json"
    mv "$F" "$R"
    ok "retired the stored key file: $R"
    log "    (the next 'scripts/near/new-principal.sh $ACCT $ROLE' generates a new key, with the same methods)"
  fi
  if [ "$(jget "$(near_key_permission "$ACCT" "$PK")" exists)" = true ]; then
    log "    The key is still an access key of $ACCT. To delete it too:"
    log "      scripts/near/revoke-key.sh $PK --delete-access-key --account $ACCT"
  fi
fi
env_hint
printf '%s\n' "$REV" | nu json-pretty
