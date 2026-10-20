#!/usr/bin/env bash
# Usage: scripts/near/faucet-fund.sh [<receiver>] [--rounds N]
#        scripts/near/faucet-fund.sh [<receiver>] --recover <key_file>
#
# Top up an existing testnet account (default NEAR_ACCOUNT_ID) from the
# testnet faucet. The faucet only funds NEW accounts (10 NEAR each), so each
# round:
#   1. generates a throwaway keypair (offline, in the private temp dir)
#   2. has the faucet create tf-faucet-<time>-<random>.testnet with it
#   3. deletes that account with <receiver> as beneficiary, which moves its
#      whole balance to <receiver>
# No NEAR_PRIVATE_KEY is needed: the throwaway account signs its own
# deletion. Testnet only. The faucet is NEAR_FAUCET_URL (default
# https://helper.testnet.near.org/account).
#
# If a deletion fails, the throwaway key is kept at
# <NEAR_CREDENTIALS_DIR>/testnet/<account>.faucet.json (0600) and the
# command to finish the round is printed (--recover).
#
# Options:
#   --rounds N         faucet rounds, 1 to 5 (default 1)
#   --recover KEYFILE  delete the throwaway account in KEYFILE into <receiver>
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

POS=() ROUNDS=1 RECOVER=""
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --rounds)
      [ $# -gt 1 ] || usage_error "--rounds needs a number"
      ROUNDS=$2
      shift
      ;;
    --recover)
      [ $# -gt 1 ] || usage_error "--recover needs a key file"
      RECOVER=$2
      shift
      ;;
    -*) usage_error "unknown option '$1'" ;;
    *) POS+=("$1") ;;
  esac
  shift
done
[ "${#POS[@]}" -le 1 ] || usage_error "expected at most one <receiver>"
case $ROUNDS in [1-5]) ;; *) usage_error "--rounds must be 1 to 5 (got '$ROUNDS')" ;; esac

near_load_config
[ "$NEAR_NETWORK" = testnet ] || die "The faucet exists only on testnet (NEAR_NETWORK=$NEAR_NETWORK)."
RECEIVER=${POS[0]:-$NEAR_ACCOUNT_ID}
require_account_id receiver "$RECEIVER"

# A deleted account's balance sent to a missing beneficiary is burnt.
R=$(near_account "$RECEIVER")
[ "$(jget "$R" exists)" = true ] || die "$RECEIVER does not exist on testnet; its faucet funds would be burnt."
BEFORE=$(jget "$R" amount)
require_uint "balance of $RECEIVER" "$BEFORE"
log "    $RECEIVER balance $(fmt_near "$BEFORE")"

# delete_into KEYFILE ACCOUNT: delete the throwaway ACCOUNT (signed by its
# own key) with RECEIVER as beneficiary. On failure, keep the key so the
# round can be finished with --recover.
delete_into() {
  local keyfile=$1 acct=$2 keep
  if near_tx "Delete $acct, beneficiary $RECEIVER" "$keyfile" \
    account delete-account "$acct" beneficiary "$RECEIVER"; then
    nur account "$acct" --wait-gone --timeout 60 >/dev/null || warn "$acct still shows as existing"
    return 0
  fi
  keep="$NEAR_CREDENTIALS_DIR/testnet/$acct.faucet.json"
  if [ "$keyfile" != "$keep" ]; then
    mkdir -p "$(dirname "$keep")"
    chmod 700 "$NEAR_CREDENTIALS_DIR" "$(dirname "$keep")" 2>/dev/null || true
    nu convert-keyfile --in "$keyfile" --account "$acct" --out "$keep" >/dev/null ||
      die "could not keep the key of $acct; its balance is stranded"
  fi
  die "Deleting $acct failed; its key is kept in $keep." \
    "Finish the round with: scripts/near/faucet-fund.sh $RECEIVER --recover $keep"
}

if [ -n "$RECOVER" ]; then
  case $RECOVER in /*) ;; *) RECOVER="$PWD/$RECOVER" ;; esac
  [ -f "$RECOVER" ] || die "no key file $RECOVER"
  INFO=$(nu keyfile-info "$RECOVER") || die "$RECOVER is not a key file"
  ACCT=$(jget "$INFO" account_id)
  A=$(near_account "$ACCT")
  [ "$(jget "$A" exists)" = true ] || die "$ACCT no longer exists; nothing to recover."
  near_cli_init
  delete_into "$RECOVER" "$ACCT"
  rm -f "$RECOVER"
  ok "recovered $(fmt_near "$(jget "$A" amount)") from $ACCT"
  exit 0
fi

near_cli_init
round=1
while [ "$round" -le "$ROUNDS" ]; do
  ACCT="tf-faucet-$(date +%s)-$RANDOM$RANDOM.testnet"
  GEN="$NEAR_TMP/generated"
  rm -rf "$GEN"
  # Offline. near-cli writes the file (with a seed phrase) 0644 by default:
  # keep it inside the private temp dir, under umask 077.
  (umask 077 && near_run account create-account fund-later use-auto-generation save-to-folder "$GEN") ||
    die "near-cli keypair generation failed: $(cat "$NEAR_TMP/err")"
  set -- "$GEN"/*.json
  [ $# -eq 1 ] && [ -f "$1" ] || die "expected one generated key file in $GEN"
  KEYFILE="$NEAR_TMP/faucet.$ACCT.json"
  PK=$(nu convert-keyfile --in "$1" --account "$ACCT" --out "$KEYFILE") || die "could not convert the generated key"
  rm -rf "$GEN"

  info "Round $round/$ROUNDS: faucet creates $ACCT"
  if ! near_run account create-account sponsor-by-faucet-service "$ACCT" \
    use-manually-provided-public-key "$PK" network-config testnet create; then
    printf '%serror:%s the faucet did not create %s. near-cli output:\n' "$C_RED" "$C_OFF" "$ACCT" >&2
    nu cli-error <"$NEAR_TMP/err" | sed 's/^/    | /' >&2
    die "The faucet may be rate-limiting or down; try again later or use https://near-faucet.io/."
  fi
  A=$(nur account "$ACCT" --wait-exists --timeout 60) || die "$ACCT did not appear within 60 s"
  GOT=$(jget "$A" amount)
  require_uint "balance of $ACCT" "$GOT"
  log "    $ACCT received $(fmt_near "$GOT")"
  delete_into "$KEYFILE" "$ACCT"
  round=$((round + 1))
done

# The beneficiary transfer lands a block after the deletion.
i=0 AFTER=$BEFORE
while [ "$i" -lt 30 ]; do
  AFTER=$(jget "$(near_account "$RECEIVER")" amount)
  require_uint "balance of $RECEIVER" "$AFTER"
  [ "$(int_calc "$AFTER > $BEFORE")" = 1 ] && break
  sleep 1
  i=$((i + 1))
done
[ "$(int_calc "$AFTER > $BEFORE")" = 1 ] || die "$RECEIVER's balance has not grown yet; check it with scripts/near/status.sh"
ok "$RECEIVER: $(fmt_near "$BEFORE") -> $(fmt_near "$AFTER") (+$(fmt_near "$(int_calc "$AFTER - $BEFORE")"))"
