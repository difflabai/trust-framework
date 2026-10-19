#!/usr/bin/env bash
# Usage: scripts/near/status.sh [--wasm PATH] [--min-available NEAR] [--check]
#
# Read-only overview of the configured network: the parent account
# (NEAR_ACCOUNT_ID), the contract account (APPROVAL_CONTRACT_ID), whether
# its code_hash matches the local wasm and the deployment record, the
# contract's owner and counters, and the principal keys stored under
# NEAR_CREDENTIALS_DIR. Before the first deploy it says how much the parent
# needs. Sends nothing. Works without NEAR_PRIVATE_KEY (the key checks are
# then skipped).
#
# Warns when the contract's available (unstaked) balance is below 0.5 NEAR:
# it pays for every request and approval stored.
#
# Options:
#   --wasm PATH           local wasm to compare against (default:
#                         APPROVAL_WASM or build-wasm.sh's output)
#   --min-available NEAR  low-balance threshold for the contract (default
#                         0.5); implies --check
#   --check               for cron/CI: exit 3 if anything needs attention
#                         (contract missing or without code, low contract
#                         balance, owner != APPROVAL_OWNER_ID, deployed
#                         code_hash != the deployment record)
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

WASM="" MIN_AVAIL_ARG="" CHECK=0
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --wasm)
      [ $# -gt 1 ] || usage_error "--wasm needs a path"
      WASM=$2
      shift
      ;;
    --min-available)
      [ $# -gt 1 ] || usage_error "--min-available needs an amount"
      MIN_AVAIL_ARG=$2
      CHECK=1
      shift
      ;;
    --check) CHECK=1 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done

MIN_AVAIL=$(yocto "${MIN_AVAIL_ARG:-0.5}") || usage_error "bad --min-available '$MIN_AVAIL_ARG'"
near_load_config
# --wasm is relative to the current directory, APPROVAL_WASM to the repo root.
if [ -n "$WASM" ]; then
  case $WASM in /*) ;; *) WASM="$PWD/$WASM" ;; esac
else
  WASM=${APPROVAL_WASM:-$DEFAULT_WASM}
fi

out() { printf '%s\n' "$*"; }
PROBLEMS=""
problem() {
  PROBLEMS="$PROBLEMS  - $*"$'\n'
}
HAVE_KEY=0
if near_derive_signer; then HAVE_KEY=1; fi
PRICE=$(near_storage_price)

out "Network     $NEAR_NETWORK  ($NEAR_RPC_URL, chain_id $NEAR_CHAIN_ID)"
out "Env file    $ENV_FILE$([ -f "$ENV_FILE" ] || echo ' (not found)')"
if [ "$HAVE_KEY" = 1 ]; then
  out "Signer key  $NEAR_SIGNER_PUBLIC_KEY (from NEAR_PRIVATE_KEY)"
else
  out "Signer key  (NEAR_PRIVATE_KEY not set: key checks skipped)"
fi
out "Storage     $PRICE yoctoNEAR/byte ($(fmt_near "$(int_calc "$PRICE * 100000")" --digits 3) per 100 KB)"

# show_account TITLE ACCOUNT -> prints, sets ACC_JSON
show_account() {
  local title=$1 acct=$2 usage amount locked
  out ""
  out "$title  $acct"
  ACC_JSON=$(near_account "$acct")
  if [ "$(jget "$ACC_JSON" exists)" != true ]; then
    out "  exists          no"
    return
  fi
  amount=$(jget "$ACC_JSON" amount)
  locked=$(jget "$ACC_JSON" locked)
  usage=$(jget "$ACC_JSON" storage_usage)
  out "  balance         $(fmt_near "$amount")"
  [ "$locked" = 0 ] || out "  locked (stake)  $(fmt_near "$locked")"
  if [ "$(int_calc "$usage > $ZBA_STORAGE_LIMIT")" = 1 ]; then
    out "  storage         $usage bytes, staking $(fmt_near "$(near_storage_stake "$usage")" --round up)"
  else
    out "  storage         $usage bytes, staking 0 NEAR (zero-balance account, <= $ZBA_STORAGE_LIMIT bytes)"
  fi
  out "  available       $(fmt_near "$(near_available "$ACC_JSON")")"
  if [ "$HAVE_KEY" = 1 ]; then
    local k
    k=$(near_key_permission "$acct" "$NEAR_SIGNER_PUBLIC_KEY")
    if [ "$(jget "$k" exists)" = true ]; then
      out "  signer key      $(jget "$k" permission) key of this account"
    else
      out "  signer key      NOT a key of this account"
    fi
  fi
}

show_account "Parent  " "$NEAR_ACCOUNT_ID"
P=$ACC_JSON

show_account "Contract" "$APPROVAL_CONTRACT_ID"
C=$ACC_JSON
DEPLOYED=0
if [ "$(jget "$C" exists)" != true ]; then
  problem "$APPROVAL_CONTRACT_ID does not exist"
  # What the first deploy will need from the parent (deploy.sh's formula).
  if [ -n "${APPROVAL_INITIAL_BALANCE:-}" ]; then
    FIRST=$(yocto "$APPROVAL_INITIAL_BALANCE") || die "bad APPROVAL_INITIAL_BALANCE '$APPROVAL_INITIAL_BALANCE'"
  elif [ -f "$WASM" ]; then
    FIRST=$(int_calc "cdiv(($(jget "$(nu hash-file "$WASM")" size) + 400) * $PRICE + $ONE_NEAR_YOCTO, $ONE_NEAR_YOCTO) * $ONE_NEAR_YOCTO")
  else
    FIRST=$(yocto 3)
  fi
  FIRST=$(int_calc "$FIRST + $TX_FEE_MARGIN_YOCTO")
  out "  first deploy    needs ~$(fmt_near "$FIRST" --round up) from $NEAR_ACCOUNT_ID (initial balance + fees); principals ~0.55 NEAR each"
  if [ "$(jget "$P" exists)" = true ]; then
    PAVAIL=$(near_available "$P")
    if [ "$(int_calc "$PAVAIL < $FIRST")" = 1 ]; then
      out "  note            $NEAR_ACCOUNT_ID is short by $(fmt_near "$(int_calc "$FIRST - $PAVAIL")" --round up)"
      near_fund_hint "$NEAR_ACCOUNT_ID" | sed 's/^/                  /'
    fi
  else
    near_fund_hint "$NEAR_ACCOUNT_ID" | sed 's/^/                  /'
  fi
else
  CAVAIL=$(near_available "$C")
  if [ "$(int_calc "$CAVAIL < $MIN_AVAIL")" = 1 ]; then
    out "  WARNING         low storage balance (available $(fmt_near "$CAVAIL") < $(fmt_near "$MIN_AVAIL")): new requests and approvals will fail when it runs out"
    out "                  top up: scripts/near/transfer.sh $APPROVAL_CONTRACT_ID 2 --yes"
    problem "$APPROVAL_CONTRACT_ID has only $(fmt_near "$CAVAIL") available"
  fi
  code_hash=$(jget "$C" code_hash)
  if [ "$code_hash" = "$EMPTY_CODE_HASH" ]; then
    out "  code            none"
    problem "$APPROVAL_CONTRACT_ID has no contract code"
  else
    DEPLOYED=1
    out "  code_hash       $code_hash"
  fi
  full=$(nur access-keys "$APPROVAL_CONTRACT_ID" | "$NEAR_PYTHON" -I -X utf8 -c '
import json, sys
keys = json.load(sys.stdin)
print(sum(1 for k in keys if k.get("permission") == "FullAccess"))')
  if [ "$full" = 0 ]; then
    out "  full-access keys 0 (locked: nobody can redeploy or delete it)"
  else
    out "  full-access keys $full (anyone holding one can redeploy the contract; lock-contract.sh removes them)"
  fi
fi

if [ -f "$WASM" ]; then
  H=$(nu hash-file "$WASM")
  local_hash=$(jget "$H" code_hash)
  out ""
  out "Local wasm  $WASM"
  out "  code_hash       $local_hash (sha256 $(jget "$H" sha256))"
  META="${WASM%.wasm}.build.json"
  if [ -f "$META" ] && [ "$(jget "$(cat "$META")" sha256)" = "$(jget "$H" sha256)" ]; then
    M=$(cat "$META")
    out "  source          $(jget "$M" source_commit) ($(jget "$M" mode)$([ "$(jget "$M" ci_run_id)" = null ] || echo ", CI run $(jget "$M" ci_run_id)"))"
  fi
  if [ "$DEPLOYED" = 1 ]; then
    if [ "$local_hash" = "$code_hash" ]; then
      out "  matches deployed  yes"
    else
      out "  matches deployed  NO (deployed $code_hash)"
    fi
  fi
else
  out ""
  out "Local wasm  $WASM (not found; scripts/near/build-wasm.sh fetches it)"
fi

REC="$NEAR_DEPLOYMENTS_DIR/$NEAR_NETWORK/$APPROVAL_CONTRACT_ID.json"
if [ -f "$REC" ]; then
  R=$(cat "$REC")
  out ""
  out "Record      $REC"
  out "  code_hash       $(jget "$R" code_hash) from $(jget "$R" source_commit) at $(jget "$R" deployed_at)"
  if [ "$DEPLOYED" = 1 ]; then
    if [ "$(jget "$R" code_hash)" = "$code_hash" ]; then
      out "  matches deployed  yes"
    else
      out "  matches deployed  NO (deployed $code_hash)"
      problem "deployed code_hash $code_hash differs from the deployment record"
    fi
  fi
fi

if [ "$DEPLOYED" = 1 ]; then
  out ""
  out "Contract state"
  if owner=$(near_view get_owner 2>"$NEAR_TMP/view.err"); then
    note=""
    if [ "$owner" != "$APPROVAL_OWNER_ID" ]; then
      note="  (APPROVAL_OWNER_ID is $APPROVAL_OWNER_ID!)"
      problem "get_owner is $owner, not APPROVAL_OWNER_ID=$APPROVAL_OWNER_ID"
    fi
    out "  get_owner          $owner$note"
    out "  get_request_count  $(near_view get_request_count)"
    out "  get_approval_count $(near_view get_approval_count)"
  else
    out "  get_owner          failed: $(cat "$NEAR_TMP/view.err")"
    problem "get_owner failed"
  fi

  dir="$NEAR_CREDENTIALS_DIR/$NEAR_NETWORK"
  found=0
  if [ -d "$dir" ]; then
    for f in "$dir"/*.agent.json "$dir"/*.approver.json; do
      [ -f "$f" ] || continue
      if [ "$found" = 0 ]; then
        out ""
        out "Stored principal keys ($dir)"
        found=1
      fi
      base=$(basename "$f" .json)
      role=${base##*.}
      acct=${base%.*}
      info=$(nu keyfile-info "$f" 2>/dev/null) || {
        out "  $acct ($role): invalid key file $f"
        continue
      }
      pk=$(jget "$info" public_key)
      p=$(near_view get_principal "$(nu json-build public_key="$pk")" 2>/dev/null || echo error)
      if [ "$p" = null ]; then
        reg="not registered"
        k=$(nur access-key "$acct" "$pk" 2>/dev/null || echo '{}')
        kc=$(jget "$info" contract_id)
        kr=$(jget "$info" registration_id)
        if [ "$(jget "$k" permission)" = FunctionCall ] && [ "$(jget "$k" receiver_id)" != "$APPROVAL_CONTRACT_ID" ]; then
          reg="scoped to $(jget "$k" receiver_id) (another contract instance)"
        elif [ "$kc" != null ] && [ "$kc" != "$APPROVAL_CONTRACT_ID" ]; then
          reg="registered in $kc (another contract instance)"
        elif [ "$kr" != null ] && [ "$(near_view get_revocation "$(nu json-build registration_id:="$kr")" 2>/dev/null || echo null)" != null ]; then
          reg="REVOKED (registration $kr); new-principal.sh will refuse it, remove the file"
        fi
      elif [ "$p" = error ]; then
        reg="get_principal failed"
      else
        reg="registered as $(jget "$p" role) of $(jget "$p" account_id) (registration $(jget "$p" registration_id), pending $(jget "$p" pending))"
      fi
      out "  $acct ($role) $pk: $reg"
    done
  fi
fi

if [ -n "$PROBLEMS" ]; then
  out ""
  out "Needs attention"
  printf '%s' "$PROBLEMS"
  [ "$CHECK" = 0 ] || exit 3
fi
