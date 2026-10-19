#!/usr/bin/env bash
# Usage: scripts/near/deploy.sh [--wasm PATH] [--initial-balance NEAR] [--upgrade | --fresh] [--dry-run] [--yes]
#
# Idempotently deploy the approval contract to APPROVAL_CONTRACT_ID
# (default approvals.<NEAR_ACCOUNT_ID>), owned by APPROVAL_OWNER_ID
# (default NEAR_ACCOUNT_ID). Signs with NEAR_PRIVATE_KEY, a full-access key
# of NEAR_ACCOUNT_ID.
#
#   contract account missing  -> create it as a subaccount of NEAR_ACCOUNT_ID,
#                                funded with the initial balance, whose
#                                full-access key is the same key as the
#                                parent's; then deploy + init new(owner_id)
#                                in one transaction signed by the contract
#                                account itself (new is #[private])
#   account exists, no code   -> deploy + init
#   same code already there   -> verify get_owner, record, exit 0
#   different code            -> refuse, unless --upgrade or --fresh
#
# After a deploy, waits for finality, checks code_hash and get_owner over
# RPC and writes <NEAR_DEPLOYMENTS_DIR>/<network>/<contract>.json.
#
# Options:
#   --wasm PATH             wasm to deploy (default: build-wasm.sh's output,
#                           or APPROVAL_WASM)
#   --initial-balance NEAR  balance for a newly created contract account
#                           (default APPROVAL_INITIAL_BALANCE, else computed:
#                           wasm storage + overhead + 1 NEAR headroom,
#                           rounded up to whole NEAR; 3 NEAR for ~164 KB).
#                           Must also cover the gas the deploy + init
#                           transaction buys up front (~0.05 NEAR, mostly
#                           refunded afterwards).
#   --upgrade               replace different code without calling init. No
#                           state migration exists: the new code must read
#                           the existing state layout.
#   --fresh                 delete the contract account (all requests,
#                           approvals and registrations are lost) and
#                           recreate it. Only possible while its non-code
#                           state is <= 10,000 bytes (NEAR refuses to delete
#                           accounts with more: DeleteAccountWithLargeState),
#                           so in practice only right after a deploy.
#   --dry-run               preflight and print the plan; send nothing. Works
#                           without NEAR_PRIVATE_KEY (the key checks are then
#                           skipped), to see what the first deploy costs.
#   --yes                   don't ask for confirmation (--upgrade, --fresh)
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

WASM=""
INIT_BALANCE_ARG=""
UPGRADE=0
FRESH=0
DRY_RUN=0
ASSUME_YES=0
# shellcheck disable=SC2034 # ASSUME_YES is read by confirm() in lib.sh
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
    --initial-balance)
      [ $# -gt 1 ] || usage_error "--initial-balance needs an amount"
      INIT_BALANCE_ARG=$2
      shift
      ;;
    --upgrade) UPGRADE=1 ;;
    --fresh) FRESH=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --yes | -y) ASSUME_YES=1 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done
[ "$UPGRADE$FRESH" != 11 ] || usage_error "--upgrade and --fresh are mutually exclusive"

near_load_config
near_print_config
HAVE_KEY=1
if [ "$DRY_RUN" = 1 ]; then
  near_derive_signer || HAVE_KEY=0
  [ "$HAVE_KEY" = 1 ] || warn "NEAR_PRIVATE_KEY is not set: dry run without the key checks."
else
  near_require_signer
fi
CONTRACT=$APPROVAL_CONTRACT_ID
# Bytes beyond the wasm that a fresh deploy+init needs: account record (100),
# the full-access key (~82) and the initial contract state (~100). Measured
# total: 284. Rounded up for margin.
DEPLOY_OVERHEAD_BYTES=400
# NEAR refuses DeleteAccount when storage_usage minus the code length exceeds this.
MAX_DELETE_STATE_BYTES=10000
ONE_NEAR=$ONE_NEAR_YOCTO
# Gas attached to the init call `new` (it burns ~1.5 Tgas). Since protocol 85
# the attached gas and the execution fees of the receipt's actions are
# bought up front at >= 1e9 yoctoNEAR/gas and the unused part refunded, so
# the contract account must hold them on top of its storage while the
# transaction runs. Measured in the sandbox (protocol 86): deploying the
# 167,622-byte wasm + init with 30 Tgas needs storage + 0.0421 NEAR.
DEPLOY_GAS="30 Tgas"

# --------------------------------------------------------------- the wasm
# --wasm is relative to the current directory; APPROVAL_WASM (already
# resolved by near_load_config) to the repo root.
if [ -n "$WASM" ]; then
  case $WASM in /*) ;; *) WASM="$PWD/$WASM" ;; esac
else
  WASM=${APPROVAL_WASM:-$DEFAULT_WASM}
fi
[ -f "$WASM" ] || die "wasm not found: $WASM" \
  "Fetch the CI-built reproducible wasm:  scripts/near/build-wasm.sh" \
  "or build it locally:                  scripts/near/build-wasm.sh --local"
H=$(nu hash-file "$WASM")
WASM_SHA256=$(jget "$H" sha256)
CODE_HASH=$(jget "$H" code_hash)
WASM_SIZE=$(jget "$H" size)
META="${WASM%.wasm}.build.json"
SRC_COMMIT="" SRC_REPO="" BUILD_MODE="" CI_RUN_ID="null" CI_RUN_URL=""
if [ -f "$META" ]; then
  M=$(cat "$META")
  if [ "$(jget "$M" sha256)" = "$WASM_SHA256" ]; then
    SRC_COMMIT=$(jget "$M" source_commit)
    SRC_REPO=$(jget "$M" source_repo)
    BUILD_MODE=$(jget "$M" mode)
    CI_RUN_ID=$(jget "$M" ci_run_id)
    CI_RUN_URL=$(jget "$M" ci_run_url)
  else
    warn "$META describes a different wasm (sha256 mismatch); ignoring it."
  fi
fi
info "Wasm $WASM"
log "    size $WASM_SIZE bytes, sha256 $WASM_SHA256"
log "    code_hash $CODE_HASH"
if [ -n "$SRC_COMMIT" ]; then
  log "    source commit $SRC_COMMIT ($BUILD_MODE build${CI_RUN_ID:+, CI run $CI_RUN_ID})"
else
  warn "No build metadata for this wasm: its source commit is unknown. Prefer scripts/near/build-wasm.sh."
fi

# --------------------------------------------------------------- preflight
PRICE=$(near_storage_price)
PARENT=$(near_account "$NEAR_ACCOUNT_ID")
if [ "$(jget "$PARENT" exists)" != true ]; then
  die "$NEAR_ACCOUNT_ID does not exist on $NEAR_NETWORK." "$(near_fund_hint "$NEAR_ACCOUNT_ID")"
fi
if [ "$HAVE_KEY" = 1 ]; then
  near_require_full_access "$NEAR_ACCOUNT_ID"
  ok "NEAR_PRIVATE_KEY is a full-access key of $NEAR_ACCOUNT_ID ($NEAR_SIGNER_PUBLIC_KEY)"
fi
log "    $NEAR_ACCOUNT_ID balance $(fmt_near "$(jget "$PARENT" amount)"), available $(fmt_near "$(near_available "$PARENT")")"
SIGNER_PK_SHOWN=${NEAR_SIGNER_PUBLIC_KEY:-<public key of NEAR_PRIVATE_KEY>}
# Execution gas of the deploy action (~65 Ggas per byte) and the function
# call, estimated generously.
DEPLOY_EXEC_TGAS=$(int_calc "cdiv($WASM_SIZE * 70000000, 1000000000000) + 3")
DEPLOY_GAS_HOLD=$(near_gas_purchase_yocto "$(int_calc "${DEPLOY_GAS%% *} + $DEPLOY_EXEC_TGAS") Tgas")
UPGRADE_GAS_HOLD=$(near_gas_purchase_yocto "$DEPLOY_EXEC_TGAS Tgas")
CALL_GAS_HOLD=$(near_gas_purchase_yocto "$NEAR_CALL_GAS")

# next_free_contract_name: approvals2.<parent>, approvals3, ... (not
# CONTRACT) that does not exist yet, for "deploy a new instance" hints.
next_free_contract_name() {
  local i=2 c
  while [ "$i" -le 11 ]; do
    c="approvals$i.$NEAR_ACCOUNT_ID"
    if [ "$c" != "$CONTRACT" ] && [ "$(jget "$(near_account "$c")" exists)" != true ]; then
      printf '%s\n' "$c"
      return 0
    fi
    i=$((i + 1))
  done
  printf '%s\n' "<name>.$NEAR_ACCOUNT_ID"
}
new_instance_hint() {
  local c
  c=$(next_free_contract_name)
  printf '%s\n' "  APPROVAL_CONTRACT_ID=$c NEAR_CREDENTIALS_DIR=.near-credentials-${c%%.*} scripts/near/deploy.sh" \
    "(a separate NEAR_CREDENTIALS_DIR keeps the new instance's principal keys apart: keys are scoped to one contract)"
}

CONTRACT_JSON=$(near_account "$CONTRACT")
DEPLOY_STORAGE=$(int_calc "($WASM_SIZE + $DEPLOY_OVERHEAD_BYTES) * $PRICE")
if [ -n "$INIT_BALANCE_ARG" ]; then
  INIT_BALANCE=$(yocto "$INIT_BALANCE_ARG") || usage_error "bad --initial-balance '$INIT_BALANCE_ARG'"
elif [ -n "${APPROVAL_INITIAL_BALANCE:-}" ]; then
  INIT_BALANCE=$(yocto "$APPROVAL_INITIAL_BALANCE") || die "bad APPROVAL_INITIAL_BALANCE '$APPROVAL_INITIAL_BALANCE'"
else
  INIT_BALANCE=$(int_calc "cdiv($DEPLOY_STORAGE + $ONE_NEAR, $ONE_NEAR) * $ONE_NEAR")
fi

PLAN=""
CMDS=""
plan() { PLAN="$PLAN  $((${PLAN_N:-0} + 1)). $*"$'\n'; PLAN_N=$((${PLAN_N:-0} + 1)); }
# cmd SIGNER ARGS...: record the near-cli command a step runs (shown by --dry-run).
cmd() {
  local signer=$1
  shift
  CMDS="$CMDS  near $* network-config $NEAR_NETWORK sign-with-access-key-file <0600 key file for $signer> send"$'\n'
}
BALANCE_OK=1
INIT_ARGS=$(nu json-build owner_id="$APPROVAL_OWNER_ID")
ACTION=""

contract_label=${CONTRACT%".$NEAR_ACCOUNT_ID"}
is_direct_subaccount() { [ "$contract_label" != "$CONTRACT" ] && case $contract_label in *.*) false ;; *) true ;; esac; }

plan_create() { # $1: extra yocto the parent gets back first (from --fresh)
  is_direct_subaccount ||
    die "$CONTRACT is not a direct subaccount of $NEAR_ACCOUNT_ID, so these scripts cannot create it." \
      "Create it yourself, or set APPROVAL_CONTRACT_ID=<name>.$NEAR_ACCOUNT_ID."
  local min_init
  min_init=$(int_calc "$DEPLOY_STORAGE + $DEPLOY_GAS_HOLD + $TX_FEE_MARGIN_YOCTO")
  if [ "$(int_calc "$INIT_BALANCE >= $min_init")" != 1 ]; then
    die "Initial balance $(fmt_near "$INIT_BALANCE") cannot pay for storing the contract." \
      "It needs at least $(fmt_near "$min_init" --round up): wasm $WASM_SIZE bytes + overhead at $PRICE yoctoNEAR/byte ($(fmt_near "$DEPLOY_STORAGE" --round up))," \
      "$(fmt_near "$DEPLOY_GAS_HOLD") for gas bought up front ($DEPLOY_GAS attached to init + ~$DEPLOY_EXEC_TGAS Tgas to run the deploy; mostly refunded), and fees."
  fi
  local parent_view need
  parent_view=$PARENT
  if [ -n "${1:-}" ]; then
    parent_view=$(nu json-build amount="$(int_calc "$(jget "$PARENT" amount) + $1")" \
      storage_usage:="$(jget "$PARENT" storage_usage)")
  fi
  need=$(int_calc "$INIT_BALANCE + $TX_FEE_MARGIN_YOCTO")
  near_check_balance "$NEAR_ACCOUNT_ID" "$parent_view" "$need" \
    "creating $CONTRACT with $(fmt_near "$INIT_BALANCE")" || BALANCE_OK=0
  plan "create $CONTRACT (signer $NEAR_ACCOUNT_ID), initial balance $(fmt_near "$INIT_BALANCE"), full-access key $SIGNER_PK_SHOWN (same as $NEAR_ACCOUNT_ID)"
  cmd "$NEAR_ACCOUNT_ID" account create-account fund-myself "$CONTRACT" "'$INIT_BALANCE yoctoNEAR'" \
    use-manually-provided-public-key "$SIGNER_PK_SHOWN" sign-as "$NEAR_ACCOUNT_ID"
  plan_deploy_init
}
plan_deploy_init() {
  plan "deploy $WASM_SIZE-byte wasm ($CODE_HASH) + init new($INIT_ARGS) in one tx (signer $CONTRACT; holds $(fmt_near "$DEPLOY_GAS_HOLD") of its balance for gas until it finishes)"
  cmd "$CONTRACT" contract deploy "$CONTRACT" use-file "$WASM" with-init-call new json-args "'$INIT_ARGS'" \
    prepaid-gas "'$DEPLOY_GAS'" attached-deposit "'0 NEAR'"
}

STATE=missing
if [ "$(jget "$CONTRACT_JSON" exists)" = true ]; then
  if [ "$(jget "$CONTRACT_JSON" has_code)" != true ]; then
    STATE=empty
  elif [ "$(jget "$CONTRACT_JSON" code_hash)" = "$CODE_HASH" ]; then
    STATE=same
  else
    STATE=different
  fi
  log "    $CONTRACT exists: balance $(fmt_near "$(jget "$CONTRACT_JSON" amount)"), storage $(jget "$CONTRACT_JSON" storage_usage) bytes, code_hash $(jget "$CONTRACT_JSON" code_hash)"
else
  log "    $CONTRACT does not exist yet"
fi

# The paths that sign as the contract account need the key to be one of
# its full-access keys (not the "same code" path: a locked contract, see
# lock-contract.sh, has none, and that is fine).
require_contract_signer() {
  if [ "$(nur access-keys "$CONTRACT")" = "[]" ]; then
    die "$CONTRACT is locked (it has no access keys, see lock-contract.sh): its code can't be changed and it can't be deleted." \
      "Deploy a new instance instead:" "$(new_instance_hint)"
  fi
  [ "$HAVE_KEY" = 1 ] || return 0
  near_require_full_access "$CONTRACT"
}

if [ "$FRESH" = 1 ] && [ "$STATE" != missing ]; then
  require_contract_signer
  usage=$(jget "$CONTRACT_JSON" storage_usage)
  code_len=0
  if [ "$STATE" != empty ]; then code_len=$(jget "$(nur code "$CONTRACT")" length); fi
  require_uint storage_usage "$usage"
  require_uint "code length" "$code_len"
  state_bytes=$(int_calc "$usage - $code_len")
  if [ "$(int_calc "$state_bytes > $MAX_DELETE_STATE_BYTES")" = 1 ]; then
    die "--fresh is impossible: $CONTRACT holds $state_bytes bytes of non-code state (storage $usage - code $code_len)." \
      "NEAR refuses to delete accounts with more than $MAX_DELETE_STATE_BYTES bytes (DeleteAccountWithLargeState)," \
      "so a used contract account is effectively permanent. Deploy a new instance under another name instead:" \
      "$(new_instance_hint)"
  fi
  ACTION=fresh
  cmd "$CONTRACT" account delete-account "$CONTRACT" beneficiary "$NEAR_ACCOUNT_ID"
  plan "DELETE $CONTRACT (non-code state $state_bytes bytes <= $MAX_DELETE_STATE_BYTES), balance $(fmt_near "$(jget "$CONTRACT_JSON" amount)") goes to $NEAR_ACCOUNT_ID; all its requests, approvals and key registrations are lost"
  plan_create "$(jget "$CONTRACT_JSON" amount)"
else
  case $STATE in
    missing)
      ACTION=create
      plan_create
      ;;
    empty)
      require_contract_signer
      ACTION=deploy
      need=$(int_calc "($(jget "$CONTRACT_JSON" storage_usage) + $WASM_SIZE + $DEPLOY_OVERHEAD_BYTES) * $PRICE + $DEPLOY_GAS_HOLD + $TX_FEE_MARGIN_YOCTO")
      near_check_balance "$CONTRACT" "$CONTRACT_JSON" "$need" "storing the contract code" amount || BALANCE_OK=0
      plan_deploy_init
      ;;
    same)
      owner=""
      if owner=$(near_view get_owner 2>"$NEAR_TMP/view.err"); then
        if [ "$owner" != "$APPROVAL_OWNER_ID" ]; then
          die "$CONTRACT already runs this code but is owned by $owner, not APPROVAL_OWNER_ID=$APPROVAL_OWNER_ID." \
            "There is no ownership transfer. Fix APPROVAL_OWNER_ID, or deploy elsewhere (APPROVAL_CONTRACT_ID=...)."
        fi
        ACTION=none
      elif grep -q 'not initialized' "$NEAR_TMP/view.err"; then
        require_contract_signer
        ACTION=init
        need=$(int_calc "($(jget "$CONTRACT_JSON" storage_usage) + $DEPLOY_OVERHEAD_BYTES) * $PRICE + $CALL_GAS_HOLD + $TX_FEE_MARGIN_YOCTO")
        near_check_balance "$CONTRACT" "$CONTRACT_JSON" "$need" "the init call (its state + $(fmt_near "$CALL_GAS_HOLD") gas held up front)" amount || BALANCE_OK=0
        plan "init new($INIT_ARGS) on $CONTRACT (code is deployed but was never initialized; signer $CONTRACT)"
        cmd "$CONTRACT" contract call-function as-transaction "$CONTRACT" new json-args "'$INIT_ARGS'" \
          prepaid-gas "'$NEAR_CALL_GAS'" attached-deposit "'0 NEAR'" sign-as "$CONTRACT"
      else
        die "get_owner on $CONTRACT failed: $(cat "$NEAR_TMP/view.err")"
      fi
      ;;
    different)
      live=$(nur code "$CONTRACT")
      live_len=$(jget "$live" length)
      if [ "$UPGRADE" != 1 ]; then
        die "$CONTRACT runs different code (code_hash $(jget "$CONTRACT_JSON" code_hash), $live_len bytes) than $WASM ($CODE_HASH)." \
          "Options:" \
          "  --upgrade  redeploy the code only, keeping state (the new code must read the existing state layout; no migration exists)" \
          "  --fresh    delete and recreate the account (only while it holds <= $MAX_DELETE_STATE_BYTES bytes of state)" \
          "  or deploy a new instance:" "$(new_instance_hint)"
      fi
      require_contract_signer
      ACTION=upgrade
      need=$(int_calc "max(0, $(jget "$CONTRACT_JSON" storage_usage) - $live_len + $WASM_SIZE + 100) * $PRICE + $UPGRADE_GAS_HOLD + $TX_FEE_MARGIN_YOCTO")
      near_check_balance "$CONTRACT" "$CONTRACT_JSON" "$need" "storing the new code" amount || BALANCE_OK=0
      plan "UPGRADE: deploy $WASM_SIZE-byte wasm ($CODE_HASH) over the $live_len-byte code WITHOUT init (signer $CONTRACT)"
      cmd "$CONTRACT" contract deploy "$CONTRACT" use-file "$WASM" without-init-call
      ;;
  esac
fi

if [ "$ACTION" = none ]; then
  ok "$CONTRACT already runs this wasm ($CODE_HASH), owner $owner. Nothing to deploy."
  REC="$NEAR_DEPLOYMENTS_DIR/$NEAR_NETWORK/$CONTRACT.json"
  if [ "$DRY_RUN" = 0 ] && { [ ! -f "$REC" ] || [ "$(jget "$(cat "$REC")" code_hash)" != "$CODE_HASH" ]; }; then
    RECORD_ACTION=recorded-existing
  else
    [ -f "$REC" ] && log "    record: $REC"
    exit 0
  fi
fi

if [ -n "$PLAN" ]; then
  info "Plan ($NEAR_NETWORK):"
  printf '%s' "$PLAN" >&2
fi
if [ "$DRY_RUN" = 1 ]; then
  if [ -n "$CMDS" ]; then
    info "near-cli commands (hermetic config; the key file is a temp 0600 copy of NEAR_PRIVATE_KEY):"
    printf '%s' "$CMDS" >&2
  fi
  if [ "$BALANCE_OK" != 1 ]; then
    die "Dry run: the plan above would fail for lack of balance (see above). Nothing was sent."
  fi
  if [ "$HAVE_KEY" != 1 ]; then
    ok "Dry run: balances suffice; key checks skipped (no NEAR_PRIVATE_KEY). Nothing was sent."
    exit 0
  fi
  ok "Dry run: preflight passed. Nothing was sent."
  exit 0
fi
[ "$BALANCE_OK" = 1 ] || exit 1

case $ACTION in
  upgrade)
    warn "--upgrade replaces the code of $CONTRACT and keeps its state. There is no migration:"
    warn "if the new code's state layout differs, the contract becomes unusable."
    confirm "Upgrade the code of $CONTRACT on $NEAR_NETWORK?"
    ;;
  fresh)
    warn "--fresh DELETES $CONTRACT: every request, approval and key registration on it is lost."
    confirm "Delete and recreate $CONTRACT on $NEAR_NETWORK?"
    ;;
esac

# --------------------------------------------------------------- execute
PARENT_KEY=$(near_signer_keyfile "$NEAR_ACCOUNT_ID")
CONTRACT_KEY=$(near_signer_keyfile "$CONTRACT")
CREATE_TX="" DEPLOY_TX=""

do_create() {
  near_tx "Create $CONTRACT" "$PARENT_KEY" \
    account create-account fund-myself "$CONTRACT" "$INIT_BALANCE yoctoNEAR" \
    use-manually-provided-public-key "$NEAR_SIGNER_PUBLIC_KEY" sign-as "$NEAR_ACCOUNT_ID" ||
    die "creating $CONTRACT failed"
  CREATE_TX=$NEAR_TX_HASH
  # The deploy is signed by the new account: wait until it and its key are final.
  nur account "$CONTRACT" --wait-exists --timeout 60 >/dev/null || die "$CONTRACT did not appear at final"
  nur access-key "$CONTRACT" "$NEAR_SIGNER_PUBLIC_KEY" --wait --timeout 60 >/dev/null ||
    die "the key of $CONTRACT did not appear at final"
}
do_deploy_init() {
  near_tx "Deploy + init $CONTRACT" "$CONTRACT_KEY" \
    contract deploy "$CONTRACT" use-file "$WASM" \
    with-init-call new json-args "$INIT_ARGS" prepaid-gas "$DEPLOY_GAS" attached-deposit '0 NEAR' ||
    die "deploy + init failed"
  DEPLOY_TX=$NEAR_TX_HASH
}

case $ACTION in
  create)
    do_create
    do_deploy_init
    ;;
  fresh)
    near_tx "Delete $CONTRACT (beneficiary $NEAR_ACCOUNT_ID)" "$CONTRACT_KEY" \
      account delete-account "$CONTRACT" beneficiary "$NEAR_ACCOUNT_ID" || die "deleting $CONTRACT failed"
    nur account "$CONTRACT" --wait-gone --timeout 60 >/dev/null || die "$CONTRACT still exists at final"
    do_create
    do_deploy_init
    ;;
  deploy) do_deploy_init ;;
  init)
    near_call "$CONTRACT" "$CONTRACT_KEY" new "$INIT_ARGS" "Init $CONTRACT" || die "init failed"
    DEPLOY_TX=$NEAR_TX_HASH
    ;;
  upgrade)
    near_tx "Upgrade code of $CONTRACT" "$CONTRACT_KEY" \
      contract deploy "$CONTRACT" use-file "$WASM" without-init-call || die "code upgrade failed"
    DEPLOY_TX=$NEAR_TX_HASH
    ;;
  none) ;;
esac

# --------------------------------------------------------------- verify
info "Verifying at finality final"
nur account "$CONTRACT" --wait-code-hash "$CODE_HASH" --timeout 60 >/dev/null ||
  die "$CONTRACT code_hash did not become $CODE_HASH"
ok "code_hash $CODE_HASH"
owner=$(near_view get_owner '{}' --wait-ok --timeout 60) ||
  die "get_owner failed after deploy$([ "$ACTION" = upgrade ] && echo ' (the new code may not read the old state!)')"
[ "$owner" = "$APPROVAL_OWNER_ID" ] || die "get_owner returned $owner, expected $APPROVAL_OWNER_ID"
ok "get_owner = $owner"

# --------------------------------------------------------------- record
REC="$NEAR_DEPLOYMENTS_DIR/$NEAR_NETWORK/$CONTRACT.json"
near_cli_init
tx_json=null link=""
if [ -n "$DEPLOY_TX" ]; then
  tx_json="\"$DEPLOY_TX\""
  [ -z "$NEAR_EXPLORER_TX_URL" ] || link="$NEAR_EXPLORER_TX_URL$DEPLOY_TX"
fi
create_json=null
[ -z "$CREATE_TX" ] || create_json="\"$CREATE_TX\""
case $CI_RUN_ID in '' | null | *[!0-9]*) CI_RUN_ID=null ;; esac
nu record-deployment --out "$REC" \
  contract_id="$CONTRACT" network="$NEAR_NETWORK" owner_id="$owner" code_hash="$CODE_HASH" \
  wasm_sha256="$WASM_SHA256" wasm_size:="$WASM_SIZE" source_commit="$SRC_COMMIT" source_repo="$SRC_REPO" \
  build_mode="$BUILD_MODE" ci_run_id:="$CI_RUN_ID" ci_run_url="$CI_RUN_URL" \
  action="${RECORD_ACTION:-$ACTION}" tx_hash:="$tx_json" create_tx_hash:="$create_json" explorer_url="$link" \
  deployed_at="$(utc_now)" deployer_account="$NEAR_ACCOUNT_ID" near_cli_version="$NEAR_CLI_VERSION"
ok "deployment record: $REC"
if [ -n "$NEAR_TX_LOG" ]; then
  log ""
  log "Transactions:"
  printf '%s' "$NEAR_TX_LOG" | while IFS= read -r l; do log "  $l${NEAR_EXPLORER_TX_URL:+  $(near_tx_link "${l##* }")}"; done
fi
if [ -z "$NEAR_EXPLORER_TX_URL" ]; then
  log "(no explorer on $NEAR_NETWORK; look a transaction up with the 'tx' RPC method)"
fi
