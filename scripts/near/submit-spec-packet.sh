#!/usr/bin/env bash
# Usage: scripts/near/submit-spec-packet.sh [--packet PATH] [--item ID]... [--agent NAME]
#                                           [--key-file PATH] [--setup-agent] [--dry-run] [--yes]
#
# File each item of a spec review packet as one request on the approval
# contract (APPROVAL_CONTRACT_ID, from NEAR_ACCOUNT_ID), for a reviewer to approve or
# reject in ui/spec-approvals/ or ui/spec-approvals-full/. Each action names the packet, the item and the
# SHA-256 of the item's canonical text (scripts/near/spec_packet.py), so the
# approval on chain binds to exactly what the reviewer read.
#
# Idempotent: an item that already has a pending, approved or rejected
# request with the same action from the agent is skipped. An item whose only
# requests are void (the agent key was revoked) is filed again. Pending
# requests for an earlier text of an item are reported; nothing withdraws
# them (the contract has no cancel), so the reviewer should reject them.
#
# Credentials come from .env (ENV_FILE), like every script here. The agent
# is --agent, else APPROVAL_AGENT_ACCOUNT_ID, else spec-agent (a short name
# means <name>.<NEAR_ACCOUNT_ID>). It signs the way request-action.sh does:
# --key-file PATH, else the stored key
# <NEAR_CREDENTIALS_DIR>/<network>/<agent>.agent.json, else APPROVAL_AGENT_*
# in .env when it names the agent (principal-env.sh). --setup-agent creates
# and registers a stored key first when there is none (new-principal.sh: the
# .env key NEAR_PRIVATE_KEY of NEAR_ACCOUNT_ID pays 0.5 NEAR for the account
# and signs add_agent as the owner).
#
# The reviewer must use a different account than the agent: the contract
# refuses approve/reject from the account that filed the request.
#
# Prints one line per filed request, "<item><TAB><request_id>", on stdout.
#
# Options:
#   --packet PATH   manifest (default ui/spec-approvals-full/packets/near-approval.json)
#   --item ID       only this item (repeatable)
#   --agent NAME    agent account (overrides APPROVAL_AGENT_ACCOUNT_ID)
#   --key-file PATH sign with this key file
#   --setup-agent   create and register the agent's stored key if missing
#   --dry-run       show the plan, send nothing (needs no key)
#   --yes           do not ask before sending
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

PACKET="$REPO_ROOT/ui/spec-approvals-full/packets/near-approval.json"
ITEMS=() AGENT_ARG="" KEY_FILE="" SETUP=0 DRY=0
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --packet)
      [ $# -gt 1 ] || usage_error "--packet needs a path"
      PACKET=$2
      shift
      ;;
    --item)
      [ $# -gt 1 ] || usage_error "--item needs an id"
      ITEMS+=(--item "$2")
      shift
      ;;
    --agent)
      [ $# -gt 1 ] || usage_error "--agent needs an account"
      AGENT_ARG=$2
      shift
      ;;
    --key-file)
      [ $# -gt 1 ] || usage_error "--key-file needs a path"
      KEY_FILE=$2
      shift
      ;;
    --setup-agent) SETUP=1 ;;
    --dry-run) DRY=1 ;;
    --yes) ASSUME_YES=1 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done
case $PACKET in /*) ;; *) PACKET="$PWD/$PACKET" ;; esac
[ -f "$PACKET" ] || die "packet manifest not found: $PACKET"

near_load_config
SPY() { "$NEAR_PYTHON" -I -X utf8 "$NEAR_SCRIPTS_DIR/spec_packet.py" "$@"; }
SPY check "$PACKET" >/dev/null || die "invalid packet manifest $PACKET"
AGENT=$(principal_account "${AGENT_ARG:-${APPROVAL_AGENT_ACCOUNT_ID:-spec-agent}}")
near_require_contract

# Every request on the contract (get_request per id; there is no index).
COUNT=$(near_view get_request_count) || die "could not read get_request_count"
require_uint "get_request_count" "$COUNT"
REQS="$NEAR_TMP/requests.jsonl"
: >"$REQS"
FROM=0
while [ "$FROM" -lt "$COUNT" ]; do
  nur requests "$APPROVAL_CONTRACT_ID" --from "$FROM" --limit 1000 >>"$REQS" 2>/dev/null ||
    die "could not read requests $FROM.. from $APPROVAL_CONTRACT_ID"
  FROM=$((FROM + 1000))
done

set -- "$PACKET" --requests "$REQS" --agent "$AGENT"
[ "${#ITEMS[@]}" -eq 0 ] || set -- "$@" "${ITEMS[@]}"
PLAN=$(SPY plan "$@") || die "could not plan the submission"
PKT_NAME=$("$NEAR_PYTHON" -I -c 'import json, sys; p = json.load(open(sys.argv[1], encoding="utf-8"))["packet"]; print(p["id"], p["version"])' "$PACKET")
info "packet $PKT_NAME on $APPROVAL_CONTRACT_ID ($NEAR_NETWORK), agent $AGENT, $COUNT requests on chain"
TODO=()
while IFS=$'\t' read -r id verdict ids detail; do
  case $verdict in
    submit)
      log "  $id: submit ($detail)"
      TODO+=("$id")
      ;;
    skip) log "  $id: already filed as request $ids ($detail)" ;;
    *) die "unexpected plan line for $id: $verdict" ;;
  esac
done <<<"$PLAN"
case $PLAN in *"earlier text"*) warn "some items have pending requests for an earlier text; the reviewer should reject those." ;; esac

if [ "${#TODO[@]}" -eq 0 ]; then
  ok "nothing to submit"
  exit 0
fi
if [ "$DRY" = 1 ]; then
  info "dry run: would file ${#TODO[@]} request(s); nothing sent"
  exit 0
fi

# The agent's signing key, resolved and checked as request-action.sh does.
if [ -z "$KEY_FILE" ] && [ ! -f "$(principal_keyfile "$AGENT" agent)" ] &&
  [ "${APPROVAL_AGENT_ACCOUNT_ID:-}" != "$AGENT" ]; then
  [ "$SETUP" = 1 ] || die "No agent key for $AGENT." \
    "Pass --setup-agent to create and register one (new-principal.sh), put it in .env (principal-env.sh), or pass --key-file PATH."
  info "setting up $AGENT as an agent (new-principal.sh)"
  ENV_FILE=$ENV_FILE "$NEAR_SCRIPTS_DIR/new-principal.sh" "$AGENT" agent >/dev/null || die "new-principal.sh $AGENT agent failed"
fi
KEYFILE=$(require_principal_keyfile "$AGENT" agent "$KEY_FILE")
require_key_can_call "$AGENT" "$KEYFILE" request_action

confirm "File ${#TODO[@]} request(s) as $AGENT on $APPROVAL_CONTRACT_ID ($NEAR_NETWORK)?"
ADIR="$NEAR_TMP/spec-actions"
for id in "${TODO[@]}"; do
  line=$(SPY actions "$PACKET" --out-dir "$ADIR" --item "$id") || die "could not write the action for $id"
  afile=$(printf '%s' "$line" | cut -f3)
  rid=$(ENV_FILE=$ENV_FILE "$NEAR_SCRIPTS_DIR/request-action.sh" "$AGENT" --action-file "$afile" --key-file "$KEYFILE") ||
    die "request_action failed for item $id (items before it were filed; re-running skips them)"
  ok "item $id is request $rid"
  printf '%s\t%s\n' "$id" "$rid"
done
# The page that loads this packet is the ui/* directory that contains it.
packet_dir=$(cd "$(dirname "$PACKET")" && pwd -P)
ui_name=$(basename "$(dirname "$packet_dir")")
info "review them in ui/${ui_name}/?agent=$AGENT (see its README for how to run it)"
