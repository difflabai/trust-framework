# Approval contract

A NEAR contract that records an agent's request to perform an action and an
approver's sign-off, each authenticated by the caller's signing key. Approvals
are public, append-only proofs.

```text
agent key ──request_action(action)──► Pending ──approve(id, action)──► Approved
                 │                       │                │
        EVENT approval_requested         │       EVENT action_approved
                                         │                │
                          agent key revoked     get_approval(id) / get_approvals(from, limit)
                                         ▼
                                       Void  (never approvable)
```

## Layout

| Crate | Purpose |
|---|---|
| `core/` (`approval-core`) | The whole state machine: authorization, transitions, paging. No dependencies, generic over account and key types, so tests and verification tools run against the exact logic deployed on-chain. |
| `contract/` (`approval-contract`) | near-sdk shell. Maps runtime context (`predecessor`, `signer`, `signer_account_pk`, block) into the core, implements `Store` over `LookupMap`, emits events, exposes JSON views. |

## Authorization model

- **Identity is the signing key.** The owner registers each key once, with one
  role (`agent` or `approver`), bound to one account. A call is accepted only
  if `env::signer_account_pk()` is registered for that role **and** bound to
  `env::signer_account_id()`.
- **No relaying.** `predecessor_account_id` must equal `signer_account_id`:
  the immediate caller is the signing account itself, not a third-party
  contract the key holder was tricked into calling. This means "the key
  holder called us directly" only if registered keys are **function-call
  access keys whose receiver is this contract** (method `request_action` for
  agents, `approve` for approvers). That is a deployment requirement, since a
  contract can't inspect another account's key permissions. With a full-access
  key, a contract deployed on the agent's own account could still be made to
  forward calls. NEP-366 meta-transactions (relayers) and DAO or multisig
  contracts as agents or approvers are therefore unsupported. Every agent and
  approver signs its own transaction.
- **Separation of duties.** An approver can't approve a request made by an
  agent key bound to the same account.
- **Approvals commit to content.** `approve(request_id, action)` fails unless
  `action` equals the stored action, so the approver's own signed transaction
  names exactly what was reviewed.
- **Revocation is permanent for pending requests.** `revoke_key` removes a key
  immediately. Approvals already recorded stay valid. Pending requests made
  with the key become `void` and stay void even if the same key is registered
  again: each registration records the request count at that moment
  (`active_from`), and only requests made after it can be approved.
- **At most once.** A request is approved at most once. Approved requests are
  never modified.
- **Bounded agent storage.** An agent key can have at most 16 pending
  requests, so a looping or compromised agent can't drain the contract's
  storage balance. Approving frees a slot. Rotating the key (revoke, then
  register) clears the backlog by voiding it.

## API

| Method | Caller | Effect |
|---|---|---|
| `new(owner_id)` | contract account (init) | Sets the key administrator. |
| `add_agent(account_id, public_key)` | owner | Registers an agent key. |
| `add_approver(account_id, public_key)` | owner | Registers an approver key. |
| `revoke_key(public_key)` | owner | Removes a key. |
| `request_action(action) -> u64` | agent key | Records a pending request (`action` is 1 to 2048 bytes) and emits `approval_requested`. Returns `request_id`. |
| `approve(request_id, action) -> ApprovalProofView` | approver key | Approves if `action` matches, and emits `action_approved`. |
| `get_approval(request_id)` | anyone (view) | Proof for one request, or `null` if pending, void or unknown (`get_request` tells these apart). |
| `get_approvals(from_index?, limit?)` | anyone (view) | Proofs in approval order. `from_index` indexes the approval log (default 0), `limit` defaults to 50 and is **clamped** to 100. Page with `from_index += page.len()` until a page comes back empty. Don't stop on a page shorter than `limit`. The log is append-only, so a stopping point stays valid. |
| `get_request(request_id)` | anyone (view) | The request with `status` `pending`, `approved` or `void`. |
| `get_request_count()`, `get_approval_count()`, `get_principal(public_key)`, `get_owner()` | anyone (view) | State inspection. |

Ids, indexes and block heights are JSON numbers. Nanosecond timestamps are
strings (`U64`).

Approvers can discover new requests without an indexer by polling
`get_request_count()` and reading each new id with `get_request`. Consuming
events needs an indexer, since NEAR RPC has no log query.

Failed calls panic with a message from `ApprovalError::as_str`, and every
guard runs before any write. NEAR reverts all state changes of a failed
receipt. A receipt can still fail **after** its event was logged, for
example by running out of gas while state is written, or with
`LackBalanceForState`. Logs of failed receipts remain visible, so event
consumers must ignore events from receipts that didn't succeed.

## Events (NEP-297)

```text
EVENT_JSON:{"standard":"trust_approval","version":"1.0.0","event":"approval_requested",
  "data":{"request_id":0,"agent_account_id":"agent.near","agent_public_key":"ed25519:…",
          "action":"…","requested_at_block":123,"requested_at_ns":"1700000000000000000",
          "status":"pending"}}

EVENT_JSON:{"standard":"trust_approval","version":"1.0.0","event":"action_approved",
  "data":{"approval_index":0,"request_id":0,"action":"…",
          "agent_account_id":"agent.near","agent_public_key":"ed25519:…",
          "requested_at_block":123,"requested_at_ns":"…",
          "approver_account_id":"approver.near","approver_public_key":"ed25519:…",
          "approved_at_block":130,"approved_at_ns":"…"}}
```

`action_approved.data` has the same shape as `get_approval`. Nanosecond
timestamps are strings because they exceed JSON's safe integer range.

## Verifying a proof off-chain

A proof is only as good as the contract that produced it. A verifier should:

1. Query `get_approval(request_id)` itself, against the expected contract
   account at `finality: "final"`. Never accept proof JSON handed over by the
   agent.
2. Check the account's `code_hash` (`view_account`) matches a reproducible
   build of this source. This needs a `[package.metadata.near.reproducible_build]`
   section pinned to a cargo-near image, which isn't added yet.
3. Check the contract account can't be redeployed: no full-access keys, or
   keys held by a governance you trust. Check `get_owner()` is the expected
   governance account. The owner alone decides who is an approver.
4. Check `approver_account_id`/`approver_public_key` against your own
   allowlist if the owner isn't fully trusted.
5. Approvals never expire and are never consumed. Executors must deduplicate
   on (contract account, `request_id`) and apply their own maximum age to
   `approved_at_ns`.
6. Only trust events from receipts that succeeded, in final blocks, and whose
   `executor_id` is the contract account. Any contract can log text that
   looks like `EVENT_JSON`. Treat events as hints and confirm with
   `get_request` / `get_approval`.

## Operating notes

- **Storage.** The contract account pays storage and takes no deposits,
  because function-call keys can't attach one. A maximum-size request locks
  about 2.2 KB (≈0.022 NEAR at 1e19 yoctoNEAR/byte) and an approval about
  0.2 KB (≈0.002 NEAR), permanently, since nothing is deleted. Each agent key
  can hold at most 16 pending requests (≈0.36 NEAR worst case), but approved
  and void requests accumulate. If the balance can't cover storage, every
  state-growing call fails with `LackBalanceForState`. Anyone can top up by
  transferring NEAR. Monitor `amount` against `storage_usage` from
  `view_account`.
- **Action content.** `action` is public and stored forever. Don't put secrets
  in it: use a hash or commitment for sensitive payloads. Approver UIs should
  render it escaped, since it may contain control or bidi characters.
- **Function-call keys** have a gas allowance. Set it high enough, or
  unlimited. To rotate a key, call `revoke_key` on the old one, then
  `add_agent`/`add_approver` for the new one.
- **Init.** `new` is `#[private]`: the contract account itself must call it,
  ideally in the deploy transaction (`cargo near deploy … with-init-call new
  json-args '{"owner_id":"…"}'`, signed by the contract account). A parent
  account creating, deploying and initializing in one batch can't call it.
- **Owner.** Make the owner a multisig or DAO in production. The contract has
  no ownership transfer or upgrade method, by design.
- **Not included (minimal by design):** rejection, expiry, M-of-N thresholds,
  idempotency keys for agent retries, registry-change events, self-service key
  revocation. An agent whose `request_action` result was lost recovers its
  `request_id` from the transaction outcome (`tx` RPC) instead of retrying.

## Build and test

```bash
# Core state machine: unit tests + randomized state-machine spec
cargo test -p approval-core

# Contract shell unit tests (mocked NEAR runtime)
cargo test -p approval-contract

# Wasm (cargo-near applies NEAR-compatible wasm post-processing; plain
# `cargo build --target wasm32-unknown-unknown` is not equivalent)
cd contract && cargo near build non-reproducible-wasm
```

Not yet covered, and needing a near-workspaces sandbox: the wasm-wrapper-only
checks (`#[private]` init, no re-init, no deposit on non-payable methods, the
JSON argument names), real `signer_account_pk` semantics for function-call
keys, storage-staking failure, and the worst-case event size against NEAR's
16 KiB log limit.

The formal verification plan for this contract lives in the
[formalver](https://github.com/difflabai/formalver) repo under
`projects/near-approval/`.
