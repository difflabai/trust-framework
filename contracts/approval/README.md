# Approval contract

A NEAR contract that records an agent's request to perform an action and an
approver's decision, each authenticated by the caller's signing key. Approvals
are public, append-only proofs.

```text
agent key ──request_action(action)──► Pending ──approve(id, action)──► Approved
                 │                     │   │               │
        EVENT approval_requested       │   │      EVENT action_approved
                                       │   │               │
                                       │   │   get_approval(id) / get_approvals(from, limit)
                                       │   │
                                       │   └──reject(id)──► Rejected   EVENT action_rejected
                                       │
                          agent key revoked (EVENT key_revoked)
                                       ▼
                                     Void  (never approvable)
```

## Layout

| Crate | Purpose |
|---|---|
| `core/` (`approval-core`) | The whole state machine: authorization, transitions, paging. Generic over account and key types and free of near-sdk, so tests and verification tools run against the exact transition logic deployed on-chain. It has no dependencies by default; the on-chain build enables the `borsh` feature, which only adds storage serialization derives (covered by a round-trip test). |
| `contract/` (`approval-contract`) | near-sdk shell. Maps runtime context (`predecessor`, `signer`, `signer_account_pk`, block) into the core, implements `Store` over `LookupMap`, emits events, exposes JSON views. |
| `sandbox/` (`approval-sandbox-tests`) | near-workspaces tests that run the built wasm in a local NEAR sandbox. |

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
  agents, `approve` and `reject` for approvers). That is a deployment requirement, since a
  contract can't inspect another account's key permissions. With a full-access
  key, a contract deployed on the agent's own account could still be made to
  forward calls. NEP-366 meta-transactions (relayers) and DAO or multisig
  contracts as agents or approvers are therefore unsupported. Every agent and
  approver signs its own transaction.
- **Separation of duties.** An approver can't approve or reject a request
  made by an agent key bound to the same account.
- **Approvals commit to content.** `approve(request_id, action)` fails unless
  `action` equals the stored action, so the approver's own signed transaction
  names exactly what was reviewed.
- **Revocation is recorded and permanent for pending requests.** Every
  registration of a key gets a new `registration_id`, and requests,
  approvals and rejections record the registration they were made under.
  `revoke_key` removes a key immediately and records the block it was revoked
  at against that registration (`get_revocation`). Approvals already recorded
  stay, but `get_approval` / `get_approvals` then report
  `agent_key_revoked_at` / `approver_key_revoked_at`, so a verifier can
  distrust approvals made with a key later revoked as compromised. Pending
  requests made with the key become `void` and stay void even if the same key
  is registered again: each registration records the request count at that
  moment (`active_from`), and only requests made after it can be decided.
- **At most once.** A request is decided (approved or rejected) at most once.
  Decided requests are never modified.
- **Bounded agent storage.** An agent key can have at most 16 pending
  requests, so a looping or compromised agent can't drain the contract's
  storage balance. Approving or rejecting frees a slot. Rotating the key
  (revoke, then register) clears the backlog by voiding it.
- **ed25519 and secp256k1 keys only, for now.** `add_agent` and
  `add_approver` refuse ML-DSA-65 keys. A 1952-byte ML-DSA-65 key prints as
  about 2.6 KB, and with one on both the agent and the approver side the
  worst-case `action_approved` event is 18,256 bytes, over NEAR's 16 KiB
  per-receipt log limit: that approver could never approve a maximum-size
  request. Supporting ML-DSA-65 needs more work first, for example a shorter
  event (key hashes or registration ids instead of full keys) or a lower
  action limit for such keys, re-checked against the 16 KiB limit.

## API

| Method | Caller | Effect |
|---|---|---|
| `new(owner_id)` | contract account (init) | Sets the key administrator. |
| `add_agent(account_id, public_key)` | owner | Registers an agent key (ed25519 or secp256k1) and emits `key_added`. |
| `add_approver(account_id, public_key)` | owner | Registers an approver key (ed25519 or secp256k1) and emits `key_added`. |
| `revoke_key(public_key)` | owner | Removes a key, records when, and emits `key_revoked`. |
| `request_action(action) -> u64` | agent key | Records a pending request (`action` is 1 to 2048 bytes) and emits `approval_requested`. Returns `request_id`. |
| `approve(request_id, action) -> ApprovalProofView` | approver key | Approves if `action` matches, and emits `action_approved`. |
| `reject(request_id) -> RejectionView` | approver key | Rejects a pending request, freeing the agent key's slot, and emits `action_rejected`. |
| `get_approval(request_id)` | anyone (view) | Proof for one request, or `null` if pending, rejected, void or unknown (`get_request` tells these apart). |
| `get_rejection(request_id)` | anyone (view) | The rejection of one request, or `null`. |
| `get_revocation(registration_id)` | anyone (view) | `{block, ns}` when that key registration was revoked, or `null` if it is live or was never issued. |
| `get_approvals(from_index?, limit?)` | anyone (view) | Proofs in approval order. `from_index` indexes the approval log (default 0), `limit` defaults to 50 and is **clamped** to 100. Page with `from_index += page.len()` until a page comes back empty. Don't stop on a page shorter than `limit`. The log is append-only, so a stopping point stays valid. |
| `get_request(request_id)` | anyone (view) | The request with `status` `pending`, `approved`, `rejected` or `void`. |
| `get_request_count()`, `get_approval_count()`, `get_principal(public_key)`, `get_owner()` | anyone (view) | State inspection. |

Ids, indexes and block heights are JSON numbers. Nanosecond timestamps are
strings (`U64`).

Approvers can discover new requests without an indexer by polling
`get_request_count()` and reading each new id with `get_request`. Consuming
events needs an indexer, since NEAR RPC has no log query.

Failed calls panic with a message from `ApprovalError::as_str`, and every
guard runs before any write. The one shell-level guard: `add_agent` and
`add_approver` refuse ML-DSA-65 keys (`"ML-DSA-65 keys are not supported"`,
checked after the owner check), because with such a key on both sides the
worst-case `action_approved` line would exceed NEAR's 16 KiB log limit and
that request could never be approved. NEAR reverts all state changes of a failed
receipt. A receipt can still fail **after** its event was logged, for
example by running out of gas while state is written, or with
`LackBalanceForState`. Logs of failed receipts remain visible, so event
consumers must ignore events from receipts that didn't succeed.

## Events (NEP-297)

```text
EVENT_JSON:{"standard":"trust_approval","version":"1.0.0","event":"approval_requested",
  "data":{"request_id":0,"agent_account_id":"agent.near","agent_public_key":"ed25519:…",
          "agent_registration_id":0,"action":"…","requested_at_block":123,
          "requested_at_ns":"1700000000000000000","status":"pending"}}

EVENT_JSON:{"standard":"trust_approval","version":"1.0.0","event":"action_approved",
  "data":{"approval_index":0,"request_id":0,"action":"…",
          "agent_account_id":"agent.near","agent_public_key":"ed25519:…",
          "agent_registration_id":0,"requested_at_block":123,"requested_at_ns":"…",
          "approver_account_id":"approver.near","approver_public_key":"ed25519:…",
          "approver_registration_id":1,"approved_at_block":130,"approved_at_ns":"…",
          "agent_key_revoked_at":null,"approver_key_revoked_at":null}}

EVENT_JSON:{"standard":"trust_approval","version":"1.0.0","event":"action_rejected",
  "data":{"request_id":1,"action":"…","agent_account_id":"agent.near",
          "agent_public_key":"ed25519:…","agent_registration_id":0,
          "requested_at_block":131,"requested_at_ns":"…",
          "approver_account_id":"approver.near","approver_public_key":"ed25519:…",
          "approver_registration_id":1,"rejected_at_block":133,"rejected_at_ns":"…"}}

EVENT_JSON:{"standard":"trust_approval","version":"1.0.0","event":"key_added",
  "data":{"public_key":"ed25519:…","account_id":"agent.near","role":"agent",
          "registration_id":0}}

EVENT_JSON:{"standard":"trust_approval","version":"1.0.0","event":"key_revoked",
  "data":{"public_key":"ed25519:…","account_id":"agent.near","role":"agent",
          "registration_id":0,"revoked_at_block":140,"revoked_at_ns":"…",
          "voided_pending":2}}
```

`action_approved.data` has the same shape as `get_approval`, except that the
event always carries `null` revocation fields, while `get_approval` reports
revocations that happen later. `key_revoked` tells an indexer that the
`voided_pending` requests still pending under that registration are now void.
Nanosecond timestamps are strings because they exceed JSON's safe integer
range.

The worst case (64-character account ids, secp256k1 keys, the longest
accepted, and a 2048-byte action of control characters, each JSON-escaped to
six bytes) logs about 13.1 KB per receipt, under NEAR's 16 KiB limit; the
sandbox tests check this.

## Verifying a proof off-chain

A proof is only as good as the contract that produced it. A verifier should:

1. Query `get_approval(request_id)` itself, against the expected contract
   account at `finality: "final"`. Never accept proof JSON handed over by the
   agent.
2. Check the account's `code_hash` (`view_account`) matches a reproducible
   build of this source at the deployed commit: `cargo near build
   reproducible-wasm` in `contract/` builds inside the cargo-near image pinned
   by digest in `contract/Cargo.toml`, and CI prints the wasm's SHA-256 for
   every commit. A NEAR `code_hash` is the base58 SHA-256 of the wasm.
3. Check the contract account can't be redeployed: no full-access keys, or
   keys held by a governance you trust. Check `get_owner()` is the expected
   governance account. The owner alone decides who is an approver.
4. Check `approver_account_id`/`approver_public_key` against your own
   allowlist if the owner isn't fully trusted.
5. Check `agent_key_revoked_at` and `approver_key_revoked_at`. A non-null
   value means the owner later revoked that key; if keys are revoked on
   compromise, treat the proof as untrusted (the contract can't know when a
   key was actually compromised, only when it was revoked).
6. Approvals never expire and are never consumed. Executors must deduplicate
   on (contract account, `request_id`) and apply their own maximum age to
   `approved_at_ns`.
7. Only trust events from receipts that succeeded, in final blocks, and whose
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
- **Not included (minimal by design):** expiry, M-of-N thresholds,
  idempotency keys for agent retries, self-service key revocation, rejection
  reasons. An agent whose `request_action` result was lost recovers its
  `request_id` from the transaction outcome (`tx` RPC) instead of retrying.

## Approver UI

[`ui/approvals/`](../../ui/approvals/README.md) is a single HTML file an
approver opens over localhost. It lists pending requests from
`get_request_count` / `get_request` and has the approver's wallet sign
`approve` or `reject` directly. It does not relay, and it does not add a
key on connect. Register the wallet's signing key with `add-approver.sh`
(`--force` for a full-access key) before it can succeed.

## Deploying

[`scripts/near/`](../../scripts/near/README.md) deploys and operates this
contract: `build-wasm.sh` fetches CI's reproducible wasm (or rebuilds it
locally), `deploy.sh` creates the contract account, deploys and calls `new`
in one transaction signed by the contract account, and records the
deployment, `new-principal.sh` sets up agents and approvers with
function-call keys scoped to this contract, and `smoke-test.sh` checks a
deployment end to end. The account comes from `NEAR_ACCOUNT_ID` (and
`APPROVAL_CONTRACT_ID`, which defaults to `approvals.<NEAR_ACCOUNT_ID>`).
The testnet demonstration is `approvals.difflabai.testnet`, owned by
`difflabai.testnet`, deployed from `081a3a6`. It can still be redeployed.
See
[`scripts/near/README.md`](../../scripts/near/README.md#testnet-demonstration).
`scripts/near/sandbox.sh` runs the same flow against a local sandbox.

## Build and test

```bash
# Core state machine: unit tests + randomized state-machine spec
cargo test -p approval-core
cargo test -p approval-core --features borsh   # + storage round-trip test

# Contract shell unit tests (mocked NEAR runtime)
cargo test -p approval-contract

# Wasm (cargo-near applies NEAR-compatible wasm post-processing; plain
# `cargo build --target wasm32-unknown-unknown` is not equivalent)
cd contract && cargo near build non-reproducible-wasm   # quick, local toolchain
cd contract && cargo near build reproducible-wasm       # pinned Docker image, needs a clean, committed tree

# Sandbox tests. `sandbox.sh bin` prints a sha256-checked near-sandbox and
# drops a copy the crate cached before the eMudhra distrust. near-workspaces
# downloads in its build script and does not hash the tarball, so the
# variable has to be set before cargo runs.
export NEAR_SANDBOX_BIN_PATH="$(../../scripts/near/sandbox.sh bin)"
cargo test -p approval-sandbox-tests
```

The sandbox tests cover what the mocked runtime can't: `#[private]` init and
no re-init, no deposit on non-payable methods, the JSON argument names, the
real `signer_account_pk` of function-call keys (and that the runtime refuses
methods outside a key's scope), storage-staking failure with no state left
behind, and the worst-case event size. The sandbox needs a file-descriptor
limit of 65535 (`ulimit -n`); GitHub's runners allow it.

CI (`.github/workflows/approval-contract.yml`) runs fmt, clippy, the unit
tests, the reproducible build (publishing its SHA-256 and the wasm as an
artifact) and the sandbox tests against that exact wasm. Every action is
pinned to a commit SHA, and the cargo-near binary is checked against a
committed SHA-256 before it runs.

Still not covered: calls relayed through a third-party contract (the
`IndirectCall` guard is unit-tested against the mocked runtime only).

The formal verification plan for this contract lives in the
[formalver](https://github.com/difflabai/formalver) repo under
`projects/near-approval/`.
