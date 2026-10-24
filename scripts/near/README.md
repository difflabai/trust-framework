# NEAR operations for the approval contract

Scripts to deploy and operate [the approval contract](../../contracts/approval/README.md)
on NEAR. The account comes from `NEAR_ACCOUNT_ID`. There is no default.
Every script takes `-h`/`--help`, works from any directory, and is safe to
re-run: each one checks the chain first and only sends what is missing.

```text
build-wasm.sh  ->  deploy.sh  ->  new-principal.sh (agent, approver)  [-> principal-env.sh]  ->  request-action.sh / approve.sh / reject.sh
                    status.sh, view.sh, list-requests.sh, smoke-test.sh, transfer.sh, faucet-fund.sh,
                    revoke-key.sh, delete-account.sh, lock-contract.sh
```

## Testnet demonstration

`approvals.difflabai.testnet` is a testnet demonstration, owned by
`difflabai.testnet`. It is not a locked reference: the contract account
still has a full-access key, so it can be redeployed. A build of current
main will not match the `code_hash` below. Point the scripts at it with:

```bash
NEAR_ACCOUNT_ID=difflabai.testnet
APPROVAL_CONTRACT_ID=approvals.difflabai.testnet
```

`APPROVAL_CONTRACT_ID` can be omitted when it is `approvals.<NEAR_ACCOUNT_ID>`.

| | |
|---|---|
| Contract | [`approvals.difflabai.testnet`](https://testnet.nearblocks.io/address/approvals.difflabai.testnet) (testnet), owner `difflabai.testnet` |
| Code | `code_hash` `5G334oPHzjDvPLXKUSstbaf3BzUPaj1sWZnDhy5Baauv` = wasm sha256 `3f48c2f2…bde9`, CI's reproducible build of [`081a3a6`](https://github.com/difflabai/trust-framework/commit/081a3a645801f2a68f2c5d3d9b707dfbc8a2993c) ([run 39073377037](https://github.com/difflabai/trust-framework/actions/runs/39073377037)), also reproduced locally with `build-wasm.sh --local` |
| Deployed | 2026-10-19, [create](https://testnet.nearblocks.io/txns/37mrGTRMPSZc4Gwtw8z5b1ya7gnY1RL6B44eVEtzXpQ1), [deploy + init](https://testnet.nearblocks.io/txns/658LMxuvnPe6vrGuZjXnUN811yi3P8v1Ayhyzpv1DECG); record in [`deployments/testnet/approvals.difflabai.testnet.json`](deployments/testnet/approvals.difflabai.testnet.json) |
| Keys | The contract account still has a full-access key (the same key as `difflabai.testnet`), so it can be redeployed; `lock-contract.sh` removes it when the deployment should become immutable. |

`scripts/near/status.sh` shows the live state.

## Prerequisites

- `near` ([near-cli-rs](https://github.com/near/near-cli-rs), tested with
  0.15.1) on `PATH` or in `~/.cargo/bin`, or set `NEAR_CLI_BIN`.
- `python3` (3.8+, standard library only), `curl`, `git`, bash (macOS
  `/bin/bash` 3.2 works).
- `gh`, authenticated, for `build-wasm.sh --ci` (the default).
- Docker and cargo, only for `build-wasm.sh --local`.

The scripts never use your own near-cli config or keychain. Each run writes
a throwaway near-cli config (one network, pointing at `NEAR_RPC_URL`) into a
private temp dir and signs with a temporary 0600 key file there, which is
deleted on exit; temp dirs left behind by a crash or `kill -9` are removed
by the next run. The private key never appears in a command line or in the
output, also not under `bash -x` (tracing is suspended while the key is
handled).

## Configuration

```bash
install -m 600 .env.example .env      # at the repo root; .env is gitignored, 0600
```

and set `NEAR_PRIVATE_KEY` to a full-access key of `NEAR_ACCOUNT_ID`. The
scripts warn when the file holding the key is readable by others. They
parse `KEY=VALUE` lines (comments, blank lines and quotes are fine; nothing
is sourced or evaluated, except that a leading `~/` in a path setting means
your home directory) and ignore keys they don't know. Variables in the
environment override the file, and `ENV_FILE=/path/to/file` picks a
different file.

| Variable | Default | |
|---|---|---|
| `NEAR_NETWORK` | `testnet` | `testnet`, `mainnet` or `sandbox`. Mainnet also needs `NEAR_ALLOW_MAINNET=1` in the environment (it is ignored in a file). Every script checks that the node's `chain_id` matches. |
| `NEAR_RPC_URL` | per network | testnet `https://test.rpc.fastnear.com` (`https://rpc.testnet.near.org` also works but is deprecated and rate-limits quickly), mainnet `https://rpc.mainnet.near.org`, sandbox `http://127.0.0.1:3030`. Plain `http://` only to localhost unless `NEAR_ALLOW_INSECURE_RPC=1` is set in the environment. The scripts trust the RPC for chain state, so use one you trust. |
| `NEAR_ACCOUNT_ID` | (required) | Pays for everything, creates subaccounts, owns the contract. Set it in the environment or `.env`. The testnet demonstration uses `difflabai.testnet`. |
| `NEAR_PRIVATE_KEY` | (none) | `ed25519:...` full-access key of `NEAR_ACCOUNT_ID`. Needed by every script that signs; `status.sh` and `view.sh` run without it. |
| `NEAR_PUBLIC_KEY` | (none) | Optional cross-check: must match the key derived from `NEAR_PRIVATE_KEY`. |
| `APPROVAL_CONTRACT_ID` | `approvals.<NEAR_ACCOUNT_ID>` | The contract account. |
| `APPROVAL_OWNER_ID` | `NEAR_ACCOUNT_ID` | Passed to `new(owner_id)`; signs `add_agent`/`add_approver`/`revoke_key`. |
| `APPROVAL_INITIAL_BALANCE` | computed (3 NEAR) | Balance a new contract account starts with. |
| `APPROVAL_PRINCIPAL_BALANCE` | `0.5` | Balance of accounts `new-principal.sh` creates (their own gas). |
| `APPROVAL_WASM` | build-wasm.sh's output | Wasm for `deploy.sh`/`status.sh` (`--wasm PATH` is relative to the current directory instead). |
| `NEAR_CREDENTIALS_DIR` | `.near-credentials` | Principal key files, `<dir>/<network>/<account>.<role>.json` (0600, gitignored). |
| `NEAR_DEPLOYMENTS_DIR` | `scripts/near/deployments` | Deployment records, `<dir>/<network>/<contract>.json`. |
| `NEAR_EXPLORER_TX_URL` | per network | Prefix for printed transaction links (testnet `https://testnet.nearblocks.io/txns/`). |
| `NEAR_FAUCET_URL` | `https://helper.testnet.near.org/account` | Testnet faucet API used by `faucet-fund.sh` (https only). |
| `APPROVAL_AGENT_ACCOUNT_ID`, `APPROVAL_AGENT_PUBLIC_KEY`, `APPROVAL_AGENT_PRIVATE_KEY` | unset | An agent's credentials, written by `principal-env.sh`. `request-action.sh <that account>` signs with them when no key file is stored for it. |
| `APPROVAL_APPROVER_ACCOUNT_ID`, `APPROVAL_APPROVER_PUBLIC_KEY`, `APPROVAL_APPROVER_PRIVATE_KEY` | unset | The same for an approver (`approve.sh`, `reject.sh`). |

Relative paths in `NEAR_CREDENTIALS_DIR`, `NEAR_DEPLOYMENTS_DIR` and
`APPROVAL_WASM` are relative to the repo root; `~/...` is expanded, `$VARS`
are refused. The scripts warn if `NEAR_CREDENTIALS_DIR` is inside the repo
but not gitignored. As a sanity check, they refuse `*.near` accounts on
testnet and `*.testnet` accounts on mainnet.

One key controls everything by design: the contract account and the
principal accounts are created with the parent's public key as their
full-access key, and `new-principal.sh` stores every principal's secret
key side by side in `NEAR_CREDENTIALS_DIR`. That is convenient for
operating a testnet deployment, but it also means approvals from those
principals prove that the flow works, not that someone independent
reviewed anything: whoever holds the `.env` key can act as every agent and
approver. For real use:

- each approver holds its own account and key, generated and kept outside
  this repo, registered with `add-approver.sh <account> <public_key>` and
  used with `approve.sh ... --key-file PATH` / `reject.sh ... --key-file PATH`;
- keep `NEAR_CREDENTIALS_DIR` outside the worktree (e.g.
  `~/.config/trust-framework/near-credentials`) and back it up: a lost
  principal key can only be revoked and replaced;
- see "Owner" and "Verifying a proof" in the contract README: make the
  owner a multisig or DAO and lock the contract account
  (`lock-contract.sh`) once the deployment is final.

## Scripts

Results (JSON, ids, hashes) go to stdout and progress to stderr, so the
scripts compose: `id=$(scripts/near/request-action.sh agent1 "...")`. They
exit 0 on success, 1 on failure and 2 on a usage error. After each
transaction they print its hash and explorer link, then wait until the
change is visible at `finality: final` before checking it (right after a
transaction returns, `final` reads can still show the old state for a few
seconds).

| Script | What it does |
|---|---|
| `status.sh [--wasm PATH] [--min-available NEAR] [--check]` | Read-only overview: parent and contract balances, storage use and its staking cost (none for accounts of at most 770 bytes, NEP-448), available balance, whether the `.env` key is a full-access key of each, the contract's `code_hash` against the local wasm and the deployment record, number of full-access keys on the contract account, `get_owner`, `get_request_count`, `get_approval_count`, the registration status of each stored principal key (registered, not registered, revoked, or scoped to another contract instance), and the `APPROVAL_AGENT_*` / `APPROVAL_APPROVER_*` principals in `.env` with their key scope and registration (a stale, unscoped or mismatched one counts as needing attention). Before the first deploy it prints what the parent needs. Warns when the contract has less than 0.5 NEAR (or `--min-available`) available. With `--check` or `--min-available` it exits 3 if anything needs attention (for cron/CI). Needs no key. |
| `build-wasm.sh [--ci [COMMIT] \| --local [COMMIT]]` | Get the wasm into `contracts/approval/target/near/approval_contract/approval_contract.wasm` (or `--out`) and write `approval_contract.build.json` next to it (source commit, sha256, code hash, mode, CI run). `--ci` (default) downloads CI's reproducible build of COMMIT and checks it against the sha256 the run printed. `--local` builds it with the cargo-near release pinned in the workflow, in Docker, from a clone outside the repo. COMMIT defaults to the latest non-docs commit under `contracts/approval`. |
| `deploy.sh` | Idempotent deploy, see below. `--dry-run` shows the plan, what it costs and the exact near-cli commands, and sends nothing; it also works without `NEAR_PRIVATE_KEY` (key checks skipped). |
| `view.sh <method> [json-args]` | Any view method, pretty-printed. |
| `list-requests.sh [--pending] [--from N] [--limit N]` | Requests as one JSON object per line (default: the newest 50), optionally only pending ones. |
| `new-principal.sh <name> <agent\|approver>` | Creates `<name>.<NEAR_ACCOUNT_ID>` (if needed, `--balance`, default 0.5 NEAR, minimum 0.05), generates a new keypair (or reuses the stored one, unless its registration was revoked), adds it as a function-call key restricted to the contract and the role's methods (agent: `request_action`; approver: `approve`, `reject`; unlimited allowance), registers it and notes the contract, methods and registration id in the key file. `--methods` narrows the key to a subset, e.g. `--methods approve` for an approver key that cannot reject; later runs reuse the recorded methods. |
| `principal-env.sh <name> <agent\|approver> [--replace]` | Appends a principal's stored credentials to `ENV_FILE` as `APPROVAL_AGENT_*` / `APPROVAL_APPROVER_*` (account id, public key, private key), after checking the key is a contract-scoped function-call key registered for that role. Rewrites the file atomically with mode 0600; the secret never passes through argv or stdout. Same key again: no change; a different key for the role needs `--replace`. |
| `add-agent.sh <account> <public_key>`, `add-approver.sh <account> <public_key>` | Register a key you manage yourself. Refuses a full-access key or one scoped to another receiver or other methods unless `--force`; a key not yet on the account only gets a warning. |
| `revoke-key.sh <public_key> [--delete-access-key [--account ACCOUNT]]` | `revoke_key`, and retires the stored key file (renamed to `<account>.<role>.revoked-<n>.json`) so the next `new-principal.sh` makes a new key. With `--delete-access-key` it also deletes the key from its account and removes the file; that also works for a key that is no longer registered. |
| `request-action.sh <agent> <action>` | Signs `request_action` with the agent's stored key, else `APPROVAL_AGENT_*` from `.env` when it names this account (or `--key-file PATH`), after checking the key may call `request_action` and is registered; prints the request id. `--action-file PATH` (`-` for stdin) reads the action byte for byte; an action starting with `-` goes after `--`. |
| `approve.sh <approver> <request_id> <action>` | Signs `approve` with the approver's stored key, else `APPROVAL_APPROVER_*` from `.env` (or `--key-file PATH`); prints the proof. Checks first that the key may call `approve` and is registered, that the request is pending, that the action matches exactly, and that the agent isn't the approver's own account (`--skip-checks` sends anyway). The action can come from `--action-file PATH`, or, after reviewing it, from `--action-from-request`. |
| `reject.sh <approver> <request_id>` | Signs `reject` with the stored key, else `APPROVAL_APPROVER_*` from `.env` (or `--key-file PATH`); prints the rejection. Refuses before sending when the key may not call `reject` (e.g. an approve-only key). |
| `submit-spec-packet.sh [--packet PATH] [--item ID]... [--setup-agent] [--dry-run] [--yes]` | Files each item of a spec review packet (default `ui/spec-approvals/packets/near-approval.json`) as one request for review in [`ui/spec-approvals/`](../../ui/spec-approvals/README.md). Each action names the item and the SHA-256 of its text (`spec_packet.py`). Idempotent: items that already have a pending, approved or rejected request are skipped, and only items with void requests are filed again. The agent (`--agent`, else `APPROVAL_AGENT_ACCOUNT_ID`, else `spec-agent`) signs as `request-action.sh` does: `--key-file`, its stored key, or `APPROVAL_AGENT_*` from `.env`. `--setup-agent` creates and registers the stored key with `new-principal.sh` if it is missing. |
| `smoke-test.sh [--cleanup]` | End-to-end check: ensures `smoke-agent` and `smoke-approver` principals, requests, approves and rejects, and asserts `get_approval`, `get_request` and `get_rejection`. `--cleanup` revokes their keys and deletes both accounts. |
| `transfer.sh <receiver> <amount> [--yes]` | Sends NEAR from `NEAR_ACCOUNT_ID`, e.g. to top up the contract's storage balance. |
| `faucet-fund.sh [<receiver>] [--rounds N]` | Testnet only: tops up an existing account (default `NEAR_ACCOUNT_ID`) with 10 NEAR per round from the testnet faucet, which only funds new accounts: each round has the faucet create a throwaway `tf-faucet-….testnet` account and then deletes it with the receiver as beneficiary. Needs no `NEAR_PRIVATE_KEY`. If a deletion fails, the throwaway key is kept and `--recover KEYFILE` finishes the round. Uses `NEAR_FAUCET_URL` (default `https://helper.testnet.near.org/account`; near-cli's own default host fails TLS). |
| `delete-account.sh <account> --yes` | Deletes a subaccount of `NEAR_ACCOUNT_ID` (balance goes back to it) and its stored key files. Refuses anything else, and the contract account unless `--delete-contract` is also given. |
| `lock-contract.sh --yes [--dry-run]` | Deletes every access key of the contract account once the deployment is final (checks code hash against the record and the owner first). Irreversible: no more `--upgrade`/`--fresh`/deletion; top-ups and contract calls keep working. |
| `sandbox.sh start\|stop\|status\|env\|reset\|bin` | Local near-sandbox node for trying all of the above without testnet. `bin` prints a sha256-checked binary for `NEAR_SANDBOX_BIN_PATH`. |

`<agent>`, `<approver>` and `<name>` accept a short name (`alice` means
`alice.<NEAR_ACCOUNT_ID>`) or a full account id. The scripts also work
through a symlink (e.g. `~/bin/near-status -> .../status.sh`).

### Gas is paid up front

Since protocol 85, NEAR buys the gas of a transaction up front at
`max(gas_price, 1e9)` yoctoNEAR per gas (`min_gas_purchase_price`) and
refunds the unused part afterwards. A function call with 30 Tgas attached
therefore holds 0.03 NEAR of the signer's balance while it runs, even
though it burns well under 0.001 NEAR. That is why the balance checks
below ask for more than the fees: the contract account must hold its
storage plus ~0.045 NEAR during deploy + init, and the owner needs ~0.04
NEAR free for each `add_agent`/`add_approver`/`revoke_key`. When a
transaction still fails for lack of balance, the scripts print the
`transfer.sh` command that fixes it.

### deploy.sh

Preflight, before anything is sent: the `.env` key is a full-access key of
`NEAR_ACCOUNT_ID`; the wasm exists (its sha256, code hash and recorded source
commit are printed); and the paying account can afford the plan. The needed
amount is computed from the wasm size, the network's storage price
(`storage_amount_per_byte`, 1e19 yoctoNEAR per byte today) and the gas
bought up front (see above), and reported as needed vs available with how
to fund it. Then:

- **No contract account:** create `APPROVAL_CONTRACT_ID` as a subaccount,
  funded with the initial balance (default: the wasm's storage, ~1.68 NEAR,
  plus 1 NEAR of headroom for requests and approvals, rounded up to 3 NEAR),
  with the parent's public key as its full-access key. Then deploy and call
  `new({"owner_id": APPROVAL_OWNER_ID})` in one transaction signed by the
  contract account, since `new` is `#[private]`.
- **Account without code:** deploy and init.
- **Same code already deployed:** check `get_owner`, record it if no
  record exists, and exit 0. If the code is there but `new` was never
  called, call it.
- **Different code:** refuse, unless:
  - `--upgrade`: deploy the code only, no init call. There is no migration,
    so the new code must read the existing state layout; `get_owner` is
    checked afterwards.
  - `--fresh`: delete the contract account and start over. **Only possible
    while the account's non-code state is at most 10,000 bytes.** Tested in
    the sandbox: deleting `approvals.test.near` holding the 167,622-byte
    contract right after `new`, or with a few requests (under 10 KB of
    state), works. With six maximum-size requests (13,548 bytes of state),
    NEAR rejects the deletion on chain with "Delete account ... whose state
    is large is temporarily banned" (`DeleteAccountWithLargeState`) and
    burns the gas. `deploy.sh` and `delete-account.sh` check this before
    sending. **A contract account in real use is effectively permanent**: to
    start over, deploy a new instance with its own credentials dir (keys
    are scoped to one contract, so the first instance's key files stay
    where they are), e.g.
    `APPROVAL_CONTRACT_ID=approvals2.example.testnet NEAR_CREDENTIALS_DIR=.near-credentials-approvals2 scripts/near/deploy.sh`,
    and run `new-principal.sh` etc. with the same two settings.
- **Locked contract** (no access keys, see `lock-contract.sh`): same code
  is reported as deployed; anything else is refused.

`--upgrade` and `--fresh` ask for confirmation (or `--yes`). After any
deploy, the script waits until `code_hash` equals the wasm's code hash and
`get_owner` returns `APPROVAL_OWNER_ID`, then writes
`<NEAR_DEPLOYMENTS_DIR>/<network>/<contract>.json`: contract, network,
owner, code hash, wasm sha256, source commit and CI run from the build
metadata, transaction hash and explorer link, UTC time, deployer, near-cli
version, plus the previous records under `history`. Commit the testnet
record so anyone can check what was deployed. Sandbox records are
gitignored.

## Typical flows

### First deploy to testnet

Set `NEAR_ACCOUNT_ID` and `NEAR_PRIVATE_KEY` in `.env` first. The commands
below are what deployed the testnet demonstration (`difflabai.testnet` /
`approvals.difflabai.testnet`) on 2026-10-19.

```bash
install -m 600 .env.example .env      # then set NEAR_ACCOUNT_ID and NEAR_PRIVATE_KEY
scripts/near/status.sh                # parent balance, what the first deploy needs; works before anything exists
scripts/near/faucet-fund.sh           # if it is short: +10 testnet NEAR from the faucet
scripts/near/build-wasm.sh            # CI's reproducible wasm for the latest contract commit
scripts/near/deploy.sh --dry-run      # key check, the plan and what it costs; sends nothing
scripts/near/deploy.sh                # create the contract account, deploy, init
scripts/near/status.sh                # code_hash matches, owner set
git add scripts/near/deployments/testnet && git commit -m "Record the testnet deployment"
scripts/near/new-principal.sh agent1 agent
scripts/near/new-principal.sh reviewer1 approver
scripts/near/smoke-test.sh            # end to end on testnet; --cleanup removes the smoke accounts
```

If `difflabai.testnet` is short of funds, `deploy.sh` stops before sending
and prints the needed and available amounts. Budget about 3.01 NEAR for the
first deploy (3 NEAR initial balance plus fees) and about 0.55 NEAR per
principal (0.5 NEAR balance plus fees; another ~0.04 NEAR is held for gas
during the registration call and refunded), so ~5.2 NEAR for the steps
above including the two smoke-test principals.

This is the sequence that deployed `approvals.difflabai.testnet` on
2026-10-19 (with `faucet-fund.sh` first: `difflabai.testnet` started as a
zero-balance account); `smoke-test.sh` passed on testnet afterwards.

### Adding principals and using them

```bash
scripts/near/new-principal.sh agent1 agent          # agent1.<NEAR_ACCOUNT_ID>
scripts/near/new-principal.sh reviewer1 approver    # a different account (separation of duties)
id=$(scripts/near/request-action.sh agent1 "deploy release 1.4.2 to prod")
scripts/near/view.sh get_request "{\"request_id\": $id}"
scripts/near/approve.sh reviewer1 "$id" "deploy release 1.4.2 to prod"
scripts/near/view.sh get_approval "{\"request_id\": $id}"
```

Key files land in `.near-credentials/testnet/<account>.<role>.json` (mode
0600, gitignored; keep a backup if the principal matters). To rotate a key:
`scripts/near/revoke-key.sh <old_public_key> --delete-access-key`, then
`scripts/near/new-principal.sh <name> <role>` generates and registers a new
one (repeat `--methods` if the old key was narrowed; `revoke-key.sh` prints
the exact command), then `scripts/near/principal-env.sh <name> <role>
--replace` if the old key was in `.env`. `revoke-key.sh` retires the stored file even without
`--delete-access-key` (renamed to `<account>.<role>.revoked-<n>.json`), so
the revoked key is never re-registered by accident; `new-principal.sh` also
refuses a stored key whose recorded registration was revoked. Revocation
voids the old key's pending requests for good.

To keep a principal's credentials in `.env` (e.g. for other tools, or a
fresh checkout without `.near-credentials/`), export them with
`principal-env.sh`. The signing scripts fall back to those variables when
no key file is stored for the account, and `status.sh` lists them:

```bash
scripts/near/new-principal.sh approver1 approver --methods approve   # may approve, not reject
scripts/near/principal-env.sh agent1 agent        # APPROVAL_AGENT_ACCOUNT_ID / _PUBLIC_KEY / _PRIVATE_KEY
scripts/near/principal-env.sh approver1 approver  # APPROVAL_APPROVER_*
```

A function-call key only limits which **change** methods its holder can
sign. View methods (`get_request`, `get_approval`, `get_owner`, ...) need
no key at all: anyone can call them over RPC (`view.sh`). Each principal
account also carries `NEAR_ACCOUNT_ID`'s full-access key, so the operator
can top it up, rotate its keys or delete it; the scoped key is the one the
agent or approver holds.

A real approver should not use a key from this repo's credentials dir:
generate it elsewhere, register it with `add-approver.sh`, and sign with
`approve.sh <approver> <id> --action-file action.txt --key-file ~/keys/reviewer.json`.
To sign from a browser wallet instead, open [`ui/approvals/`](../../ui/approvals/README.md) (or [`ui/spec-approvals/`](../../ui/spec-approvals/README.md) for a spec review packet)
and register the wallet's public key with `add-approver.sh … --force`
(a full-access key; the page cannot select a different key than the one
the wallet connects with).

### Smoke test

```bash
scripts/near/smoke-test.sh            # creates smoke-agent/smoke-approver on first run, reuses them after
scripts/near/smoke-test.sh --cleanup  # revoke their keys and delete both accounts
```

Each run leaves two requests and one approval in the contract (about 1 KB of
its storage balance), since nothing is ever deleted.

### Storage top-up

The contract account pays for all storage. `status.sh` shows its balance,
the amount locked for storage and what is still available, and warns below
0.5 NEAR available. A maximum-size request costs about 0.022 NEAR and an
approval about 0.002 NEAR, for good. When it runs out, `request_action` and
`approve` fail and the scripts print the top-up command. Top up with:

```bash
scripts/near/transfer.sh "$APPROVAL_CONTRACT_ID" 2 --yes
```

For monitoring, `scripts/near/status.sh --min-available 1` exits 3 when the
contract has less than 1 NEAR available, the owner or code hash is not what
is configured/recorded, or the contract is missing.

### Local sandbox

```bash
scripts/near/sandbox.sh start
eval "$(scripts/near/sandbox.sh env)"     # export ENV_FILE=scripts/near/.sandbox/.env
scripts/near/build-wasm.sh && scripts/near/deploy.sh && scripts/near/smoke-test.sh
scripts/near/sandbox.sh stop              # `reset` also wipes the chain
```

The sandbox `.env` sets `NEAR_NETWORK=sandbox`, `NEAR_ACCOUNT_ID=test.near`
with the sandbox's genesis key, and keeps credentials and deployment records
under the sandbox dir, so nothing in the repo changes. The contract id there
is `approvals.test.near`. `SANDBOX_DIR` and `SANDBOX_RPC_PORT` (p2p uses the
RPC port + 21500) let several sandboxes run side by side; each sandbox dir
remembers its port, so later `start`/`status` calls need only `SANDBOX_DIR`:

```bash
SANDBOX_DIR=/tmp/sbx2 SANDBOX_RPC_PORT=3040 scripts/near/sandbox.sh start
ENV_FILE=/tmp/sbx2/.env scripts/near/deploy.sh
```

The node is near-sandbox 2.13.4, the version the contract's own sandbox
tests use, downloaded once and checked against a sha256 recorded in
`sandbox.sh`. Upstream publishes no checksums (the near-sandbox crate
downloads the tarball unverified); these hashes were recorded from the S3
tarballs on 2026-10-19 (trust on first use), so they pin the bytes, not
their provenance. To move `SANDBOX_VERSION`, download the new tarball,
verify it as well as you can, and add its hash to `sandbox.sh` or pass
`SANDBOX_SHA256`.

### Verifying the deployed code

A NEAR `code_hash` is the base58 SHA-256 of the wasm. To check that the
testnet demonstration (`approvals.difflabai.testnet`) runs this repo's code
at a given commit, set `NEAR_ACCOUNT_ID=difflabai.testnet` first so
`status.sh` reads that account:

```bash
scripts/near/build-wasm.sh --local <commit>   # your own reproducible build
scripts/near/status.sh                        # "matches deployed: yes"
```

`build-wasm.sh` prints the code hash, and `status.sh` compares it with
`view_account.code_hash`. The deployment record names the commit and CI run
the deployed wasm came from. `--local` builds in the image pinned by digest in
`contracts/approval/contract/Cargo.toml`, so it reproduces CI's hash
(`3f48c2f2…bde9`, code hash `5G334oPHzjDvPLXKUSstbaf3BzUPaj1sWZnDhy5Baauv`,
for commit `081a3a6`).

## Files

| Path | |
|---|---|
| `lib.sh` | Shared config loading, hermetic near-cli wrapper, RPC helpers. Sourced by every script. |
| `spec_packet.py` | Stdlib helper for spec review packets: canonical item hash, request action, and the submission plan. |
| `near_util.py` | Stdlib helper: JSON-RPC queries (with retry on rate limits), base58, key files, code hashes, exact yoctoNEAR arithmetic. |
| `deployments/<network>/<contract>.json` | Deployment records (testnet: commit them). |
| `.sandbox/`, `.cache/` | Local sandbox state and the cargo-near download cache (gitignored). |
| `../../.near-credentials/` | Principal key files (gitignored). |

## Limitations

- Only ed25519 keys are generated and accepted for `NEAR_PRIVATE_KEY`.
- The owner must be `NEAR_ACCOUNT_ID` for the owner-signed scripts. A
  multisig or DAO owner has to submit `add_agent`/`add_approver`/`revoke_key`
  through its own tooling.
- `new-principal.sh` only manages direct subaccounts of `NEAR_ACCOUNT_ID`;
  register keys of other accounts with `add-agent.sh`/`add-approver.sh`.
- `build-wasm.sh --local` has pinned cargo-near builds for Linux x86_64 and
  macOS arm64 only (those are what the workflow pins). It runs that binary
  directly (not `cargo near`, which could pick another installed
  cargo-near).
- Scripts that sign with the same key at the same time can collide on the
  access-key nonce (`Transaction nonce ... must be ... + 1`); nothing is
  sent twice, re-running the failed one is safe.
- The scripts trust `NEAR_RPC_URL` for chain state (balances, code hashes,
  view results); they validate its numbers and its `chain_id`, but a
  malicious RPC can still lie about state.
- The sandbox runs on Linux x86_64/aarch64 and macOS arm64 (no upstream
  Intel macOS build).
