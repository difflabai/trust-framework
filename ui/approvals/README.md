# Approver UI

A single HTML file for reviewing pending requests and signing `approve` or
`reject` on the approval contract. The architecture is in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Run

```bash
cd ui/approvals && python3 -m http.server 8080
```

Open <http://127.0.0.1:8080>. Use HTTP on localhost, not `file://`: wallet
extensions and the clipboard do not reliably work from a file URL. No
install and no build.

The page opens on the testnet demonstration,
`approvals.difflabai.testnet`. It can still be redeployed. Override the
account in the query string:

```text
http://127.0.0.1:8080/?contract=approvals.difflabai.testnet&network=testnet
```

| Param | Default |
|---|---|
| `contract` | `approvals.difflabai.testnet` (testnet demonstration) |
| `network` | `testnet` (`mainnet` is the other accepted value) |
| `rpc` | `https://test.rpc.fastnear.com`, or `https://rpc.mainnet.near.org` on mainnet. HTTPS, or HTTP to localhost only. |
| `code_hash` | `5G334oPHzjDvPLXKUSstbaf3BzUPaj1sWZnDhy5Baauv` for the testnet demonstration. Signing stays disabled until the live `code_hash` matches. |
| `request` | Open that request's action. |
| `status` | `all`, or `pending`, `approved`, `rejected`, `void`. |
| `q` | Search agent, action, key, or id. |
| `keys` | `all`, `live`, or `revoked` on the approval log. |

The page reads at `finality: final` and polls while the tab is visible. It
does not run an indexer. Requests are paged by id, 50 at a time. The
approval log is paged with `get_approvals`, also 50. A refresh re-reads the
open page, not every request ever seen. Status and search filter requests;
search and a revoked-key filter apply to the approval log. A filter walks
ids until that page of matches is full, and the timer does not repeat the
walk. **Show action** opens one request: the exact action string, its
length, and a hex dump. The request field loads an id directly.

## Registering the wallet key

The contract authenticates the signing key, not just the account. Connect
the wallet, copy the public key the page shows, and have the owner
register it:

```bash
scripts/near/add-approver.sh <approver-account> <public-key> --force
```

`--force` is required for a full-access key. Browser wallets sign with
that key, so this is the v1 path, and it is a weaker one: a contract on
the approver's own account can still forward calls. `add-approver.sh`
refuses the key without `--force` for that reason. A function-call key
limited to `approve` and `reject` on this contract is stronger;
`new-principal.sh` creates those for the CLI. This page cannot ask the
wallet to sign with a key other than the one it connected with.

The approver account must not be the agent account that filed the
request. The connected account pays gas (30 Tgas is bought up front, on
the order of 0.03 NEAR held and then mostly refunded).

On testnet the connector shows wallets that advertise testnet: Meteor,
Intear, Nightly, Ledger, NEAR CLI. HOT Wallet does not set that flag, so
it is hidden. MyNearWallet is shutting down on 31 October 2026.

## What the page will not do

It will not add a function-call key on connect, relay a transaction, or
enable signing when the contract's `code_hash` does not match. It will
not register keys, revoke them, or file requests. Those stay with the
owner scripts and the agent.
