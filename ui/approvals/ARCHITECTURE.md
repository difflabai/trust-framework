# Approver UI

A page an approver uses to review requests on the approval contract and
sign `approve` or `reject` with their own key. Reads are public. The chain
is the source of truth. The page holds no keys. The only transaction it
submits is the one the approver's wallet signs.

## Shape

`index.html` is the application. Contract reads, the wallet connector,
signing and the text-safety helpers live in `../shared/approval-kit.js`,
and the base styles in `../shared/base.css`. Both are shared with
`../spec-approvals/` and `../spec-approvals-full/`. No build, no framework, no backend. Views
are `fetch` calls to a NEAR JSON-RPC at `finality: final`. Signing uses
[NEAR Connect](https://docs.near.org/tools/near-connect)
(`@hot-labs/near-connect` 0.11.4), loaded from a pinned URL with
subresource integrity. The wallet signs from the approver account to the
contract account, so predecessor and signer are the same account.

The page is one column of semantic HTML, system fonts, and `color-scheme`
for light and dark. Chain data is inserted with `textContent`. The action
is never parsed as HTML.

## Reads

On load, and about every 20 seconds while the tab is visible, the page
reads `view_account` (for `code_hash` and the contract account's
full-access keys), `get_owner`, `get_request_count`, and
`get_approval_count`.

Requests are paged by id, 50 at a time, newest page first. A refresh
re-reads that page only. Approvals are paged with `get_approvals(from_index,
limit)`, also 50, newest page first. A refresh re-reads that page only.
There is no paged rejection log and no principal list; those are not paged.

Status (all, pending, approved, rejected, void) and a search box filter
requests. Search matches the id, agent account, action, and agent key.
The approval log has the same search, plus a filter for whether a key
behind the proof was later revoked. A filter walks ids, or approval-log
pages, until the current result page is full. The walk is not repeated on
the timer: a later refresh re-reads the visible matches and any new ids at
the tip. If a visible match no longer qualifies, the scan continues until
the page is full again or the log is exhausted. New ids are inserted
newest-first. Filtered approval proofs are re-read, so a later revocation
leaves the "neither key revoked" filter. The contract has no pending
index, so a pending filter cannot skip decided history. Show action still
loads one id directly.

## Showing an action

Show action opens one request on its own. The request id comes from a card,
from the request field, or from `?request=`. The field loads an id the poll
window does not contain.

The view shows the status, the agent account, when it was requested, and
the action string returned by `get_request`. The string is rendered in an
isolated `<pre>` (`unicode-bidi: isolate`, `direction: ltr`). The page
reports the UTF-8 length, warns when the action contains control,
bidi-override, or zero-width characters, and offers a hex dump of the
bytes. Copy copies that same string.

Approve and reject for a pending request start from this view as well as
from the card. A request filed by the connected account has no decision
buttons.

## Signing

`approve(request_id, action)` is sent with the action from a fresh
`get_request`, not a string the approver retyped. The page aborts if the
status is no longer `pending` or the action differs from what was shown.
`reject(request_id)` does not carry the action in the signed arguments, and
the confirm step says so. Deposit is `0`. Gas is 30 Tgas.

NEAR Connect is created with `signInWithoutAddKey` and
`signAndSendTransaction`. Connect does not add a function-call key. Each
decision is a prompted signature.

After connect the page reads `view_access_key` and `get_principal` for the
key the wallet reports. Signing stays disabled unless that key is
registered on this contract as an approver key of the connected account. A
full-access key is named as such. The owner registers it with
`add-approver.sh --force`. A function-call key limited to `approve` and
`reject` on this contract is the stronger registration; the page signs with
the key the wallet connected, not a different one.

The connector script is pinned to commit
`de0f08af1e07c19fe5f80070383231d16ef924f6` with `integrity`. If the bytes
differ, the script does not run and signing is unavailable. Reads still
work. Wallet executor scripts are loaded by the connector from each
wallet's URL. The wallet prompt is the check on the signed arguments.

On testnet the connector lists wallets that advertise testnet, including
Meteor, Intear, Nightly, Ledger, and NEAR CLI. HOT Wallet does not
advertise testnet, so it is not listed. WalletConnect is not configured.

## Contract check

Signing is disabled unless `view_account.code_hash` equals the expected
hash. The testnet demonstration pair is `approvals.difflabai.testnet` /
`5G334oPHzjDvPLXKUSstbaf3BzUPaj1sWZnDhy5Baauv`. Another deployment sets
`?code_hash=`. An empty expected hash does not skip the check.

The page reports how many full-access keys the contract account has. A
match on refresh is not a lock. `lock-contract.sh` removes those keys.

| Param | Default |
|---|---|
| `contract` | `approvals.difflabai.testnet` (testnet demonstration) |
| `network` | `testnet` (`mainnet` is the other value passed to the connector) |
| `rpc` | `https://test.rpc.fastnear.com`, or `https://rpc.mainnet.near.org` on mainnet. HTTPS, or HTTP to localhost. |
| `code_hash` | the hash recorded for the testnet demonstration |
| `request` | open that request's action |
| `status` | `all` (also `pending`, `approved`, `rejected`, `void`) |
| `q` | search string |
| `keys` | `all` (also `live`, `revoked`) on the approval log |

Run it with `python3 -m http.server` from `ui/` (the page loads `../shared/`). Wallet extensions
and the clipboard need HTTP on localhost, not `file://`.

## Roadmap: hosted on-chain

The artifact is this HTML file. Hosting it on NEAR stores those bytes on
chain and serves them through a gateway. NEAR does not speak HTTP to
browsers, so a gateway is how a browser loads the page.

The host is a contract other than the approval contract. A view returns the
HTML and its SHA-256. That contract's `code_hash` pins the page the same
way the approval contract's `code_hash` pins the state machine. The gateway
does one RPC call and returns `text/html`. The page can fetch that view and
compare it to itself, so a gateway that swaps the body fails in the
approver's browser.

SocialDB (`social.near` on mainnet, `v1.social08.testnet` on testnet) can
hold the same bytes. Values are size-capped per key, and the account owner
can overwrite them without a code-hash change. A view on a locked contract
is the stronger pin.

Unchanged when the page is hosted that way: no relay, no key added on
connect, the action string copied from `get_request`, signing disabled when
the approval contract's `code_hash` does not match, the wallet connector
pinned. Embedding the connector in the HTML is how that deploy drops the
CDN for the connector itself. Wallet executor scripts still come from each
wallet.

## Out of scope

Expiry, M-of-N, rejection reasons, key registration, revocation, and agent
`request_action`. The owner registers keys. The agent files requests. An
unregistered approver is told to ask the owner to run `add-approver.sh`.
