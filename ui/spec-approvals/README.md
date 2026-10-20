# Spec approval UI

A page for a spec reviewer. It walks a spec review packet item by item and
signs `approve` or `reject` on the approval contract for each one. For each
item it shows:

- what to read, with links to the exact file and lines at the pinned commits;
- what to check;
- the properties, assumptions and findings the item covers.

The packet for the NEAR approval contract is
[`packets/near-approval.json`](packets/near-approval.json). It is built from
formalver's spec review packet, `status.toml` and `strategy.md`.

## Run

```bash
cd ui && python3 -m http.server 8080
```

Open <http://127.0.0.1:8080/spec-approvals/>. Serve from `ui/`, not from
this directory: the page loads `../shared/`. Use HTTP on localhost, not
`file://`. There is nothing to install or build.

| Param | Default |
|---|---|
| `packet` | `near-approval`, which loads `packets/near-approval.json` |
| `item` | the first item. Opens that item. |
| `agent` | `spec-agent.<parent>` for `approvals.<parent>`. Only requests filed by this account count. |
| `contract`, `network`, `rpc`, `code_hash` | as in [`../approvals/`](../approvals/README.md) |

## Flow

1. The owner files the packet, one request per item:

   ```bash
   scripts/near/submit-spec-packet.sh --dry-run        # plan; sends nothing
   scripts/near/submit-spec-packet.sh --setup-agent    # first run: creates spec-agent.<NEAR_ACCOUNT_ID>
   ```

   The script reads its credentials from `.env`, like every script in
   `scripts/near/` (see [its README](../../scripts/near/README.md)). It is
   idempotent: re-running it files only the items that are missing.

2. The owner registers the reviewer's wallet key as an approver:

   ```bash
   scripts/near/add-approver.sh <reviewer-account> <public-key> --force
   ```

   `--force` is needed because a browser wallet signs with a full-access
   key. The reviewer's account must not be the agent account.

3. The reviewer opens the page and connects their wallet. For each item they
   read the linked material, tick each reading and check line, and then
   either approve or reject it. Approve stays disabled until every line is
   ticked. Reject needs a note first. Ticks and notes are kept in the
   browser (localStorage), keyed by the item's hash.

4. **Export review** downloads a JSON record of the review: each item's
   hash, request id, status, who decided it, and the reviewer's note. The
   record goes with the PR that sets `[review] spec_reviewer` in formalver.

## What an approval binds to

Each request's action is five lines:

```text
spec-review/1
packet: near-approval 2026-10-20
item: D1
title: Verus spec machine and lemma statements
sha256: 363f5cba…
```

The hash covers the item's canonical JSON, together with its properties,
assumptions and findings, the packet header and the source commits. Each
reading entry also carries the sha256 of its file at the pinned commit. The
format is defined in
[`scripts/near/spec_packet.py`](../../scripts/near/spec_packet.py), and
[`spec-kit.js`](spec-kit.js) computes the same value.

The page recomputes each hash from the packet file it loaded and matches
requests by exact action. If the file served to the browser differs from
the one that was filed, no request matches it and nothing can be approved.

Requests filed for an earlier text of an item (same packet and item, a
different hash) are listed as outdated. The page offers to reject them. The
contract has no way to withdraw a request.

## Rebuilding a packet

```bash
ui/spec-approvals/tools/build-packet.py --formalver ~/src/formalver --trust-framework .
ui/spec-approvals/tools/check-hashes.sh     # Python and JS agree on every hash
```

`packets/near-approval.src.json` holds the items and pins the commits.
Every file is read with `git show <commit>:<path>`, so the clones only need
those commits fetched. A new review round needs a new `packet.version`.
Changing an item's text changes its hash, so any request filed for the old
text shows up as outdated.

## What the page will not do

It will not file requests, register keys, or relay a transaction. It will
not sign while the contract's `code_hash` differs from the expected one, or
for a request filed by the connected account. It will not approve a
request whose action differs from the packet text it loaded. Signing goes
through the same pinned NEAR Connect script as `../approvals/`, using the
shared code in `../shared/approval-kit.js`.
