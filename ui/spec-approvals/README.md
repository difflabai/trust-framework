# Spec approval UI

A page for a spec reviewer. It walks the 23 requirements (R1–R6, D1–D17)
one sentence at a time and signs `approve` or `reject` on the approval
contract for each one. The full packet review is
[`../spec-approvals-full/`](../spec-approvals-full/README.md). Both pages
share `../shared/spec-app.js`.

For each requirement it shows:

- the sentence from `requirement/2` in `approval_req.pl`, which is what you sign;
- the properties `traceability.pl` says discharge that sentence;
- what to check before approving.

The property text under a sentence is the proof obligation. You are signing
the sentence, and that those properties are the right discharge, not the
proof obligation as if it were the requirement.

The packet is [`packets/requirements.json`](packets/requirements.json). It
is built from formalver's `approval_req.pl`, `traceability.pl`, `status.toml`
and `strategy.md` at the same commits as the full packet.

## Run

```bash
cd ui && python3 -m http.server 8080
```

Open <http://127.0.0.1:8080/spec-approvals/>. Serve from `ui/`, not from
this directory: the page loads `../shared/`. Use HTTP on localhost, not
`file://`. There is nothing to install or build.

| Param | Default |
|---|---|
| `packet` | `requirements`, which loads `packets/requirements.json` |
| `item` | the first requirement. Opens that requirement. |
| `agent` | `agent1.<parent>` for `approvals.<parent>` (`data-agent`). A short name is expanded the same way. Only requests filed by this account count. |
| `contract`, `network`, `rpc`, `code_hash` | as in [`../approvals/`](../approvals/README.md) |

The same agent can file this packet and the full packet. The page matches a
request by the action text, which names this packet id, so the two reviews
do not collide.

## Flow

1. The owner files the packet, one request per requirement:

   ```bash
   scripts/near/submit-spec-packet.sh --packet ui/spec-approvals/packets/requirements.json --dry-run
   scripts/near/submit-spec-packet.sh --packet ui/spec-approvals/packets/requirements.json
   scripts/near/submit-spec-packet.sh --packet ui/spec-approvals/packets/requirements.json --item D5
   ```

   The script reads its credentials from `.env`, like every script in
   `scripts/near/` (see [its README](../../scripts/near/README.md)). It is
   idempotent: re-running it files only the requirements that are missing.
   Open the page with `?agent=<that account>` if the agent is not `agent1`.

2. The owner registers the reviewer's wallet key as an approver:

   ```bash
   scripts/near/add-approver.sh <reviewer-account> <public-key> --force
   ```

   `--force` is needed because a browser wallet signs with a full-access
   key. The reviewer's account must not be the agent account.

3. The reviewer opens the page and connects their wallet. For each
   requirement they read the sentence and the properties that discharge it,
   tick each reading and check line, and then either approve or reject it.
   Approve stays disabled until every line is ticked. Reject needs a note
   first. Ticks and notes are kept in the browser (localStorage), keyed by
   the requirement's hash.

4. **Export review** downloads a JSON record of the review: each
   requirement's hash, request id, status, who decided it, and the
   reviewer's note.

## What an approval binds to

Each request's action is five lines:

```text
spec-review/1
packet: requirements 2026-10-30
item: D5
title: Separation of duties: an approver cannot approve or reject a request made by an agent key bound to the same account
sha256: …
```

The hash covers the sentence, the properties named as its discharge (their
status.toml records), the assumptions and findings those records name, the
packet header and the source commits. Each reading entry also carries the
sha256 of its file at the pinned commit. The format is the same as the full
packet, defined in
[`scripts/near/spec_packet.py`](../../scripts/near/spec_packet.py).
[`../shared/spec-kit.js`](../shared/spec-kit.js) computes the same value.

The page recomputes each hash from the packet file it loaded and matches
requests by exact action. If the file served to the browser differs from
the one that was filed, no request matches it and nothing can be approved.

## Rebuilding the packet

```bash
ui/spec-approvals/tools/build-packet.py --formalver ~/src/formalver --trust-framework .
ui/spec-approvals-full/tools/check-hashes.sh     # Python and JS agree on every hash
```

`packets/requirements.src.json` pins the commits. A new review round needs
a new `packet.version`. Changing a sentence or its discharge changes its
hash, so any request filed for the old text shows up as outdated.

## What the page will not do

It will not file requests, register keys, or relay a transaction. It will
not sign while the contract's `code_hash` differs from the expected one, or
for a request filed by the connected account. It will not approve a
request whose action differs from the packet text it loaded. Signing goes
through the same pinned NEAR Connect script as `../approvals/`, using the
shared code in `../shared/approval-kit.js` and `../shared/spec-app.js`.
