# Trust framework

Projects for enforcing trust boundaries.

[MIT](LICENSE) licensed. Security reports go to [SECURITY.md](SECURITY.md).

## Production usage

Nothing here yet.

## Development usage

### Approval contract

A NEAR contract that records an agent's request to act and an approver's decision, each signed by its own key. Proofs are public.

- Contract: [`contracts/approval`](contracts/approval/README.md)
- Operations: [`scripts/near`](scripts/near/README.md)
- Approver page: [`ui/approvals`](ui/approvals/README.md)
- Spec review page: [`ui/spec-approvals`](ui/spec-approvals/README.md)

The testnet demonstration is [`approvals.difflabai.testnet`](https://testnet.nearblocks.io/address/approvals.difflabai.testnet), owned by `difflabai.testnet`. It can still be redeployed. Set `NEAR_ACCOUNT_ID` to point the scripts at it, or at your own account. `APPROVAL_CONTRACT_ID` defaults to `approvals.<NEAR_ACCOUNT_ID>`.

## In progress

No release. No CI.

- **Guards** (`guards/`): input and output guard pipeline, adapters, `trust-proxy`, `trust-server`. The Prolog evaluator is a stub.
- **Adjudicator** (`adjudicator/`): policy scoring of proposed agent output.
- **Ledger** (`ledger/`): signed verdict recording across a few backends.

How the pieces fit is in [Architecture.md](Architecture.md).
