# Security

Report a vulnerability privately through [GitHub Security Advisories](https://github.com/difflabai/trust-framework/security/advisories/new) on this repository. Do not open a public issue for an unfixed flaw.

## Known limitations

These are the approval contract's design, not surprises.

- Approvals do not expire and are not consumed. An executor has to deduplicate on (contract account, `request_id`) and apply its own maximum age.
- The owner chooses who is an approver. There is no ownership transfer and no upgrade method.
- A full-access key can still be relayed by a contract on the signer's own account. Function-call keys scoped to this contract are the deployment requirement.
- Logs from failed receipts stay visible. Ignore events from receipts that did not succeed.
- `add_agent` and `add_approver` refuse ML-DSA-65 keys.
- The testnet demonstration account can still be redeployed. A matching `code_hash` on one read is not a lock.

The checks a verifier should make are in [`contracts/approval/README.md`](contracts/approval/README.md#verifying-a-proof-off-chain).
