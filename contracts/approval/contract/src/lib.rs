//! NEAR contract for agent action approval.
//!
//! An agent requests an action by signing a `request_action` transaction with
//! its registered access key; the contract records the request and emits
//! `approval_requested`. An approver signs `approve` with its own registered
//! key, restating the action it reviewed; the contract records who approved,
//! when, and with which key, and emits `action_approved`. An approver can
//! instead `reject` a request (`action_rejected`). Approval proofs are
//! publicly readable per request (`get_approval`) or as a paged log
//! (`get_approvals`), and report whether either key behind them has since
//! been revoked. Key registry changes emit `key_added` / `key_revoked`.
//!
//! All authorization and state-transition logic lives in `approval-core`.
//! This crate only maps the NEAR runtime onto it: caller identity, block
//! time, storage, events and JSON views.
//!
//! Identity is the signing key, not just the account. Register each agent and
//! approver key with `add_agent` / `add_approver`. Registered keys must be
//! function-call access keys scoped to this contract: that is what makes
//! "the signer's own account called us" mean "the key holder called us".

use approval_core::{
    ActionRequest, ApprovalError, ApprovalProof, BlockTime, Caller, Principal, RegistrationId,
    RequestId, RequestStatus, Role, Store, DEFAULT_PAGE_SIZE,
};
use near_sdk::json_types::U64;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, CurveType, PanicOnDefault, PublicKey};

type Request = ActionRequest<AccountId, PublicKey>;
type Proof = ApprovalProof<AccountId, PublicKey>;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct ApprovalContract {
    owner: AccountId,
    principals: LookupMap<PublicKey, Principal<AccountId>>,
    requests: LookupMap<RequestId, Request>,
    request_count: u64,
    /// Approval index -> request id, in approval order.
    approval_log: LookupMap<u64, RequestId>,
    approval_count: u64,
    registration_count: u64,
    /// Registration id -> when that registration was revoked.
    revocations: LookupMap<RegistrationId, BlockTime>,
}

#[near(event_json(standard = "trust_approval"))]
pub enum ApprovalEvent {
    #[event_version("1.0.0")]
    ApprovalRequested(RequestView),
    #[event_version("1.0.0")]
    ActionApproved(ApprovalProofView),
    #[event_version("1.0.0")]
    ActionRejected(RejectionView),
    #[event_version("1.0.0")]
    KeyAdded(KeyView),
    #[event_version("1.0.0")]
    KeyRevoked(KeyRevokedView),
}

/// A block height and its nanosecond timestamp (a string, since it exceeds
/// JSON's safe integer range).
#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockTimeView {
    pub block: u64,
    pub ns: U64,
}

#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoleView {
    Agent,
    Approver,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalView {
    pub account_id: AccountId,
    pub role: RoleView,
    pub registration_id: RegistrationId,
    /// Pending requests made with this key (agent keys only).
    pub pending: u32,
}

/// Data of `key_added`.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyView {
    pub public_key: PublicKey,
    pub account_id: AccountId,
    pub role: RoleView,
    pub registration_id: RegistrationId,
}

/// Data of `key_revoked`. For an agent key, the `voided_pending` requests
/// made under this registration that were still pending are now void.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRevokedView {
    pub public_key: PublicKey,
    pub account_id: AccountId,
    pub role: RoleView,
    pub registration_id: RegistrationId,
    pub revoked_at_block: u64,
    pub revoked_at_ns: U64,
    pub voided_pending: u32,
}

/// `pending`: awaiting a decision. `approved` and `rejected`: final. `void`:
/// the agent key it was made with has been revoked, so it can never be
/// decided.
#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatusView {
    Pending,
    Approved,
    Rejected,
    Void,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestView {
    pub request_id: RequestId,
    pub agent_account_id: AccountId,
    pub agent_public_key: PublicKey,
    pub agent_registration_id: RegistrationId,
    pub action: String,
    pub requested_at_block: u64,
    pub requested_at_ns: U64,
    pub status: RequestStatusView,
}

/// Record that `approver_public_key` rejected request `request_id`.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectionView {
    pub request_id: RequestId,
    pub action: String,
    pub agent_account_id: AccountId,
    pub agent_public_key: PublicKey,
    pub agent_registration_id: RegistrationId,
    pub requested_at_block: u64,
    pub requested_at_ns: U64,
    pub approver_account_id: AccountId,
    pub approver_public_key: PublicKey,
    pub approver_registration_id: RegistrationId,
    pub rejected_at_block: u64,
    pub rejected_at_ns: U64,
}

/// Public proof that `approver_public_key` approved `action` as requested by
/// `agent_public_key`. Nanosecond timestamps are strings (`U64`) because
/// they exceed JSON's safe integer range.
///
/// Every field is fixed at approval except `agent_key_revoked_at` and
/// `approver_key_revoked_at`: they are `null` until the owner revokes the
/// registration (`*_registration_id`) the key acted under, and then report
/// when. In the `action_approved` event they are always `null`.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalProofView {
    pub approval_index: u64,
    pub request_id: RequestId,
    pub action: String,
    pub agent_account_id: AccountId,
    pub agent_public_key: PublicKey,
    pub agent_registration_id: RegistrationId,
    pub requested_at_block: u64,
    pub requested_at_ns: U64,
    pub approver_account_id: AccountId,
    pub approver_public_key: PublicKey,
    pub approver_registration_id: RegistrationId,
    pub approved_at_block: u64,
    pub approved_at_ns: U64,
    pub agent_key_revoked_at: Option<BlockTimeView>,
    pub approver_key_revoked_at: Option<BlockTimeView>,
}

#[near]
impl ApprovalContract {
    /// Initializes the contract with `owner_id` as the key administrator.
    /// Must be called by the contract account itself, e.g. in the deploy
    /// transaction signed by that account.
    #[init]
    #[private]
    pub fn new(owner_id: AccountId) -> Self {
        Self {
            owner: owner_id,
            principals: LookupMap::new(b"p".to_vec()),
            requests: LookupMap::new(b"r".to_vec()),
            request_count: 0,
            approval_log: LookupMap::new(b"a".to_vec()),
            approval_count: 0,
            registration_count: 0,
            revocations: LookupMap::new(b"v".to_vec()),
        }
    }

    /// Registers `public_key` as an agent key of `account_id`. Owner only.
    /// Emits `key_added`.
    pub fn add_agent(&mut self, account_id: AccountId, public_key: PublicKey) {
        self.add_principal(account_id, public_key, Role::Agent);
    }

    /// Registers `public_key` as an approver key of `account_id`. Owner only.
    /// Emits `key_added`.
    pub fn add_approver(&mut self, account_id: AccountId, public_key: PublicKey) {
        self.add_principal(account_id, public_key, Role::Approver);
    }

    /// Removes a key from the registry and records when. Owner only.
    /// Existing approvals remain, and their proofs report the revocation.
    /// Pending requests made with the key become void permanently, even if
    /// the key is registered again. Emits `key_revoked`.
    pub fn revoke_key(&mut self, public_key: PublicKey) {
        let caller = env::predecessor_account_id();
        let at = now();
        let removed = ok(approval_core::revoke_key(self, &caller, &public_key, at));
        ApprovalEvent::KeyRevoked(KeyRevokedView {
            public_key,
            account_id: removed.account_id,
            role: removed.role.into(),
            registration_id: removed.registration_id,
            revoked_at_block: at.height,
            revoked_at_ns: at.timestamp_ns.into(),
            voided_pending: removed.pending,
        })
        .emit();
    }

    /// Requests approval for `action` (1 to 2048 bytes). Must be called by
    /// the signing account with a registered agent key of that account, which
    /// may have at most 16 pending requests. Emits `approval_requested` and
    /// returns the request id.
    pub fn request_action(&mut self, action: String) -> RequestId {
        let request = ok(approval_core::request_action(
            self,
            &caller(),
            action,
            now(),
        ));
        ApprovalEvent::ApprovalRequested(self.request_view(&request)).emit();
        request.id
    }

    /// Approves pending request `request_id`. `action` must equal the
    /// request's action, so the approver's signed transaction commits to what
    /// it reviewed. Must be called by the signing account with a registered
    /// approver key of that account, and the approver account must differ
    /// from the agent's. Emits `action_approved` and returns the proof.
    pub fn approve(&mut self, request_id: RequestId, action: String) -> ApprovalProofView {
        let proof = ok(approval_core::approve(
            self,
            &caller(),
            request_id,
            &action,
            now(),
        ));
        let view = self.proof_view(proof);
        ApprovalEvent::ActionApproved(view.clone()).emit();
        view
    }

    /// Rejects pending request `request_id`, freeing a slot in the agent
    /// key's pending limit. A rejected request can never be approved. Must
    /// be called by the signing account with a registered approver key of
    /// that account, and the approver account must differ from the agent's.
    /// Emits `action_rejected` and returns the rejection.
    pub fn reject(&mut self, request_id: RequestId) -> RejectionView {
        let request = ok(approval_core::reject(self, &caller(), request_id, now()));
        let view = rejection_view(request).unwrap_or_else(|| env::abort());
        ApprovalEvent::ActionRejected(view.clone()).emit();
        view
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn get_principal(&self, public_key: PublicKey) -> Option<PrincipalView> {
        self.principal(&public_key).map(PrincipalView::from)
    }

    pub fn get_request(&self, request_id: RequestId) -> Option<RequestView> {
        self.request(request_id).map(|r| self.request_view(&r))
    }

    pub fn get_request_count(&self) -> u64 {
        self.request_count
    }

    /// Proof of approval for one request, or `None` if it is unknown,
    /// pending, rejected or void.
    pub fn get_approval(&self, request_id: RequestId) -> Option<ApprovalProofView> {
        approval_core::approval::<AccountId, PublicKey, _>(self, request_id)
            .map(|p| self.proof_view(p))
    }

    /// Rejection of one request, or `None` if it is not rejected.
    pub fn get_rejection(&self, request_id: RequestId) -> Option<RejectionView> {
        self.request(request_id).and_then(rejection_view)
    }

    /// When key registration `registration_id` was revoked, or `None` if it
    /// is live or was never issued.
    pub fn get_revocation(&self, registration_id: RegistrationId) -> Option<BlockTimeView> {
        self.revocation(registration_id).map(Into::into)
    }

    /// Approval proofs in approval order, starting at `from_index` (default 0)
    /// of the approval log. `limit` defaults to 50 and is capped at 100, so
    /// page until an empty page comes back, not until a page is short.
    pub fn get_approvals(
        &self,
        from_index: Option<u64>,
        limit: Option<u64>,
    ) -> Vec<ApprovalProofView> {
        approval_core::approvals::<AccountId, PublicKey, _>(
            self,
            from_index.unwrap_or(0),
            limit.unwrap_or(DEFAULT_PAGE_SIZE),
        )
        .into_iter()
        .map(|p| self.proof_view(p))
        .collect()
    }

    pub fn get_approval_count(&self) -> u64 {
        self.approval_count
    }
}

impl ApprovalContract {
    fn add_principal(&mut self, account_id: AccountId, public_key: PublicKey, role: Role) {
        let caller = env::predecessor_account_id();
        // A 1952-byte ML-DSA-65 key prints as about 2.6 KB of base58. With one
        // on both the agent and the approver side, a 2048-byte action's
        // `action_approved` line exceeds NEAR's 16 KiB log limit, so that
        // approver could never approve the request. Refused after the owner
        // check (non-owners still get NotOwner first) and before any write.
        if caller == self.owner && public_key.curve_type() == CurveType::MLDSA65 {
            env::panic_str(UNSUPPORTED_KEY_TYPE);
        }
        let added = ok(approval_core::add_principal(
            self,
            &caller,
            public_key.clone(),
            account_id,
            role,
        ));
        ApprovalEvent::KeyAdded(KeyView {
            public_key,
            account_id: added.account_id,
            role: added.role.into(),
            registration_id: added.registration_id,
        })
        .emit();
    }

    fn proof_view(&self, proof: Proof) -> ApprovalProofView {
        let revoked = approval_core::proof_revocations(self, &proof);
        ApprovalProofView {
            approval_index: proof.approval_index,
            request_id: proof.request_id,
            action: proof.action,
            agent_account_id: proof.agent_account_id,
            agent_public_key: proof.agent_key,
            agent_registration_id: proof.agent_registration_id,
            requested_at_block: proof.requested_at.height,
            requested_at_ns: proof.requested_at.timestamp_ns.into(),
            approver_account_id: proof.approver_account_id,
            approver_public_key: proof.approver_key,
            approver_registration_id: proof.approver_registration_id,
            approved_at_block: proof.approved_at.height,
            approved_at_ns: proof.approved_at.timestamp_ns.into(),
            agent_key_revoked_at: revoked.agent.map(Into::into),
            approver_key_revoked_at: revoked.approver.map(Into::into),
        }
    }

    fn request_view(&self, r: &Request) -> RequestView {
        let status = match approval_core::status_of(self, r) {
            RequestStatus::Pending => RequestStatusView::Pending,
            RequestStatus::Approved => RequestStatusView::Approved,
            RequestStatus::Rejected => RequestStatusView::Rejected,
            RequestStatus::Void => RequestStatusView::Void,
        };
        RequestView {
            request_id: r.id,
            agent_account_id: r.agent_account_id.clone(),
            agent_public_key: r.agent_key.clone(),
            agent_registration_id: r.agent_registration_id,
            action: r.action.clone(),
            requested_at_block: r.requested_at.height,
            requested_at_ns: r.requested_at.timestamp_ns.into(),
            status,
        }
    }
}

impl Store<AccountId, PublicKey> for ApprovalContract {
    fn owner(&self) -> &AccountId {
        &self.owner
    }

    fn principal(&self, key: &PublicKey) -> Option<Principal<AccountId>> {
        self.principals.get(key).cloned()
    }

    fn insert_principal(&mut self, key: PublicKey, principal: Principal<AccountId>) {
        self.principals.insert(key, principal);
    }

    fn remove_principal(&mut self, key: &PublicKey) -> Option<Principal<AccountId>> {
        self.principals.remove(key)
    }

    fn request_count(&self) -> u64 {
        self.request_count
    }

    fn request(&self, id: RequestId) -> Option<Request> {
        self.requests.get(&id).cloned()
    }

    fn push_request(&mut self, request: Request) {
        self.requests.insert(self.request_count, request);
        self.request_count += 1;
    }

    fn replace_request(&mut self, request: Request) {
        self.requests.insert(request.id, request);
    }

    fn approval_count(&self) -> u64 {
        self.approval_count
    }

    fn approved_request_id(&self, approval_index: u64) -> Option<RequestId> {
        self.approval_log.get(&approval_index).copied()
    }

    fn push_approval(&mut self, request_id: RequestId) {
        self.approval_log.insert(self.approval_count, request_id);
        self.approval_count += 1;
    }

    fn registration_count(&self) -> u64 {
        self.registration_count
    }

    fn increment_registration_count(&mut self) {
        self.registration_count += 1;
    }

    fn revocation(&self, registration_id: RegistrationId) -> Option<BlockTime> {
        self.revocations.get(&registration_id).copied()
    }

    fn insert_revocation(&mut self, registration_id: RegistrationId, revoked_at: BlockTime) {
        self.revocations.insert(registration_id, revoked_at);
    }
}

fn caller() -> Caller<AccountId, PublicKey> {
    Caller {
        predecessor: env::predecessor_account_id(),
        signer: env::signer_account_id(),
        signer_key: env::signer_account_pk(),
    }
}

fn now() -> BlockTime {
    BlockTime {
        height: env::block_height(),
        timestamp_ns: env::block_timestamp(),
    }
}

/// Panic message of `add_agent` / `add_approver` for an ML-DSA-65 key.
pub const UNSUPPORTED_KEY_TYPE: &str = "ML-DSA-65 keys are not supported";

fn ok<T>(result: Result<T, ApprovalError>) -> T {
    result.unwrap_or_else(|e| env::panic_str(e.as_str()))
}

fn rejection_view(r: Request) -> Option<RejectionView> {
    let rejection = r.rejection?;
    Some(RejectionView {
        request_id: r.id,
        action: r.action,
        agent_account_id: r.agent_account_id,
        agent_public_key: r.agent_key,
        agent_registration_id: r.agent_registration_id,
        requested_at_block: r.requested_at.height,
        requested_at_ns: r.requested_at.timestamp_ns.into(),
        approver_account_id: rejection.approver_account_id,
        approver_public_key: rejection.approver_key,
        approver_registration_id: rejection.approver_registration_id,
        rejected_at_block: rejection.rejected_at.height,
        rejected_at_ns: rejection.rejected_at.timestamp_ns.into(),
    })
}

impl From<Role> for RoleView {
    fn from(role: Role) -> Self {
        match role {
            Role::Agent => RoleView::Agent,
            Role::Approver => RoleView::Approver,
        }
    }
}

impl From<BlockTime> for BlockTimeView {
    fn from(t: BlockTime) -> Self {
        Self {
            block: t.height,
            ns: t.timestamp_ns.into(),
        }
    }
}

impl From<Principal<AccountId>> for PrincipalView {
    fn from(p: Principal<AccountId>) -> Self {
        Self {
            account_id: p.account_id,
            role: p.role.into(),
            registration_id: p.registration_id,
            pending: p.pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::serde_json::{self, json, Value};
    use near_sdk::test_utils::{accounts, get_logs, VMContextBuilder};
    use near_sdk::testing_env;

    // ed25519 keys whose 32 bytes are all 1, 2 and 3 respectively.
    const AGENT_PK: &str = "ed25519:4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
    const APPROVER_PK: &str = "ed25519:8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
    const OTHER_PK: &str = "ed25519:CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8";

    fn pk(s: &str) -> PublicKey {
        s.parse().unwrap()
    }

    fn owner() -> AccountId {
        accounts(0)
    }

    fn agent() -> AccountId {
        accounts(1)
    }

    fn approver() -> AccountId {
        accounts(2)
    }

    fn contract_id() -> AccountId {
        "approvals.near".parse().unwrap()
    }

    fn context(predecessor: AccountId, signer: AccountId, key: &str, height: u64) {
        testing_env!(VMContextBuilder::new()
            .current_account_id(contract_id())
            .predecessor_account_id(predecessor)
            .signer_account_id(signer)
            .signer_account_pk(pk(key))
            .block_height(height)
            .block_timestamp(height * 1_000_000_000)
            .build());
    }

    fn signed_by(account: AccountId, key: &str, height: u64) {
        context(account.clone(), account, key, height);
    }

    /// Round-trips the contract through storage, as the runtime does between
    /// calls, so every read after this comes from serialized state.
    fn reload(c: ApprovalContract) -> ApprovalContract {
        env::state_write(&c);
        drop(c); // flushes the LookupMap write caches
        env::state_read().expect("contract state")
    }

    fn setup() -> ApprovalContract {
        signed_by(contract_id(), OTHER_PK, 1);
        let mut c = ApprovalContract::new(owner());
        signed_by(owner(), OTHER_PK, 1);
        c.add_agent(agent(), pk(AGENT_PK));
        c.add_approver(approver(), pk(APPROVER_PK));
        reload(c)
    }

    /// Parses the single NEP-297 event logged by the last call.
    fn event() -> Value {
        let logs = get_logs();
        assert_eq!(logs.len(), 1, "expected exactly one log: {logs:?}");
        let json = logs[0].strip_prefix("EVENT_JSON:").expect("NEP-297 prefix");
        serde_json::from_str(json).unwrap()
    }

    fn to_json<T: near_sdk::serde::Serialize>(value: T) -> Value {
        serde_json::to_value(value).unwrap()
    }

    #[test]
    fn request_and_approve_emit_events_and_publish_proof() {
        let mut c = setup();
        let action = "transfer 5 NEAR to bob.near";

        signed_by(agent(), AGENT_PK, 10);
        let id = c.request_action(action.into());
        assert_eq!(id, 0);
        let requested = json!({
            "request_id": 0,
            "agent_account_id": agent(),
            "agent_public_key": AGENT_PK,
            "agent_registration_id": 0,
            "action": action,
            "requested_at_block": 10,
            "requested_at_ns": "10000000000",
            "status": "pending",
        });
        assert_eq!(
            event(),
            json!({
                "standard": "trust_approval",
                "version": "1.0.0",
                "event": "approval_requested",
                "data": requested,
            })
        );
        let mut c = reload(c);
        assert_eq!(to_json(c.get_request(id)), requested);
        assert_eq!(c.get_approval(id), None);

        signed_by(approver(), APPROVER_PK, 12);
        let proof = c.approve(id, action.into());
        let approved = json!({
            "approval_index": 0,
            "request_id": 0,
            "action": action,
            "agent_account_id": agent(),
            "agent_public_key": AGENT_PK,
            "agent_registration_id": 0,
            "requested_at_block": 10,
            "requested_at_ns": "10000000000",
            "approver_account_id": approver(),
            "approver_public_key": APPROVER_PK,
            "approver_registration_id": 1,
            "approved_at_block": 12,
            "approved_at_ns": "12000000000",
            "agent_key_revoked_at": null,
            "approver_key_revoked_at": null,
        });
        assert_eq!(
            event(),
            json!({
                "standard": "trust_approval",
                "version": "1.0.0",
                "event": "action_approved",
                "data": approved,
            })
        );
        assert_eq!(to_json(&proof), approved);

        let c = reload(c);
        assert_eq!(c.get_approval(id), Some(proof.clone()));
        assert_eq!(c.get_approvals(None, None), vec![proof]);
        assert_eq!(
            c.get_request(id).unwrap().status,
            RequestStatusView::Approved
        );
        assert_eq!((c.get_request_count(), c.get_approval_count()), (1, 1));
        assert_eq!(c.get_request(1), None);
        assert_eq!(c.get_approval(1), None);
    }

    #[test]
    fn reject_emits_event_and_is_readable() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let id = c.request_action("wipe disk".into());
        signed_by(approver(), APPROVER_PK, 3);
        let rejection = c.reject(id);
        let expected = json!({
            "request_id": 0,
            "action": "wipe disk",
            "agent_account_id": agent(),
            "agent_public_key": AGENT_PK,
            "agent_registration_id": 0,
            "requested_at_block": 2,
            "requested_at_ns": "2000000000",
            "approver_account_id": approver(),
            "approver_public_key": APPROVER_PK,
            "approver_registration_id": 1,
            "rejected_at_block": 3,
            "rejected_at_ns": "3000000000",
        });
        assert_eq!(
            event(),
            json!({
                "standard": "trust_approval",
                "version": "1.0.0",
                "event": "action_rejected",
                "data": expected,
            })
        );
        assert_eq!(to_json(&rejection), expected);
        let c = reload(c);
        assert_eq!(c.get_rejection(id), Some(rejection));
        assert_eq!(
            c.get_request(id).unwrap().status,
            RequestStatusView::Rejected
        );
        assert_eq!(c.get_approval(id), None);
        assert_eq!(c.get_principal(pk(AGENT_PK)).unwrap().pending, 0);
    }

    #[test]
    #[should_panic(expected = "request is already rejected")]
    fn rejected_request_cannot_be_approved() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let id = c.request_action("x".into());
        signed_by(approver(), APPROVER_PK, 3);
        c.reject(id);
        let mut c = reload(c);
        c.approve(id, "x".into());
    }

    #[test]
    fn key_changes_emit_events() {
        signed_by(contract_id(), OTHER_PK, 1);
        let mut c = ApprovalContract::new(owner());
        signed_by(owner(), OTHER_PK, 1);
        c.add_agent(agent(), pk(AGENT_PK));
        assert_eq!(
            event(),
            json!({
                "standard": "trust_approval",
                "version": "1.0.0",
                "event": "key_added",
                "data": {
                    "public_key": AGENT_PK,
                    "account_id": agent(),
                    "role": "agent",
                    "registration_id": 0,
                },
            })
        );
        signed_by(agent(), AGENT_PK, 2);
        c.request_action("x".into());
        c.request_action("y".into());
        signed_by(owner(), OTHER_PK, 7);
        c.revoke_key(pk(AGENT_PK));
        assert_eq!(
            event(),
            json!({
                "standard": "trust_approval",
                "version": "1.0.0",
                "event": "key_revoked",
                "data": {
                    "public_key": AGENT_PK,
                    "account_id": agent(),
                    "role": "agent",
                    "registration_id": 0,
                    "revoked_at_block": 7,
                    "revoked_at_ns": "7000000000",
                    "voided_pending": 2,
                },
            })
        );
    }

    #[test]
    fn proofs_report_later_key_revocation() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let id = c.request_action("x".into());
        signed_by(approver(), APPROVER_PK, 3);
        let at_approval = c.approve(id, "x".into());
        assert_eq!(at_approval.approver_key_revoked_at, None);
        signed_by(owner(), OTHER_PK, 9);
        c.revoke_key(pk(APPROVER_PK));
        // A new registration of the same key does not clear the old one's
        // revocation.
        c.add_approver(approver(), pk(APPROVER_PK));
        let c = reload(c);
        let revoked = Some(BlockTimeView {
            block: 9,
            ns: 9_000_000_000.into(),
        });
        let proof = c.get_approval(id).unwrap();
        assert_eq!(proof.approver_key_revoked_at, revoked);
        assert_eq!(proof.agent_key_revoked_at, None);
        assert_eq!(c.get_approvals(None, None), vec![proof.clone()]);
        assert_eq!(
            ApprovalProofView {
                approver_key_revoked_at: None,
                ..proof
            },
            at_approval
        );
        assert_eq!(c.get_revocation(1), revoked);
        assert_eq!(c.get_revocation(0), None);
        assert_eq!(c.get_principal(pk(APPROVER_PK)).unwrap().registration_id, 2);
    }

    #[test]
    fn approvals_are_paged_in_approval_order() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let ids: Vec<_> = (0..4)
            .map(|i| c.request_action(format!("action {i}")))
            .collect();
        signed_by(approver(), APPROVER_PK, 3);
        for &i in &[2, 0, 3] {
            c.approve(ids[i], format!("action {i}"));
        }
        let c = reload(c);
        let page = |from, limit| -> Vec<RequestId> {
            c.get_approvals(from, limit)
                .iter()
                .map(|p| p.request_id)
                .collect()
        };
        assert_eq!(page(None, None), vec![2, 0, 3]);
        assert_eq!(page(Some(1), Some(1)), vec![0]);
        assert_eq!(page(Some(3), None), Vec::<RequestId>::new());
    }

    #[test]
    fn approvals_page_defaults_and_cap() {
        let mut c = setup();
        for _ in 0..105 {
            signed_by(agent(), AGENT_PK, 2);
            let id = c.request_action("x".into());
            signed_by(approver(), APPROVER_PK, 3);
            c.approve(id, "x".into());
        }
        let c = reload(c);
        assert_eq!(c.get_approvals(None, None).len(), 50);
        assert_eq!(c.get_approvals(None, Some(500)).len(), 100);
        assert_eq!(c.get_approvals(Some(100), Some(500)).len(), 5);
    }

    #[test]
    fn principal_registry_is_readable() {
        let c = setup();
        assert_eq!(
            to_json(c.get_principal(pk(AGENT_PK))),
            json!({ "account_id": agent(), "role": "agent", "registration_id": 0, "pending": 0 })
        );
        assert_eq!(
            to_json(c.get_principal(pk(APPROVER_PK))),
            json!({ "account_id": approver(), "role": "approver", "registration_id": 1, "pending": 0 })
        );
        assert_eq!(c.get_principal(pk(OTHER_PK)), None);
        assert_eq!(c.get_owner(), owner());
    }

    #[test]
    fn revoked_agent_requests_show_as_void() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let id = c.request_action("x".into());
        signed_by(owner(), OTHER_PK, 3);
        c.revoke_key(pk(AGENT_PK));
        c.add_agent(agent(), pk(AGENT_PK));
        let c = reload(c);
        assert_eq!(c.get_request(id).unwrap().status, RequestStatusView::Void);
    }

    #[test]
    fn owner_may_be_a_contract_account() {
        // e.g. a multisig: the owner account is the predecessor, a member signs.
        let mut c = setup();
        context(owner(), accounts(3), OTHER_PK, 2);
        c.add_approver(accounts(4), pk(OTHER_PK));
        c.revoke_key(pk(OTHER_PK));
        assert_eq!(c.get_principal(pk(OTHER_PK)), None);
    }

    fn mldsa65_key() -> PublicKey {
        PublicKey::from_parts(CurveType::MLDSA65, vec![7; 1952]).unwrap()
    }

    #[test]
    #[should_panic(expected = "ML-DSA-65 keys are not supported")]
    fn mldsa65_agent_key_is_refused() {
        let mut c = setup();
        c.add_agent(accounts(3), mldsa65_key());
    }

    #[test]
    #[should_panic(expected = "ML-DSA-65 keys are not supported")]
    fn mldsa65_approver_key_is_refused() {
        let mut c = setup();
        c.add_approver(accounts(3), mldsa65_key());
    }

    #[test]
    #[should_panic(expected = "only the owner can manage keys")]
    fn mldsa65_key_from_a_non_owner_fails_not_owner_first() {
        let mut c = setup();
        signed_by(accounts(3), OTHER_PK, 2);
        c.add_agent(accounts(3), mldsa65_key());
    }

    #[test]
    #[should_panic(expected = "only the owner can manage keys")]
    fn owner_signature_relayed_by_another_contract_cannot_add_keys() {
        let mut c = setup();
        context(accounts(3), owner(), OTHER_PK, 2);
        c.add_approver(accounts(3), pk(OTHER_PK));
    }

    #[test]
    #[should_panic(expected = "only the owner can manage keys")]
    fn owner_signature_relayed_by_another_contract_cannot_revoke_keys() {
        let mut c = setup();
        context(accounts(3), owner(), OTHER_PK, 2);
        c.revoke_key(pk(APPROVER_PK));
    }

    #[test]
    #[should_panic(expected = "only the owner can manage keys")]
    fn only_owner_registers_keys() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        c.add_approver(agent(), pk(OTHER_PK));
    }

    #[test]
    #[should_panic(expected = "signing key is unknown")]
    fn agent_account_with_unregistered_key_cannot_request() {
        let mut c = setup();
        signed_by(agent(), OTHER_PK, 2);
        c.request_action("x".into());
    }

    #[test]
    #[should_panic(expected = "caller must be the signing account")]
    fn request_relayed_through_another_contract_is_rejected() {
        let mut c = setup();
        context(accounts(3), agent(), AGENT_PK, 2);
        c.request_action("x".into());
    }

    #[test]
    #[should_panic(expected = "signing key has the wrong role")]
    fn agent_key_cannot_approve() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let id = c.request_action("x".into());
        c.approve(id, "x".into());
    }

    #[test]
    #[should_panic(expected = "action does not match the request")]
    fn approval_must_restate_the_action() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let id = c.request_action("pay 5".into());
        signed_by(approver(), APPROVER_PK, 3);
        c.approve(id, "pay 50".into());
    }

    #[test]
    #[should_panic(expected = "request is already approved")]
    fn request_cannot_be_approved_twice() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let id = c.request_action("x".into());
        signed_by(approver(), APPROVER_PK, 3);
        c.approve(id, "x".into());
        let mut c = reload(c);
        c.approve(id, "x".into());
    }

    #[test]
    #[should_panic(expected = "request is void: its agent key was revoked")]
    fn revoked_agent_request_cannot_be_approved() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        let id = c.request_action("x".into());
        signed_by(owner(), OTHER_PK, 3);
        c.revoke_key(pk(AGENT_PK));
        signed_by(approver(), APPROVER_PK, 4);
        c.approve(id, "x".into());
    }

    #[test]
    #[should_panic(expected = "agent key has too many pending requests")]
    fn pending_requests_are_capped() {
        let mut c = setup();
        signed_by(agent(), AGENT_PK, 2);
        for _ in 0..=approval_core::MAX_PENDING_PER_KEY {
            c.request_action("x".into());
        }
    }
}
