//! NEAR contract for agent action approval.
//!
//! An agent requests an action by signing a `request_action` transaction with
//! its registered access key; the contract records the request and emits
//! `approval_requested`. An approver signs `approve` with its own registered
//! key, restating the action it reviewed; the contract records who approved,
//! when, and with which key, and emits `action_approved`. Approval proofs are
//! publicly readable per request (`get_approval`) or as a paged log
//! (`get_approvals`).
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
    ActionRequest, ApprovalError, ApprovalProof, BlockTime, Caller, Principal, RequestId,
    RequestStatus, Role, Store, DEFAULT_PAGE_SIZE,
};
use near_sdk::json_types::U64;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, PanicOnDefault, PublicKey};

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
}

#[near(event_json(standard = "trust_approval"))]
pub enum ApprovalEvent {
    #[event_version("1.0.0")]
    ApprovalRequested(RequestView),
    #[event_version("1.0.0")]
    ActionApproved(ApprovalProofView),
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
    /// Pending requests made with this key (agent keys only).
    pub pending: u32,
}

/// `pending`: awaiting approval. `approved`: final. `void`: the agent key it
/// was made with has been revoked, so it can never be approved.
#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatusView {
    Pending,
    Approved,
    Void,
}

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestView {
    pub request_id: RequestId,
    pub agent_account_id: AccountId,
    pub agent_public_key: PublicKey,
    pub action: String,
    pub requested_at_block: u64,
    pub requested_at_ns: U64,
    pub status: RequestStatusView,
}

/// Public proof that `approver_public_key` approved `action` as requested by
/// `agent_public_key`. Nanosecond timestamps are strings (`U64`) because
/// they exceed JSON's safe integer range.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalProofView {
    pub approval_index: u64,
    pub request_id: RequestId,
    pub action: String,
    pub agent_account_id: AccountId,
    pub agent_public_key: PublicKey,
    pub requested_at_block: u64,
    pub requested_at_ns: U64,
    pub approver_account_id: AccountId,
    pub approver_public_key: PublicKey,
    pub approved_at_block: u64,
    pub approved_at_ns: U64,
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
        }
    }

    /// Registers `public_key` as an agent key of `account_id`. Owner only.
    pub fn add_agent(&mut self, account_id: AccountId, public_key: PublicKey) {
        self.add_principal(account_id, public_key, Role::Agent);
    }

    /// Registers `public_key` as an approver key of `account_id`. Owner only.
    pub fn add_approver(&mut self, account_id: AccountId, public_key: PublicKey) {
        self.add_principal(account_id, public_key, Role::Approver);
    }

    /// Removes a key from the registry. Owner only. Existing approvals remain
    /// valid. Pending requests made with the key become void permanently,
    /// even if the key is registered again.
    pub fn revoke_key(&mut self, public_key: PublicKey) {
        let caller = env::predecessor_account_id();
        ok(approval_core::revoke_key(self, &caller, &public_key));
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
        let view = ApprovalProofView::from(proof);
        ApprovalEvent::ActionApproved(view.clone()).emit();
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
    /// pending or void.
    pub fn get_approval(&self, request_id: RequestId) -> Option<ApprovalProofView> {
        approval_core::approval::<AccountId, PublicKey, _>(self, request_id).map(Into::into)
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
        .map(Into::into)
        .collect()
    }

    pub fn get_approval_count(&self) -> u64 {
        self.approval_count
    }
}

impl ApprovalContract {
    fn add_principal(&mut self, account_id: AccountId, public_key: PublicKey, role: Role) {
        let caller = env::predecessor_account_id();
        ok(approval_core::add_principal(
            self, &caller, public_key, account_id, role,
        ));
    }

    fn request_view(&self, r: &Request) -> RequestView {
        let status = match approval_core::request_status::<AccountId, PublicKey, _>(self, r.id) {
            Some(RequestStatus::Approved) => RequestStatusView::Approved,
            Some(RequestStatus::Void) => RequestStatusView::Void,
            Some(RequestStatus::Pending) | None => RequestStatusView::Pending,
        };
        RequestView {
            request_id: r.id,
            agent_account_id: r.agent_account_id.clone(),
            agent_public_key: r.agent_key.clone(),
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

fn ok<T>(result: Result<T, ApprovalError>) -> T {
    result.unwrap_or_else(|e| env::panic_str(e.as_str()))
}

impl From<Principal<AccountId>> for PrincipalView {
    fn from(p: Principal<AccountId>) -> Self {
        let role = match p.role {
            Role::Agent => RoleView::Agent,
            Role::Approver => RoleView::Approver,
        };
        Self {
            account_id: p.account_id,
            role,
            pending: p.pending,
        }
    }
}

impl From<Proof> for ApprovalProofView {
    fn from(p: Proof) -> Self {
        Self {
            approval_index: p.approval_index,
            request_id: p.request_id,
            action: p.action,
            agent_account_id: p.agent_account_id,
            agent_public_key: p.agent_key,
            requested_at_block: p.requested_at.height,
            requested_at_ns: p.requested_at.timestamp_ns.into(),
            approver_account_id: p.approver_account_id,
            approver_public_key: p.approver_key,
            approved_at_block: p.approved_at.height,
            approved_at_ns: p.approved_at.timestamp_ns.into(),
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
            "requested_at_block": 10,
            "requested_at_ns": "10000000000",
            "approver_account_id": approver(),
            "approver_public_key": APPROVER_PK,
            "approved_at_block": 12,
            "approved_at_ns": "12000000000",
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
            json!({ "account_id": agent(), "role": "agent", "pending": 0 })
        );
        assert_eq!(
            to_json(c.get_principal(pk(APPROVER_PK))),
            json!({ "account_id": approver(), "role": "approver", "pending": 0 })
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
