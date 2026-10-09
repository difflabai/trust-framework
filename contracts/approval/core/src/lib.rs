//! Pure state machine behind the NEAR action-approval contract.
//!
//! Every state transition lives here, free of `near-sdk`, so the same code
//! runs on-chain (through the contract crate's [`Store`] impl) and under
//! tests or verification harnesses (through [`MemStore`]). The runtime
//! supplies the [`Caller`] and [`BlockTime`]; this crate decides what they
//! are allowed to do.
//!
//! Identity is generic: `A` is an account id and `K` a public key. On-chain
//! these are `near_sdk::AccountId` and `near_sdk::PublicKey`; harnesses can
//! use small integers to keep the state space tractable.
//!
//! Lifecycle of a request:
//!
//! ```text
//! request_action (agent key)          approve (approver key, same action)
//!        │                                   │
//!        ▼                                   ▼
//!     Pending ───────────────────────────► Approved   (terminal, immutable)
//!        │
//!        ├── reject (approver key) ──────► Rejected   (terminal, immutable)
//!        │
//!        └── agent key revoked ──────────► Void       (terminal: never approvable)
//! ```
//!
//! Every key registration gets a unique, increasing registration id. Requests
//! and decisions record the registration they were made under, and revoking
//! a key records the block it was revoked at against that id, so a verifier
//! can tell whether (and when) the key behind a proof was later revoked.
//!
//! Every function either returns `Err` without touching the store, or
//! performs all of its writes. The NEAR runtime also reverts state on panic,
//! but the core does not rely on that. Guards are checked in the order listed
//! in each function's docs; the first failing guard is the error returned.

#![forbid(unsafe_code)]

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

pub type RequestId = u64;

/// Maximum length of an action payload, in bytes. Bounds per-request
/// storage, which the contract account pays for. The action is repeated in
/// event logs, so a worst-case (fully JSON-escaped) action must stay well
/// under NEAR's 16 KiB per-receipt log limit; don't raise this past ~2.5 KiB.
pub const MAX_ACTION_LEN: usize = 2048;

// `ApprovalError::ActionTooLong`'s message names the limit; keep them in step.
const _: () = assert!(MAX_ACTION_LEN == 2048);

/// Unique id of one registration of a key. Re-registering a revoked key
/// gives it a new id.
pub type RegistrationId = u64;

/// Maximum number of pending requests per agent key. Bounds the storage an
/// agent can consume without an approver's involvement.
pub const MAX_PENDING_PER_KEY: u32 = 16;

/// Page size used when a caller does not specify one.
pub const DEFAULT_PAGE_SIZE: u64 = 50;

/// Upper bound on page size, keeping view calls under the gas limit.
pub const MAX_PAGE_SIZE: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(BorshSerialize, BorshDeserialize, BorshSchema)
)]
pub enum Role {
    Agent,
    Approver,
}

/// A registered key's owner and role. Each key holds exactly one role.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(BorshSerialize, BorshDeserialize, BorshSchema)
)]
pub struct Principal<A> {
    pub account_id: A,
    pub role: Role,
    pub registration_id: RegistrationId,
    /// Request count when this registration was made. Requests with a lower
    /// id were made under an earlier, since-revoked registration of the same
    /// key and can never be approved.
    pub active_from: RequestId,
    /// Agent keys: pending requests made under this registration.
    /// Always 0 for approver keys.
    pub pending: u32,
}

/// Identity of the current call as reported by the runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller<A, K> {
    /// Account that invoked this function (`env::predecessor_account_id`).
    pub predecessor: A,
    /// Account that signed the originating transaction (`env::signer_account_id`).
    pub signer: A,
    /// Access key that signed the originating transaction (`env::signer_account_pk`).
    pub signer_key: K,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(BorshSerialize, BorshDeserialize, BorshSchema)
)]
pub struct BlockTime {
    pub height: u64,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(BorshSerialize, BorshDeserialize, BorshSchema)
)]
pub struct Approval<A, K> {
    /// Position of this approval in the append-only approval log.
    pub approval_index: u64,
    pub approver_account_id: A,
    pub approver_key: K,
    pub approver_registration_id: RegistrationId,
    pub approved_at: BlockTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(BorshSerialize, BorshDeserialize, BorshSchema)
)]
pub struct Rejection<A, K> {
    pub approver_account_id: A,
    pub approver_key: K,
    pub approver_registration_id: RegistrationId,
    pub rejected_at: BlockTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(BorshSerialize, BorshDeserialize, BorshSchema)
)]
pub struct ActionRequest<A, K> {
    pub id: RequestId,
    pub agent_account_id: A,
    pub agent_key: K,
    pub agent_registration_id: RegistrationId,
    pub action: String,
    pub requested_at: BlockTime,
    /// `None` unless approved. Once set it is never modified.
    pub approval: Option<Approval<A, K>>,
    /// `None` unless rejected. Once set it is never modified. At most one of
    /// `approval` and `rejection` is ever set.
    pub rejection: Option<Rejection<A, K>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestStatus {
    /// Not yet decided, and still approvable.
    Pending,
    Approved,
    Rejected,
    /// Not approved, and never will be: the agent key registration it was
    /// made under has been revoked.
    Void,
}

/// Self-contained record that `approver_key` approved `action` requested by
/// `agent_key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalProof<A, K> {
    pub approval_index: u64,
    pub request_id: RequestId,
    pub action: String,
    pub agent_account_id: A,
    pub agent_key: K,
    pub agent_registration_id: RegistrationId,
    pub requested_at: BlockTime,
    pub approver_account_id: A,
    pub approver_key: K,
    pub approver_registration_id: RegistrationId,
    pub approved_at: BlockTime,
}

/// When each key registration behind a proof was revoked, if it has been.
/// Unlike the proof itself this can change after approval: a verifier
/// should distrust approvals whose keys were later revoked as compromised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProofRevocations {
    pub agent: Option<BlockTime>,
    pub approver: Option<BlockTime>,
}

impl<A: Clone, K: Clone> ActionRequest<A, K> {
    pub fn proof(&self) -> Option<ApprovalProof<A, K>> {
        self.approval.as_ref().map(|a| self.proof_for(a))
    }

    fn proof_for(&self, approval: &Approval<A, K>) -> ApprovalProof<A, K> {
        ApprovalProof {
            approval_index: approval.approval_index,
            request_id: self.id,
            action: self.action.clone(),
            agent_account_id: self.agent_account_id.clone(),
            agent_key: self.agent_key.clone(),
            agent_registration_id: self.agent_registration_id,
            requested_at: self.requested_at,
            approver_account_id: approval.approver_account_id.clone(),
            approver_key: approval.approver_key.clone(),
            approver_registration_id: approval.approver_registration_id,
            approved_at: approval.approved_at,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    NotOwner,
    IndirectCall,
    UnknownKey,
    WrongRole,
    KeyAccountMismatch,
    KeyAlreadyRegistered,
    KeyNotRegistered,
    EmptyAction,
    ActionTooLong,
    TooManyPending,
    RequestNotFound,
    AlreadyApproved,
    AlreadyRejected,
    AgentRevoked,
    ActionMismatch,
    SelfApproval,
    LogFull,
}

impl ApprovalError {
    /// Panic message on-chain. No message is a substring of another, so
    /// tests matching on substrings stay unambiguous.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotOwner => "only the owner can manage keys",
            Self::IndirectCall => "caller must be the signing account",
            Self::UnknownKey => "signing key is unknown",
            Self::WrongRole => "signing key has the wrong role",
            Self::KeyAccountMismatch => "signing key belongs to another account",
            Self::KeyAlreadyRegistered => "key is already registered",
            Self::KeyNotRegistered => "key to revoke was not found",
            Self::EmptyAction => "action is empty",
            Self::ActionTooLong => "action exceeds 2048 bytes",
            Self::TooManyPending => "agent key has too many pending requests",
            Self::RequestNotFound => "request not found",
            Self::AlreadyApproved => "request is already approved",
            Self::AlreadyRejected => "request is already rejected",
            Self::AgentRevoked => "request is void: its agent key was revoked",
            Self::ActionMismatch => "action does not match the request",
            Self::SelfApproval => "approver and agent must be different accounts",
            Self::LogFull => "log is full",
        }
    }
}

impl core::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persistent state the state machine reads and writes.
///
/// Implementations must behave as:
/// - a map `K -> Principal<A>` (`principal`, `insert_principal` inserting or
///   overwriting, `remove_principal`);
/// - an append-only array of requests, where `push_request` stores at index
///   `request_count()` and then increments it, and `replace_request`
///   overwrites the existing entry at `request.id`;
/// - an append-only array of request ids (the approval log), where
///   `push_approval` stores at index `approval_count()` and then increments it;
/// - a counter of registrations made (`registration_count`,
///   `increment_registration_count`);
/// - a map `RegistrationId -> BlockTime` of revocations (`revocation`,
///   `insert_revocation`), written at most once per id.
pub trait Store<A, K> {
    fn owner(&self) -> &A;

    fn principal(&self, key: &K) -> Option<Principal<A>>;
    fn insert_principal(&mut self, key: K, principal: Principal<A>);
    fn remove_principal(&mut self, key: &K) -> Option<Principal<A>>;

    fn request_count(&self) -> u64;
    fn request(&self, id: RequestId) -> Option<ActionRequest<A, K>>;
    fn push_request(&mut self, request: ActionRequest<A, K>);
    fn replace_request(&mut self, request: ActionRequest<A, K>);

    fn approval_count(&self) -> u64;
    fn approved_request_id(&self, approval_index: u64) -> Option<RequestId>;
    fn push_approval(&mut self, request_id: RequestId);

    fn registration_count(&self) -> u64;
    fn increment_registration_count(&mut self);
    fn revocation(&self, registration_id: RegistrationId) -> Option<BlockTime>;
    fn insert_revocation(&mut self, registration_id: RegistrationId, revoked_at: BlockTime);
}

/// Registers `key` to `account_id` with `role` under a fresh registration
/// id, and returns the registration. Owner only. A key must be revoked
/// before it can be re-registered.
///
/// Guards: `NotOwner`, `KeyAlreadyRegistered`, `LogFull`.
pub fn add_principal<A, K, S>(
    store: &mut S,
    caller: &A,
    key: K,
    account_id: A,
    role: Role,
) -> Result<Principal<A>, ApprovalError>
where
    A: Clone + PartialEq,
    S: Store<A, K>,
{
    if caller != store.owner() {
        return Err(ApprovalError::NotOwner);
    }
    if store.principal(&key).is_some() {
        return Err(ApprovalError::KeyAlreadyRegistered);
    }
    let registration_id = store.registration_count();
    if registration_id == u64::MAX {
        return Err(ApprovalError::LogFull);
    }
    let principal = Principal {
        account_id,
        role,
        registration_id,
        active_from: store.request_count(),
        pending: 0,
    };
    store.increment_registration_count();
    store.insert_principal(key, principal.clone());
    Ok(principal)
}

/// Removes `key` from the registry, records `now` as the revocation time of
/// its registration, and returns the removed registration. Owner only.
/// Approvals and rejections already recorded stay, and their proofs report
/// the revocation. Pending requests made under this registration become
/// void permanently, even if the key is registered again later.
///
/// Guards: `NotOwner`, `KeyNotRegistered`.
pub fn revoke_key<A, K, S>(
    store: &mut S,
    caller: &A,
    key: &K,
    now: BlockTime,
) -> Result<Principal<A>, ApprovalError>
where
    A: PartialEq,
    S: Store<A, K>,
{
    if caller != store.owner() {
        return Err(ApprovalError::NotOwner);
    }
    let removed = store
        .remove_principal(key)
        .ok_or(ApprovalError::KeyNotRegistered)?;
    store.insert_revocation(removed.registration_id, now);
    Ok(removed)
}

/// Checks that the immediate caller is the signing account and that the
/// signing key is registered to that account with `role`, returning its
/// registration.
///
/// `predecessor == signer` means the call came from the signer's own
/// transaction or the signer account's own contract code, never from a third
/// party contract the key holder happened to call. It amounts to "signed
/// directly" only when registered keys are function-call keys scoped to this
/// contract, which is a deployment requirement.
///
/// Guards: `IndirectCall`, `UnknownKey`, `WrongRole`, `KeyAccountMismatch`.
fn authenticate<A, K, S>(
    store: &S,
    caller: &Caller<A, K>,
    role: Role,
) -> Result<Principal<A>, ApprovalError>
where
    A: PartialEq,
    S: Store<A, K>,
{
    if caller.predecessor != caller.signer {
        return Err(ApprovalError::IndirectCall);
    }
    let principal = store
        .principal(&caller.signer_key)
        .ok_or(ApprovalError::UnknownKey)?;
    if principal.role != role {
        return Err(ApprovalError::WrongRole);
    }
    if principal.account_id != caller.signer {
        return Err(ApprovalError::KeyAccountMismatch);
    }
    Ok(principal)
}

/// The agent registration a pending request was made under, if it is still
/// in force. `None` means the request is void.
fn live_agent_registration<A, K, S>(
    store: &S,
    request: &ActionRequest<A, K>,
) -> Option<Principal<A>>
where
    A: PartialEq,
    S: Store<A, K>,
{
    store.principal(&request.agent_key).filter(|p| {
        p.role == Role::Agent
            && p.account_id == request.agent_account_id
            && p.active_from <= request.id
    })
}

/// Records a new pending request for `action`, signed by an agent key.
///
/// Guards: [authentication](authenticate), `EmptyAction`, `ActionTooLong`
/// (measured in bytes), `TooManyPending`, `LogFull`.
pub fn request_action<A, K, S>(
    store: &mut S,
    caller: &Caller<A, K>,
    action: String,
    now: BlockTime,
) -> Result<ActionRequest<A, K>, ApprovalError>
where
    A: Clone + PartialEq,
    K: Clone,
    S: Store<A, K>,
{
    let mut principal = authenticate(store, caller, Role::Agent)?;
    if action.is_empty() {
        return Err(ApprovalError::EmptyAction);
    }
    if action.len() > MAX_ACTION_LEN {
        return Err(ApprovalError::ActionTooLong);
    }
    if principal.pending >= MAX_PENDING_PER_KEY {
        return Err(ApprovalError::TooManyPending);
    }
    let id = store.request_count();
    if id == u64::MAX {
        return Err(ApprovalError::LogFull);
    }
    let request = ActionRequest {
        id,
        agent_account_id: caller.signer.clone(),
        agent_key: caller.signer_key.clone(),
        agent_registration_id: principal.registration_id,
        action,
        requested_at: now,
        approval: None,
        rejection: None,
    };
    principal.pending += 1;
    store.insert_principal(caller.signer_key.clone(), principal);
    store.push_request(request.clone());
    Ok(request)
}

/// Approves a pending request, signed by an approver key, and appends it to
/// the approval log. `action` must equal the stored action, so the approver's
/// signed transaction commits to exactly what was reviewed.
///
/// Guards: [authentication](authenticate), `RequestNotFound`,
/// `AlreadyApproved`, `AlreadyRejected`, `AgentRevoked` (the request is
/// void), `ActionMismatch`, `SelfApproval` (approver account is the agent
/// account), `LogFull`.
pub fn approve<A, K, S>(
    store: &mut S,
    caller: &Caller<A, K>,
    request_id: RequestId,
    action: &str,
    now: BlockTime,
) -> Result<ApprovalProof<A, K>, ApprovalError>
where
    A: Clone + PartialEq,
    K: Clone,
    S: Store<A, K>,
{
    let approver = authenticate(store, caller, Role::Approver)?;
    let (mut request, mut agent) = decidable_request(store, request_id)?;
    if request.action != action {
        return Err(ApprovalError::ActionMismatch);
    }
    if caller.signer == request.agent_account_id {
        return Err(ApprovalError::SelfApproval);
    }
    let approval_index = store.approval_count();
    if approval_index == u64::MAX {
        return Err(ApprovalError::LogFull);
    }
    let approval = Approval {
        approval_index,
        approver_account_id: caller.signer.clone(),
        approver_key: caller.signer_key.clone(),
        approver_registration_id: approver.registration_id,
        approved_at: now,
    };
    let proof = request.proof_for(&approval);
    request.approval = Some(approval);
    agent.pending = agent.pending.saturating_sub(1);
    store.insert_principal(request.agent_key.clone(), agent);
    store.replace_request(request);
    store.push_approval(request_id);
    Ok(proof)
}

/// Rejects a pending request, signed by an approver key, freeing its slot in
/// the agent key's pending limit. A rejected request can never be approved.
///
/// Guards: [authentication](authenticate), `RequestNotFound`,
/// `AlreadyApproved`, `AlreadyRejected`, `AgentRevoked` (the request is
/// void), `SelfApproval` (approver account is the agent account).
pub fn reject<A, K, S>(
    store: &mut S,
    caller: &Caller<A, K>,
    request_id: RequestId,
    now: BlockTime,
) -> Result<ActionRequest<A, K>, ApprovalError>
where
    A: Clone + PartialEq,
    K: Clone,
    S: Store<A, K>,
{
    let approver = authenticate(store, caller, Role::Approver)?;
    let (mut request, mut agent) = decidable_request(store, request_id)?;
    if caller.signer == request.agent_account_id {
        return Err(ApprovalError::SelfApproval);
    }
    request.rejection = Some(Rejection {
        approver_account_id: caller.signer.clone(),
        approver_key: caller.signer_key.clone(),
        approver_registration_id: approver.registration_id,
        rejected_at: now,
    });
    agent.pending = agent.pending.saturating_sub(1);
    store.insert_principal(request.agent_key.clone(), agent);
    store.replace_request(request.clone());
    Ok(request)
}

/// The pending request `request_id` and the live agent registration it was
/// made under, for an approver's decision.
///
/// Guards: `RequestNotFound`, `AlreadyApproved`, `AlreadyRejected`,
/// `AgentRevoked`.
fn decidable_request<A, K, S>(
    store: &S,
    request_id: RequestId,
) -> Result<(ActionRequest<A, K>, Principal<A>), ApprovalError>
where
    A: PartialEq,
    S: Store<A, K>,
{
    let request = store
        .request(request_id)
        .ok_or(ApprovalError::RequestNotFound)?;
    if request.approval.is_some() {
        return Err(ApprovalError::AlreadyApproved);
    }
    if request.rejection.is_some() {
        return Err(ApprovalError::AlreadyRejected);
    }
    let agent = live_agent_registration(store, &request).ok_or(ApprovalError::AgentRevoked)?;
    Ok((request, agent))
}

/// Current status of `request_id`, or `None` if it doesn't exist.
pub fn request_status<A, K, S>(store: &S, request_id: RequestId) -> Option<RequestStatus>
where
    A: PartialEq,
    S: Store<A, K>,
{
    store.request(request_id).map(|r| status_of(store, &r))
}

/// Current status of a request already read from `store`.
pub fn status_of<A, K, S>(store: &S, request: &ActionRequest<A, K>) -> RequestStatus
where
    A: PartialEq,
    S: Store<A, K>,
{
    if request.approval.is_some() {
        RequestStatus::Approved
    } else if request.rejection.is_some() {
        RequestStatus::Rejected
    } else if live_agent_registration(store, request).is_some() {
        RequestStatus::Pending
    } else {
        RequestStatus::Void
    }
}

/// Revocation times of the key registrations behind `proof`.
pub fn proof_revocations<A, K, S>(store: &S, proof: &ApprovalProof<A, K>) -> ProofRevocations
where
    S: Store<A, K>,
{
    ProofRevocations {
        agent: store.revocation(proof.agent_registration_id),
        approver: store.revocation(proof.approver_registration_id),
    }
}

/// Proof of approval for `request_id`, if it has been approved.
pub fn approval<A, K, S>(store: &S, request_id: RequestId) -> Option<ApprovalProof<A, K>>
where
    A: Clone,
    K: Clone,
    S: Store<A, K>,
{
    store.request(request_id)?.proof()
}

/// Approval proofs in approval order, starting at `from_index` in the
/// approval log. `limit` is clamped to [`MAX_PAGE_SIZE`], so callers should
/// page until an empty page comes back (or `from_index` reaches
/// `approval_count()`), not until a page is shorter than `limit`.
pub fn approvals<A, K, S>(store: &S, from_index: u64, limit: u64) -> Vec<ApprovalProof<A, K>>
where
    A: Clone,
    K: Clone,
    S: Store<A, K>,
{
    let end = from_index
        .saturating_add(limit.min(MAX_PAGE_SIZE))
        .min(store.approval_count());
    (from_index..end)
        .filter_map(|i| store.approved_request_id(i))
        .filter_map(|id| approval(store, id))
        .collect()
}

/// In-memory [`Store`] for tests and verification harnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemStore<A, K> {
    pub owner: A,
    pub principals: Vec<(K, Principal<A>)>,
    pub requests: Vec<ActionRequest<A, K>>,
    pub approval_log: Vec<RequestId>,
    pub registration_count: u64,
    pub revocations: Vec<(RegistrationId, BlockTime)>,
}

impl<A, K> MemStore<A, K> {
    pub fn new(owner: A) -> Self {
        Self {
            owner,
            principals: Vec::new(),
            requests: Vec::new(),
            approval_log: Vec::new(),
            registration_count: 0,
            revocations: Vec::new(),
        }
    }
}

impl<A: Clone, K: Clone + PartialEq> Store<A, K> for MemStore<A, K> {
    fn owner(&self) -> &A {
        &self.owner
    }

    fn principal(&self, key: &K) -> Option<Principal<A>> {
        self.principals
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, p)| p.clone())
    }

    fn insert_principal(&mut self, key: K, principal: Principal<A>) {
        match self.principals.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = principal,
            None => self.principals.push((key, principal)),
        }
    }

    fn remove_principal(&mut self, key: &K) -> Option<Principal<A>> {
        let index = self.principals.iter().position(|(k, _)| k == key)?;
        Some(self.principals.remove(index).1)
    }

    fn request_count(&self) -> u64 {
        self.requests.len() as u64
    }

    fn request(&self, id: RequestId) -> Option<ActionRequest<A, K>> {
        self.requests.get(usize::try_from(id).ok()?).cloned()
    }

    fn push_request(&mut self, request: ActionRequest<A, K>) {
        self.requests.push(request);
    }

    fn replace_request(&mut self, request: ActionRequest<A, K>) {
        if let Some(slot) = usize::try_from(request.id)
            .ok()
            .and_then(|i| self.requests.get_mut(i))
        {
            *slot = request;
        }
    }

    fn approval_count(&self) -> u64 {
        self.approval_log.len() as u64
    }

    fn approved_request_id(&self, approval_index: u64) -> Option<RequestId> {
        self.approval_log
            .get(usize::try_from(approval_index).ok()?)
            .copied()
    }

    fn push_approval(&mut self, request_id: RequestId) {
        self.approval_log.push(request_id);
    }

    fn registration_count(&self) -> u64 {
        self.registration_count
    }

    fn increment_registration_count(&mut self) {
        self.registration_count += 1;
    }

    fn revocation(&self, registration_id: RegistrationId) -> Option<BlockTime> {
        self.revocations
            .iter()
            .find(|(id, _)| *id == registration_id)
            .map(|(_, at)| *at)
    }

    fn insert_revocation(&mut self, registration_id: RegistrationId, revoked_at: BlockTime) {
        self.revocations.push((registration_id, revoked_at));
    }
}

#[cfg(test)]
mod tests;
