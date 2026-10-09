use super::*;
use std::collections::BTreeSet;

type S = MemStore<u8, u8>;

const OWNER: u8 = 0;
const AGENT: u8 = 1;
const APPROVER: u8 = 2;
const OTHER: u8 = 3;

const AGENT_KEY: u8 = 10;
const APPROVER_KEY: u8 = 20;
const OTHER_KEY: u8 = 30;

fn t(height: u64) -> BlockTime {
    BlockTime {
        height,
        timestamp_ns: height * 1_000_000_000,
    }
}

fn direct(account: u8, key: u8) -> Caller<u8, u8> {
    Caller {
        predecessor: account,
        signer: account,
        signer_key: key,
    }
}

fn add(s: &mut S, key: u8, account: u8, role: Role) {
    add_principal(s, &OWNER, key, account, role).unwrap();
}

/// Owner plus one agent key and one approver key.
fn setup() -> S {
    let mut s = S::new(OWNER);
    add(&mut s, AGENT_KEY, AGENT, Role::Agent);
    add(&mut s, APPROVER_KEY, APPROVER, Role::Approver);
    s
}

fn request(s: &mut S, action: &str) -> RequestId {
    request_action(s, &direct(AGENT, AGENT_KEY), action.to_string(), t(1))
        .unwrap()
        .id
}

fn approve_as_approver(s: &mut S, id: RequestId) -> Result<ApprovalProof<u8, u8>, ApprovalError> {
    let action = s.request(id).map(|r| r.action).unwrap_or_default();
    approve(s, &direct(APPROVER, APPROVER_KEY), id, &action, t(2))
}

#[test]
fn owner_registers_and_revokes_keys() {
    let mut s = setup();
    let registered = Principal {
        account_id: AGENT,
        role: Role::Agent,
        registration_id: 0,
        active_from: 0,
        pending: 0,
    };
    assert_eq!(s.principal(&AGENT_KEY), Some(registered.clone()));
    assert_eq!(s.principal(&APPROVER_KEY).unwrap().registration_id, 1);
    assert_eq!(s.registration_count(), 2);
    assert_eq!(s.revocation(0), None);
    assert_eq!(revoke_key(&mut s, &OWNER, &AGENT_KEY, t(5)), Ok(registered));
    assert_eq!(s.principal(&AGENT_KEY), None);
    assert_eq!(s.revocation(0), Some(t(5)));
    assert_eq!(s.revocation(1), None);
    assert_eq!(
        revoke_key(&mut s, &OWNER, &AGENT_KEY, t(5)),
        Err(ApprovalError::KeyNotRegistered)
    );
}

#[test]
fn only_owner_manages_keys() {
    let mut s = setup();
    assert_eq!(
        add_principal(&mut s, &AGENT, OTHER_KEY, AGENT, Role::Approver),
        Err(ApprovalError::NotOwner)
    );
    assert_eq!(
        revoke_key(&mut s, &APPROVER, &AGENT_KEY, t(5)),
        Err(ApprovalError::NotOwner)
    );
    assert_eq!(s, setup());
}

#[test]
fn key_cannot_be_registered_twice() {
    let mut s = setup();
    assert_eq!(
        add_principal(&mut s, &OWNER, AGENT_KEY, OTHER, Role::Approver),
        Err(ApprovalError::KeyAlreadyRegistered)
    );
    assert_eq!(s, setup());
}

#[test]
fn agent_requests_action() {
    let mut s = setup();
    let r = request_action(&mut s, &direct(AGENT, AGENT_KEY), "deploy v2".into(), t(7)).unwrap();
    assert_eq!(
        r,
        ActionRequest {
            id: 0,
            agent_account_id: AGENT,
            agent_key: AGENT_KEY,
            agent_registration_id: 0,
            action: "deploy v2".into(),
            requested_at: t(7),
            approval: None,
            rejection: None,
        }
    );
    assert_eq!(s.request(0), Some(r));
    assert_eq!(request_status(&s, 0), Some(RequestStatus::Pending));
    assert_eq!(s.principal(&AGENT_KEY).unwrap().pending, 1);
    assert_eq!(request(&mut s, "second"), 1);
    assert_eq!(s.request_count(), 2);
    assert_eq!(request_status(&s, 2), None);
}

#[test]
fn request_rejects_unauthorized_callers() {
    let mut s = setup();
    add(&mut s, OTHER_KEY, OTHER, Role::Agent);
    let snapshot = s.clone();
    let relayed = Caller {
        predecessor: OTHER,
        signer: AGENT,
        signer_key: AGENT_KEY,
    };
    let cases = [
        (relayed, ApprovalError::IndirectCall),
        (direct(AGENT, 99), ApprovalError::UnknownKey),
        (direct(APPROVER, APPROVER_KEY), ApprovalError::WrongRole),
        // AGENT presenting a key registered to OTHER.
        (direct(AGENT, OTHER_KEY), ApprovalError::KeyAccountMismatch),
    ];
    for (caller, err) in cases {
        assert_eq!(request_action(&mut s, &caller, "x".into(), t(1)), Err(err));
    }
    assert_eq!(s, snapshot);
}

#[test]
fn action_length_is_bounded_in_bytes() {
    let mut s = setup();
    let caller = direct(AGENT, AGENT_KEY);
    let mut try_action = |a: String| request_action(&mut s, &caller, a, t(1)).map(|_| ());
    assert_eq!(try_action(String::new()), Err(ApprovalError::EmptyAction));
    assert_eq!(
        try_action("a".repeat(MAX_ACTION_LEN + 1)),
        Err(ApprovalError::ActionTooLong)
    );
    assert_eq!(
        try_action("é".repeat(MAX_ACTION_LEN / 2 + 1)),
        Err(ApprovalError::ActionTooLong)
    );
    assert_eq!(
        try_action("😀".repeat(MAX_ACTION_LEN / 4 + 1)),
        Err(ApprovalError::ActionTooLong)
    );
    assert_eq!(try_action("a".repeat(MAX_ACTION_LEN)), Ok(()));
    assert_eq!(try_action("é".repeat(MAX_ACTION_LEN / 2)), Ok(()));
    // Non-empty means at least one byte; whitespace is a valid action.
    assert_eq!(try_action(" ".into()), Ok(()));
}

#[test]
fn pending_requests_per_agent_key_are_capped() {
    let mut s = setup();
    for _ in 0..MAX_PENDING_PER_KEY {
        request(&mut s, "x");
    }
    let snapshot = s.clone();
    assert_eq!(
        request_action(&mut s, &direct(AGENT, AGENT_KEY), "x".into(), t(1)),
        Err(ApprovalError::TooManyPending)
    );
    assert_eq!(s, snapshot);
    // An approval frees a slot.
    approve_as_approver(&mut s, 0).unwrap();
    assert_eq!(
        s.principal(&AGENT_KEY).unwrap().pending,
        MAX_PENDING_PER_KEY - 1
    );
    request(&mut s, "x");
    // Rotating the key also clears the backlog (and voids it).
    revoke_key(&mut s, &OWNER, &AGENT_KEY, t(5)).unwrap();
    add(&mut s, AGENT_KEY, AGENT, Role::Agent);
    assert_eq!(s.principal(&AGENT_KEY).unwrap().pending, 0);
    request(&mut s, "x");
}

#[test]
fn approver_approves_request() {
    let mut s = setup();
    let id = request(&mut s, "rotate keys");
    let proof = approve(
        &mut s,
        &direct(APPROVER, APPROVER_KEY),
        id,
        "rotate keys",
        t(9),
    )
    .unwrap();
    assert_eq!(
        proof,
        ApprovalProof {
            approval_index: 0,
            request_id: id,
            action: "rotate keys".into(),
            agent_account_id: AGENT,
            agent_key: AGENT_KEY,
            agent_registration_id: 0,
            requested_at: t(1),
            approver_account_id: APPROVER,
            approver_key: APPROVER_KEY,
            approver_registration_id: 1,
            approved_at: t(9),
        }
    );
    assert_eq!(approval(&s, id), Some(proof));
    assert_eq!(request_status(&s, id), Some(RequestStatus::Approved));
    assert_eq!(s.approval_count(), 1);
    assert_eq!(s.approved_request_id(0), Some(id));
    assert_eq!(s.principal(&AGENT_KEY).unwrap().pending, 0);
}

#[test]
fn approval_must_name_the_requested_action() {
    let mut s = setup();
    let id = request(&mut s, "pay 5 NEAR to bob.near");
    let snapshot = s.clone();
    for wrong in ["pay 50 NEAR to bob.near", "pay 5 NEAR to bob.near ", ""] {
        assert_eq!(
            approve(&mut s, &direct(APPROVER, APPROVER_KEY), id, wrong, t(2)),
            Err(ApprovalError::ActionMismatch)
        );
    }
    assert_eq!(s, snapshot);
}

#[test]
fn request_is_approved_at_most_once() {
    let mut s = setup();
    add(&mut s, OTHER_KEY, OTHER, Role::Approver);
    let id = request(&mut s, "x");
    approve_as_approver(&mut s, id).unwrap();
    let snapshot = s.clone();
    assert_eq!(
        approve(&mut s, &direct(OTHER, OTHER_KEY), id, "x", t(3)),
        Err(ApprovalError::AlreadyApproved)
    );
    assert_eq!(s, snapshot);
}

#[test]
fn approve_rejects_unauthorized_callers() {
    let mut s = setup();
    let id = request(&mut s, "x");
    let snapshot = s.clone();
    let relayed = Caller {
        predecessor: OTHER,
        signer: APPROVER,
        signer_key: APPROVER_KEY,
    };
    let cases = [
        (relayed, ApprovalError::IndirectCall),
        (direct(APPROVER, 99), ApprovalError::UnknownKey),
        (direct(AGENT, AGENT_KEY), ApprovalError::WrongRole),
        (
            direct(OTHER, APPROVER_KEY),
            ApprovalError::KeyAccountMismatch,
        ),
    ];
    for (caller, err) in cases {
        assert_eq!(approve(&mut s, &caller, id, "x", t(2)), Err(err));
    }
    assert_eq!(
        approve(&mut s, &direct(APPROVER, APPROVER_KEY), id + 1, "x", t(2)),
        Err(ApprovalError::RequestNotFound)
    );
    assert_eq!(s, snapshot);
}

#[test]
fn agent_account_cannot_approve_its_own_request() {
    let mut s = setup();
    add(&mut s, OTHER_KEY, AGENT, Role::Approver);
    let id = request(&mut s, "x");
    assert_eq!(
        approve(&mut s, &direct(AGENT, OTHER_KEY), id, "x", t(2)),
        Err(ApprovalError::SelfApproval)
    );
}

#[test]
fn revocation_voids_pending_requests_permanently() {
    let mut s = setup();
    let id = request(&mut s, "x");
    revoke_key(&mut s, &OWNER, &AGENT_KEY, t(5)).unwrap();
    assert_eq!(request_status(&s, id), Some(RequestStatus::Void));
    assert_eq!(
        approve_as_approver(&mut s, id),
        Err(ApprovalError::AgentRevoked)
    );
    // Re-registering the same key to the same account does not revive it...
    add(&mut s, AGENT_KEY, AGENT, Role::Agent);
    assert_eq!(request_status(&s, id), Some(RequestStatus::Void));
    assert_eq!(
        approve_as_approver(&mut s, id),
        Err(ApprovalError::AgentRevoked)
    );
    // ...but requests made under the new registration are approvable.
    let fresh = request(&mut s, "y");
    assert_eq!(request_status(&s, fresh), Some(RequestStatus::Pending));
    approve_as_approver(&mut s, fresh).unwrap();
    // Re-registering to a different account does not revive it either.
    revoke_key(&mut s, &OWNER, &AGENT_KEY, t(5)).unwrap();
    add(&mut s, AGENT_KEY, OTHER, Role::Agent);
    assert_eq!(
        approve_as_approver(&mut s, id),
        Err(ApprovalError::AgentRevoked)
    );
}

#[test]
fn revoked_approver_cannot_approve() {
    let mut s = setup();
    let id = request(&mut s, "x");
    revoke_key(&mut s, &OWNER, &APPROVER_KEY, t(5)).unwrap();
    assert_eq!(
        approve_as_approver(&mut s, id),
        Err(ApprovalError::UnknownKey)
    );
}

#[test]
fn proofs_survive_key_revocation() {
    let mut s = setup();
    let id = request(&mut s, "x");
    let proof = approve_as_approver(&mut s, id).unwrap();
    assert_eq!(proof_revocations(&s, &proof), ProofRevocations::default());
    revoke_key(&mut s, &OWNER, &AGENT_KEY, t(5)).unwrap();
    revoke_key(&mut s, &OWNER, &APPROVER_KEY, t(6)).unwrap();
    assert_eq!(approval(&s, id), Some(proof.clone()));
    assert_eq!(request_status(&s, id), Some(RequestStatus::Approved));
    assert_eq!(approvals(&s, 0, 10), vec![proof.clone()]);
    // The proof is unchanged, but now reports when each key was revoked.
    assert_eq!(
        proof_revocations(&s, &proof),
        ProofRevocations {
            agent: Some(t(5)),
            approver: Some(t(6)),
        }
    );
}

#[test]
fn revocation_is_tracked_per_registration() {
    let mut s = setup();
    revoke_key(&mut s, &OWNER, &APPROVER_KEY, t(3)).unwrap();
    // Re-registering the same key creates a new registration that is live,
    // while the old registration stays revoked.
    let again = add_principal(&mut s, &OWNER, APPROVER_KEY, APPROVER, Role::Approver).unwrap();
    assert_eq!(again.registration_id, 2);
    let id = request(&mut s, "x");
    let proof = approve_as_approver(&mut s, id).unwrap();
    assert_eq!(proof.approver_registration_id, 2);
    assert_eq!(proof_revocations(&s, &proof), ProofRevocations::default());
    assert_eq!(s.revocation(1), Some(t(3)));
}

fn reject_as_approver(s: &mut S, id: RequestId) -> Result<ActionRequest<u8, u8>, ApprovalError> {
    reject(s, &direct(APPROVER, APPROVER_KEY), id, t(4))
}

#[test]
fn approver_rejects_request() {
    let mut s = setup();
    let id = request(&mut s, "drop table");
    let rejected = reject_as_approver(&mut s, id).unwrap();
    assert_eq!(
        rejected.rejection,
        Some(Rejection {
            approver_account_id: APPROVER,
            approver_key: APPROVER_KEY,
            approver_registration_id: 1,
            rejected_at: t(4),
        })
    );
    assert_eq!(rejected.approval, None);
    assert_eq!(s.request(id), Some(rejected));
    assert_eq!(request_status(&s, id), Some(RequestStatus::Rejected));
    assert_eq!(approval(&s, id), None);
    assert_eq!(s.approval_count(), 0);
    assert_eq!(s.principal(&AGENT_KEY).unwrap().pending, 0);
    assert_eq!(
        reject_as_approver(&mut s, id),
        Err(ApprovalError::AlreadyRejected)
    );
    assert_eq!(
        approve_as_approver(&mut s, id),
        Err(ApprovalError::AlreadyRejected)
    );
    // Rejection is terminal even if the agent key is later revoked.
    revoke_key(&mut s, &OWNER, &AGENT_KEY, t(5)).unwrap();
    assert_eq!(request_status(&s, id), Some(RequestStatus::Rejected));
}

#[test]
fn rejecting_frees_pending_slots() {
    let mut s = setup();
    let ids: Vec<_> = (0..MAX_PENDING_PER_KEY)
        .map(|i| request(&mut s, &format!("a{i}")))
        .collect();
    assert_eq!(
        request_action(&mut s, &direct(AGENT, AGENT_KEY), "more".into(), t(1)),
        Err(ApprovalError::TooManyPending)
    );
    reject_as_approver(&mut s, ids[0]).unwrap();
    request(&mut s, "more");
}

#[test]
fn reject_guards() {
    let mut s = setup();
    add(&mut s, OTHER_KEY, AGENT, Role::Approver);
    let id = request(&mut s, "x");
    let approved = request(&mut s, "y");
    approve_as_approver(&mut s, approved).unwrap();
    let before = s.clone();
    let cases = [
        (direct(AGENT, AGENT_KEY), id, ApprovalError::WrongRole),
        (
            direct(APPROVER, APPROVER_KEY),
            99,
            ApprovalError::RequestNotFound,
        ),
        (
            direct(APPROVER, APPROVER_KEY),
            approved,
            ApprovalError::AlreadyApproved,
        ),
        (direct(AGENT, OTHER_KEY), id, ApprovalError::SelfApproval),
        (
            Caller {
                predecessor: OTHER,
                signer: APPROVER,
                signer_key: APPROVER_KEY,
            },
            id,
            ApprovalError::IndirectCall,
        ),
    ];
    for (caller, id, err) in cases {
        assert_eq!(reject(&mut s, &caller, id, t(4)), Err(err));
    }
    assert_eq!(s, before);
    revoke_key(&mut s, &OWNER, &AGENT_KEY, t(5)).unwrap();
    assert_eq!(
        reject_as_approver(&mut s, id),
        Err(ApprovalError::AgentRevoked)
    );
}

#[test]
fn pending_request_has_no_proof() {
    let mut s = setup();
    let id = request(&mut s, "x");
    assert_eq!(approval(&s, id), None);
    assert_eq!(approval(&s, id + 1), None);
}

#[test]
fn approvals_page_in_approval_order() {
    let mut s = setup();
    let ids: Vec<_> = (0..5).map(|i| request(&mut s, &format!("a{i}"))).collect();
    for &i in &[3, 0, 4, 1] {
        approve_as_approver(&mut s, ids[i]).unwrap();
    }
    let page = |from, limit| -> Vec<RequestId> {
        approvals(&s, from, limit)
            .iter()
            .map(|p| p.request_id)
            .collect()
    };
    assert_eq!(page(0, 10), vec![3, 0, 4, 1]);
    assert_eq!(page(1, 2), vec![0, 4]);
    assert_eq!(page(3, 10), vec![1]);
    assert_eq!(page(4, 10), Vec::<RequestId>::new());
    assert_eq!(page(u64::MAX, u64::MAX), Vec::<RequestId>::new());
    assert_eq!(page(0, 0), Vec::<RequestId>::new());
    let indices: Vec<_> = approvals(&s, 0, 10)
        .iter()
        .map(|p| p.approval_index)
        .collect();
    assert_eq!(indices, vec![0, 1, 2, 3]);
}

#[test]
fn approvals_page_is_clamped_and_paging_until_empty_sees_everything() {
    let mut s = setup();
    let total = MAX_PAGE_SIZE + 5;
    for _ in 0..total {
        let id = request(&mut s, "x");
        approve_as_approver(&mut s, id).unwrap();
    }
    assert_eq!(approvals(&s, 0, u64::MAX).len() as u64, MAX_PAGE_SIZE);
    assert_eq!(approvals(&s, MAX_PAGE_SIZE, u64::MAX).len(), 5);
    // The documented client loop: advance by the page length, stop on an
    // empty page. Works for any limit above zero, including ones over the cap.
    for limit in [1, 7, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, 500] {
        let (mut from, mut seen) = (0, Vec::new());
        loop {
            let page = approvals(&s, from, limit);
            if page.is_empty() {
                break;
            }
            from += page.len() as u64;
            seen.extend(page.into_iter().map(|p| p.approval_index));
        }
        assert_eq!(seen, (0..total).collect::<Vec<_>>(), "limit {limit}");
    }
}

/// Reports every log and counter as full; everything else delegates to a `MemStore`.
struct FullStore(S);

impl Store<u8, u8> for FullStore {
    fn owner(&self) -> &u8 {
        self.0.owner()
    }
    fn principal(&self, key: &u8) -> Option<Principal<u8>> {
        self.0.principal(key)
    }
    fn insert_principal(&mut self, key: u8, principal: Principal<u8>) {
        self.0.insert_principal(key, principal)
    }
    fn remove_principal(&mut self, key: &u8) -> Option<Principal<u8>> {
        self.0.remove_principal(key)
    }
    fn request_count(&self) -> u64 {
        u64::MAX
    }
    fn request(&self, id: RequestId) -> Option<ActionRequest<u8, u8>> {
        self.0.request(id)
    }
    fn push_request(&mut self, request: ActionRequest<u8, u8>) {
        self.0.push_request(request)
    }
    fn replace_request(&mut self, request: ActionRequest<u8, u8>) {
        self.0.replace_request(request)
    }
    fn approval_count(&self) -> u64 {
        u64::MAX
    }
    fn approved_request_id(&self, approval_index: u64) -> Option<RequestId> {
        self.0.approved_request_id(approval_index)
    }
    fn push_approval(&mut self, request_id: RequestId) {
        self.0.push_approval(request_id)
    }
    fn registration_count(&self) -> u64 {
        u64::MAX
    }
    fn increment_registration_count(&mut self) {
        self.0.increment_registration_count()
    }
    fn revocation(&self, registration_id: RegistrationId) -> Option<BlockTime> {
        self.0.revocation(registration_id)
    }
    fn insert_revocation(&mut self, registration_id: RegistrationId, revoked_at: BlockTime) {
        self.0.insert_revocation(registration_id, revoked_at)
    }
}

#[test]
fn full_logs_are_rejected_without_writes() {
    let mut base = setup();
    let id = request(&mut base, "x");
    let mut full = FullStore(base.clone());
    assert_eq!(
        request_action(&mut full, &direct(AGENT, AGENT_KEY), "y".into(), t(2)),
        Err(ApprovalError::LogFull)
    );
    assert_eq!(
        approve(&mut full, &direct(APPROVER, APPROVER_KEY), id, "x", t(2)),
        Err(ApprovalError::LogFull)
    );
    assert_eq!(
        add_principal(&mut full, &OWNER, OTHER_KEY, OTHER, Role::Agent),
        Err(ApprovalError::LogFull)
    );
    assert_eq!(full.0, base);
}

#[test]
fn error_messages_are_distinct() {
    use ApprovalError::*;
    let all = [
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
    ];
    for a in all {
        for b in all {
            if a != b {
                assert!(!a.as_str().contains(b.as_str()), "{a:?} contains {b:?}");
            }
        }
    }
    assert!(ActionTooLong.as_str().contains(&MAX_ACTION_LEN.to_string()));
}

/// The on-chain build stores these types with borsh; check they round-trip.
#[cfg(feature = "borsh")]
#[test]
fn stored_types_round_trip_through_borsh() {
    fn round_trip<
        T: borsh::BorshSerialize + borsh::BorshDeserialize + PartialEq + core::fmt::Debug,
    >(
        value: T,
    ) {
        let bytes = borsh::to_vec(&value).unwrap();
        assert_eq!(T::try_from_slice(&bytes).unwrap(), value);
    }
    let mut s = setup();
    let approved = request(&mut s, "x");
    approve_as_approver(&mut s, approved).unwrap();
    let rejected = request(&mut s, "é".repeat(MAX_ACTION_LEN / 2).as_str());
    reject_as_approver(&mut s, rejected).unwrap();
    let pending = request(&mut s, "z");
    for id in [approved, rejected, pending] {
        round_trip(s.request(id).unwrap());
    }
    round_trip(s.principal(&AGENT_KEY).unwrap());
    round_trip(s.principal(&APPROVER_KEY).unwrap());
    round_trip(BlockTime {
        height: u64::MAX,
        timestamp_ns: u64::MAX,
    });
}

// ---------------------------------------------------------------------------
// Randomized state-machine check
//
// Drives the core with long random operation sequences and, after every
// step, checks (a) the global invariants, (b) that each operation fails with
// exactly the error its specified guards predict (first failing guard wins)
// and succeeds otherwise, (c) the operation's frame condition: what changed
// and that nothing else did, (d) every request's status.
//
// Revocation is specified with ghost state (`Model::void`), independent of
// the implementation's `active_from` mechanism: once a request's agent key is
// revoked while the request is pending, the request is void forever. The
// invariants also check that the recorded revocation of each pending
// request's agent registration agrees with the ghost state.
// ---------------------------------------------------------------------------

const ACCOUNTS: [u8; 4] = [OWNER, AGENT, APPROVER, OTHER];
const KEYS: [u8; 5] = [10, 11, 20, 21, 30];

#[derive(Clone, Debug)]
enum Op {
    Add(u8, u8, u8, Role),
    Revoke(u8, u8),
    Request(Caller<u8, u8>, String),
    Approve(Caller<u8, u8>, RequestId, String),
    Reject(Caller<u8, u8>, RequestId),
}

#[derive(Clone, Debug, PartialEq)]
struct Model {
    s: S,
    /// Ghost: requests whose agent key was revoked while they were pending.
    void: BTreeSet<RequestId>,
}

/// xorshift64*, deterministic so failures reproduce.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

fn random_caller(rng: &mut Rng, s: &S) -> Caller<u8, u8> {
    let signer = rng.pick(&ACCOUNTS);
    let predecessor = if rng.chance(90) {
        signer
    } else {
        rng.pick(&ACCOUNTS)
    };
    let own_keys: Vec<u8> = s
        .principals
        .iter()
        .filter(|(_, p)| p.account_id == signer)
        .map(|(k, _)| *k)
        .collect();
    let signer_key = if !own_keys.is_empty() && rng.chance(75) {
        rng.pick(&own_keys)
    } else {
        rng.pick(&KEYS)
    };
    Caller {
        predecessor,
        signer,
        signer_key,
    }
}

fn random_action(rng: &mut Rng) -> String {
    match rng.below(24) {
        0 => String::new(),
        1 => "a".repeat(MAX_ACTION_LEN),
        2 => "a".repeat(MAX_ACTION_LEN + 1),
        3 => "é".repeat(MAX_ACTION_LEN / 2),
        4 => "é".repeat(MAX_ACTION_LEN / 2 + 1),
        _ => format!("act-{}", rng.below(6)),
    }
}

fn random_op(rng: &mut Rng, s: &S) -> Op {
    let admin = |rng: &mut Rng| {
        if rng.chance(85) {
            OWNER
        } else {
            rng.pick(&ACCOUNTS)
        }
    };
    match rng.below(100) {
        0..=14 => {
            let role = if rng.chance(50) {
                Role::Agent
            } else {
                Role::Approver
            };
            Op::Add(admin(rng), rng.pick(&KEYS), rng.pick(&ACCOUNTS), role)
        }
        15..=21 => Op::Revoke(admin(rng), rng.pick(&KEYS)),
        22..=61 => Op::Request(random_caller(rng, s), random_action(rng)),
        90..=99 => {
            let id = rng.below(s.requests.len() as u64 + 1);
            Op::Reject(random_caller(rng, s), id)
        }
        _ => {
            let id = rng.below(s.requests.len() as u64 + 1);
            let action = match s.request(id) {
                Some(r) if rng.chance(85) => r.action,
                _ => random_action(rng),
            };
            Op::Approve(random_caller(rng, s), id, action)
        }
    }
}

/// Authentication guards, in specified order.
fn auth_error(s: &S, caller: &Caller<u8, u8>, role: Role) -> Option<ApprovalError> {
    if caller.predecessor != caller.signer {
        return Some(ApprovalError::IndirectCall);
    }
    let Some(p) = s.principal(&caller.signer_key) else {
        return Some(ApprovalError::UnknownKey);
    };
    if p.role != role {
        return Some(ApprovalError::WrongRole);
    }
    if p.account_id != caller.signer {
        return Some(ApprovalError::KeyAccountMismatch);
    }
    None
}

/// The specified outcome of each operation: `None` for success, otherwise
/// the first failing guard.
fn expected_err(m: &Model, op: &Op) -> Option<ApprovalError> {
    let s = &m.s;
    match op {
        Op::Add(caller, key, _, _) => {
            if *caller != OWNER {
                Some(ApprovalError::NotOwner)
            } else if s.principal(key).is_some() {
                Some(ApprovalError::KeyAlreadyRegistered)
            } else {
                None
            }
        }
        Op::Revoke(caller, key) => {
            if *caller != OWNER {
                Some(ApprovalError::NotOwner)
            } else if s.principal(key).is_none() {
                Some(ApprovalError::KeyNotRegistered)
            } else {
                None
            }
        }
        Op::Request(caller, action) => auth_error(s, caller, Role::Agent).or_else(|| {
            if action.is_empty() {
                Some(ApprovalError::EmptyAction)
            } else if action.len() > MAX_ACTION_LEN {
                Some(ApprovalError::ActionTooLong)
            } else if ghost_pending(m, caller.signer_key) >= MAX_PENDING_PER_KEY as usize {
                Some(ApprovalError::TooManyPending)
            } else {
                None
            }
        }),
        Op::Approve(caller, id, action) => auth_error(s, caller, Role::Approver).or_else(|| {
            let Some(r) = s.request(*id) else {
                return Some(ApprovalError::RequestNotFound);
            };
            if r.approval.is_some() {
                Some(ApprovalError::AlreadyApproved)
            } else if r.rejection.is_some() {
                Some(ApprovalError::AlreadyRejected)
            } else if m.void.contains(id) {
                Some(ApprovalError::AgentRevoked)
            } else if r.action != *action {
                Some(ApprovalError::ActionMismatch)
            } else if caller.signer == r.agent_account_id {
                Some(ApprovalError::SelfApproval)
            } else {
                None
            }
        }),
        Op::Reject(caller, id) => auth_error(s, caller, Role::Approver).or_else(|| {
            let Some(r) = s.request(*id) else {
                return Some(ApprovalError::RequestNotFound);
            };
            if r.approval.is_some() {
                Some(ApprovalError::AlreadyApproved)
            } else if r.rejection.is_some() {
                Some(ApprovalError::AlreadyRejected)
            } else if m.void.contains(id) {
                Some(ApprovalError::AgentRevoked)
            } else if caller.signer == r.agent_account_id {
                Some(ApprovalError::SelfApproval)
            } else {
                None
            }
        }),
    }
}

fn undecided(r: &ActionRequest<u8, u8>) -> bool {
    r.approval.is_none() && r.rejection.is_none()
}

/// Live (pending, not void) requests made with `key`, per the ghost model.
fn ghost_pending(m: &Model, key: u8) -> usize {
    m.s.requests
        .iter()
        .filter(|r| r.agent_key == key && undecided(r) && !m.void.contains(&r.id))
        .count()
}

fn ghost_status(m: &Model, r: &ActionRequest<u8, u8>) -> RequestStatus {
    if r.approval.is_some() {
        RequestStatus::Approved
    } else if r.rejection.is_some() {
        RequestStatus::Rejected
    } else if m.void.contains(&r.id) {
        RequestStatus::Void
    } else {
        RequestStatus::Pending
    }
}

fn principals_except(s: &S, key: u8) -> Vec<(u8, Principal<u8>)> {
    let mut v: Vec<_> = s
        .principals
        .iter()
        .filter(|(k, _)| *k != key)
        .cloned()
        .collect();
    v.sort_by_key(|(k, _)| *k);
    v
}

fn check_invariants(m: &Model) {
    let s = &m.s;
    assert_eq!(s.owner, OWNER);
    assert!(s.approval_log.len() <= s.requests.len());
    for (i, (id, _)) in s.revocations.iter().enumerate() {
        assert!(
            *id < s.registration_count,
            "revoked an unissued registration"
        );
        assert!(
            s.revocations[i + 1..].iter().all(|(id2, _)| id2 != id),
            "registration revoked twice"
        );
    }
    for (i, (k, p)) in s.principals.iter().enumerate() {
        assert!(
            s.principals[i + 1..].iter().all(|(k2, _)| k2 != k),
            "duplicate key"
        );
        assert!(
            s.principals[i + 1..]
                .iter()
                .all(|(_, p2)| p2.registration_id != p.registration_id),
            "duplicate registration id"
        );
        assert!(p.registration_id < s.registration_count);
        assert_eq!(s.revocation(p.registration_id), None, "live key is revoked");
        assert!(p.active_from <= s.request_count());
        let expected_pending = match p.role {
            Role::Agent => ghost_pending(m, *k),
            Role::Approver => 0,
        };
        assert_eq!(
            p.pending as usize, expected_pending,
            "pending count for key {k}"
        );
        assert!(p.pending <= MAX_PENDING_PER_KEY);
    }
    for (i, r) in s.requests.iter().enumerate() {
        assert_eq!(r.id, i as u64, "request ids are dense");
        assert!(!r.action.is_empty() && r.action.len() <= MAX_ACTION_LEN);
        assert!(r.agent_registration_id < s.registration_count);
        assert!(
            r.approval.is_none() || r.rejection.is_none(),
            "approved and rejected"
        );
        // The registration-id view of revocation agrees with the ghost model.
        if undecided(r) {
            assert_eq!(
                s.revocation(r.agent_registration_id).is_some(),
                m.void.contains(&r.id)
            );
        }
        if let Some(j) = &r.rejection {
            assert_ne!(
                j.approver_account_id, r.agent_account_id,
                "separation of duties"
            );
            assert!(!m.void.contains(&r.id), "void requests are never rejected");
        }
        if let Some(a) = &r.approval {
            assert_eq!(s.approval_log.get(a.approval_index as usize), Some(&r.id));
            assert_ne!(
                a.approver_account_id, r.agent_account_id,
                "separation of duties"
            );
            assert!(a.approved_at.height >= r.requested_at.height);
            assert!(!m.void.contains(&r.id), "void requests are never approved");
        }
        assert_eq!(request_status(s, r.id), Some(ghost_status(m, r)));
    }
    for (j, &id) in s.approval_log.iter().enumerate() {
        let r = &s.requests[id as usize];
        assert_eq!(
            r.approval.as_ref().map(|a| a.approval_index),
            Some(j as u64)
        );
    }
}

/// Applies `op` and checks its result and frame condition against `pre`.
fn step(m: &mut Model, op: &Op, now: BlockTime) -> Result<(), ApprovalError> {
    let pre = m.clone();
    let expected = expected_err(&pre, op);
    let s = &mut m.s;
    let result = match op {
        Op::Add(caller, key, account, role) => {
            add_principal(s, caller, *key, *account, *role).map(|returned| {
                let added = Principal {
                    account_id: *account,
                    role: *role,
                    registration_id: pre.s.registration_count,
                    active_from: pre.s.request_count(),
                    pending: 0,
                };
                assert_eq!(returned, added);
                assert_eq!(s.principal(key), Some(added));
                assert_eq!(s.registration_count, pre.s.registration_count + 1);
                assert_eq!(principals_except(s, *key), principals_except(&pre.s, *key));
                assert_eq!(
                    (&s.requests, &s.approval_log, &s.revocations),
                    (&pre.s.requests, &pre.s.approval_log, &pre.s.revocations)
                );
            })
        }
        Op::Revoke(caller, key) => revoke_key(s, caller, key, now).map(|removed| {
            assert_eq!(s.revocation(removed.registration_id), Some(now));
            assert_eq!(
                &s.revocations[..pre.s.revocations.len()],
                &pre.s.revocations[..]
            );
            assert_eq!(s.revocations.len(), pre.s.revocations.len() + 1);
            assert_eq!(pre.s.principal(key), Some(removed));
            assert_eq!(s.principal(key), None);
            assert_eq!(principals_except(s, *key), principals_except(&pre.s, *key));
            assert_eq!(
                (&s.requests, &s.approval_log, s.registration_count),
                (
                    &pre.s.requests,
                    &pre.s.approval_log,
                    pre.s.registration_count
                )
            );
            m.void.extend(
                s.requests
                    .iter()
                    .filter(|r| r.agent_key == *key && undecided(r))
                    .map(|r| r.id),
            );
        }),
        Op::Request(caller, action) => request_action(s, caller, action.clone(), now).map(|r| {
            assert_eq!(r.id, pre.s.request_count());
            assert_eq!(
                (r.agent_account_id, r.agent_key),
                (caller.signer, caller.signer_key)
            );
            assert_eq!(
                (&r.action, r.requested_at, &r.approval, &r.rejection),
                (action, now, &None, &None)
            );
            assert_eq!(
                r.agent_registration_id,
                pre.s.principal(&caller.signer_key).unwrap().registration_id
            );
            assert_eq!(&s.requests[..pre.s.requests.len()], &pre.s.requests[..]);
            assert_eq!(s.requests.last(), Some(&r));
            assert_eq!(s.approval_log, pre.s.approval_log);
            let key = caller.signer_key;
            assert_eq!(principals_except(s, key), principals_except(&pre.s, key));
            let (before, after) = (pre.s.principal(&key).unwrap(), s.principal(&key).unwrap());
            assert_eq!(
                after,
                Principal {
                    pending: before.pending + 1,
                    ..before
                }
            );
        }),
        Op::Approve(caller, id, _) => approve(s, caller, *id, &op_action(op), now).map(|proof| {
            let idx = *id as usize;
            assert_eq!(proof.approval_index, pre.s.approval_count());
            assert_eq!(
                (
                    proof.approver_account_id,
                    proof.approver_key,
                    proof.approver_registration_id,
                    proof.approved_at
                ),
                (
                    caller.signer,
                    caller.signer_key,
                    pre.s.principal(&caller.signer_key).unwrap().registration_id,
                    now
                )
            );
            assert_eq!(s.requests[idx].proof(), Some(proof));
            assert_eq!(
                Some(ActionRequest {
                    approval: None,
                    ..s.requests[idx].clone()
                }),
                pre.s.request(*id)
            );
            for (j, r) in s.requests.iter().enumerate() {
                if j != idx {
                    assert_eq!(r, &pre.s.requests[j]);
                }
            }
            assert_eq!(
                &s.approval_log[..pre.s.approval_log.len()],
                &pre.s.approval_log[..]
            );
            assert_eq!(s.approval_log.last(), Some(id));
            assert_eq!(s.approval_log.len(), pre.s.approval_log.len() + 1);
            let key = s.requests[idx].agent_key;
            assert_eq!(principals_except(s, key), principals_except(&pre.s, key));
            let (before, after) = (pre.s.principal(&key).unwrap(), s.principal(&key).unwrap());
            assert_eq!(
                after,
                Principal {
                    pending: before.pending - 1,
                    ..before
                }
            );
        }),
        Op::Reject(caller, id) => reject(s, caller, *id, now).map(|rejected| {
            let idx = *id as usize;
            assert_eq!(
                rejected.rejection,
                Some(Rejection {
                    approver_account_id: caller.signer,
                    approver_key: caller.signer_key,
                    approver_registration_id: pre
                        .s
                        .principal(&caller.signer_key)
                        .unwrap()
                        .registration_id,
                    rejected_at: now,
                })
            );
            assert_eq!(s.requests[idx], rejected);
            assert_eq!(
                Some(ActionRequest {
                    rejection: None,
                    ..rejected.clone()
                }),
                pre.s.request(*id)
            );
            for (j, r) in s.requests.iter().enumerate() {
                if j != idx {
                    assert_eq!(r, &pre.s.requests[j]);
                }
            }
            assert_eq!(s.approval_log, pre.s.approval_log);
            let key = rejected.agent_key;
            assert_eq!(principals_except(s, key), principals_except(&pre.s, key));
            let (before, after) = (pre.s.principal(&key).unwrap(), s.principal(&key).unwrap());
            assert_eq!(
                after,
                Principal {
                    pending: before.pending - 1,
                    ..before
                }
            );
        }),
    };
    assert_eq!(result.err(), expected, "wrong outcome for {op:?}");
    if result.is_err() {
        assert_eq!(*m, pre, "failed operation must not change state");
    }
    // Decided requests are immutable under every operation.
    for r in pre.s.requests.iter().filter(|r| !undecided(r)) {
        assert_eq!(m.s.request(r.id).as_ref(), Some(r));
    }
    // Void is terminal.
    assert!(pre.void.is_subset(&m.void));
    check_invariants(m);
    result
}

fn op_action(op: &Op) -> String {
    match op {
        Op::Request(_, a) | Op::Approve(_, _, a) => a.clone(),
        _ => String::new(),
    }
}

#[test]
fn random_operation_sequences_preserve_invariants() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut successes = [0u32; 5];
    let mut errors = BTreeSet::new();
    let mut voided = 0;
    for _ in 0..3_000 {
        let mut m = Model {
            s: S::new(OWNER),
            void: BTreeSet::new(),
        };
        let mut now = t(0);
        // Some sequences never decide anything, so agents hit the pending cap.
        let flood = rng.chance(10);
        for _ in 0..120 {
            now.height += rng.below(3);
            now.timestamp_ns += rng.below(3) * 1_000_000_000;
            let op = loop {
                let op = random_op(&mut rng, &m.s);
                if !(flood && matches!(op, Op::Approve(..) | Op::Reject(..))) {
                    break op;
                }
            };
            let kind = match op {
                Op::Add(..) => 0,
                Op::Revoke(..) => 1,
                Op::Request(..) => 2,
                Op::Approve(..) => 3,
                Op::Reject(..) => 4,
            };
            match step(&mut m, &op, now) {
                Ok(()) => successes[kind] += 1,
                Err(e) => {
                    errors.insert(format!("{e:?}"));
                }
            }
        }
        voided += m.void.len();
        let paged: Vec<_> = (0..m.s.approval_count())
            .step_by(7)
            .flat_map(|from| approvals(&m.s, from, 7))
            .collect();
        let expected: Vec<_> =
            m.s.approval_log
                .iter()
                .map(|&id| m.s.requests[id as usize].proof().unwrap())
                .collect();
        assert_eq!(
            paged, expected,
            "paging must enumerate the log exactly once, in order"
        );
    }
    // Guard against a vacuous run: every success path and every error
    // reachable through MemStore must have been exercised.
    assert!(
        successes.iter().all(|&n| n > 1_000),
        "successes: {successes:?}"
    );
    assert!(voided > 1_000, "voided: {voided}");
    let reachable = [
        "NotOwner",
        "IndirectCall",
        "UnknownKey",
        "WrongRole",
        "KeyAccountMismatch",
        "KeyAlreadyRegistered",
        "KeyNotRegistered",
        "EmptyAction",
        "ActionTooLong",
        "TooManyPending",
        "RequestNotFound",
        "AlreadyApproved",
        "AlreadyRejected",
        "AgentRevoked",
        "ActionMismatch",
        "SelfApproval",
    ];
    for e in reachable {
        assert!(errors.contains(e), "never observed {e}; saw {errors:?}");
    }
}
