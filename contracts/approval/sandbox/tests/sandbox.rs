//! Runs the approval contract's wasm in a local NEAR sandbox, covering what
//! the mocked-runtime unit tests can't: `#[private]` init and re-init,
//! deposits on non-payable methods, JSON argument names, the real
//! `signer_account_pk` of function-call access keys, storage staking, and
//! the worst-case event size against NEAR's 16 KiB log limit.
//!
//! Build the wasm first (`cargo near build non-reproducible-wasm` in
//! `contract/`, or the reproducible build), or point `APPROVAL_WASM` at one.

use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{
    AccessKey, AccountDetailsPatch, KeyType, NearToken, PublicKey, SecretKey,
};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::{json, Value};

/// NEAR's limit on the total length of logs emitted by one receipt.
const MAX_TOTAL_LOG_LEN: usize = 16 * 1024;
/// Storage price: yoctoNEAR per byte.
const YOCTO_PER_BYTE: u128 = 10_000_000_000_000_000_000;
const MAX_ACTION_LEN: usize = 2048;

fn wasm() -> Vec<u8> {
    let path = std::env::var("APPROVAL_WASM").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../target/near/approval_contract/approval_contract.wasm"
        )
        .to_string()
    });
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!("can't read {path}: {e}. Run `cargo near build non-reproducible-wasm` in contract/ or set APPROVAL_WASM")
    })
}

/// The text of a failed call: either the transaction was rejected before
/// execution (`Err`) or it executed and failed. Panics if it succeeded.
fn failure(result: near_workspaces::Result<ExecutionFinalResult>) -> String {
    match result {
        Err(e) => format!("{e:?}"),
        Ok(outcome) => match outcome.into_result() {
            Ok(success) => panic!("expected failure, got success: {:?}", success.logs()),
            Err(failure) => format!("{failure:?}"),
        },
    }
}

fn assert_fails_with(result: near_workspaces::Result<ExecutionFinalResult>, needle: &str) {
    let text = failure(result);
    assert!(text.contains(needle), "expected {needle:?} in {text}");
}

fn events(outcome: &ExecutionFinalResult) -> Vec<Value> {
    outcome
        .logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str(j).unwrap())
        .collect()
}

fn single_event(outcome: &ExecutionFinalResult) -> Value {
    let all = events(outcome);
    assert_eq!(all.len(), 1, "expected one event: {all:?}");
    all.into_iter().next().unwrap()
}

/// Longest log total of any receipt in `outcome`.
fn max_receipt_log_len(outcome: &ExecutionFinalResult) -> usize {
    outcome
        .receipt_outcomes()
        .iter()
        .map(|r| r.logs.iter().map(String::len).sum::<usize>())
        .max()
        .unwrap_or(0)
}

async fn subaccount(worker: &Worker<Sandbox>, name: &str, near: u128) -> Account {
    worker
        .root_account()
        .unwrap()
        .create_subaccount(name)
        .initial_balance(NearToken::from_near(near))
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap()
}

/// Gives `account` a function-call access key for `methods` on `contract`
/// and returns a handle that signs with that key.
async fn function_call_key(
    worker: &Worker<Sandbox>,
    account: &Account,
    contract: &AccountId,
    methods: &[&str],
    key_type: KeyType,
) -> Account {
    let sk = SecretKey::from_random(key_type);
    account
        .batch(account.id())
        .add_key(
            sk.public_key(),
            AccessKey::function_call_access(contract, methods, None),
        )
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();
    Account::from_secret_key(account.id().clone(), sk, worker)
}

fn pk(account: &Account) -> PublicKey {
    account.secret_key().public_key()
}

struct Setup {
    worker: Worker<Sandbox>,
    contract: Contract,
    owner: Account,
    /// The agent account, signing with its full-access key.
    agent_account: Account,
    /// The agent account, signing with its registered function-call key.
    agent: Account,
    approver: Account,
}

/// Deploys and initializes the contract, then registers one agent and one
/// approver, each signing with a function-call key scoped to the contract.
/// Account names default to short ones; `long_names` uses 64-character ids.
async fn setup(long_names: bool, key_type: KeyType) -> Setup {
    let worker = near_workspaces::sandbox().await.unwrap();
    let root_len = worker.root_account().unwrap().id().as_str().len();
    let name = |c: char, short: &str| {
        if long_names {
            // `{name}.{root}` must be at most 64 characters.
            c.to_string().repeat(64 - root_len - 1)
        } else {
            short.to_string()
        }
    };
    let contract_account = subaccount(&worker, "approvals", 20).await;
    let contract = contract_account
        .deploy(&wasm())
        .await
        .unwrap()
        .into_result()
        .unwrap();
    let owner = subaccount(&worker, "owner", 10).await;
    contract
        .call("new")
        .args_json(json!({ "owner_id": owner.id() }))
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();

    let agent_account = subaccount(&worker, &name('a', "agent"), 10).await;
    let approver_account = subaccount(&worker, &name('b', "approver"), 10).await;
    let agent = function_call_key(
        &worker,
        &agent_account,
        contract.id(),
        &["request_action"],
        key_type,
    )
    .await;
    let approver = function_call_key(
        &worker,
        &approver_account,
        contract.id(),
        &["approve", "reject"],
        key_type,
    )
    .await;
    for (method, account) in [("add_agent", &agent), ("add_approver", &approver)] {
        owner
            .call(contract.id(), method)
            .args_json(json!({ "account_id": account.id(), "public_key": pk(account) }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();
    }
    Setup {
        worker,
        contract,
        owner,
        agent_account,
        agent,
        approver,
    }
}

async fn request_action(s: &Setup, action: &str) -> near_workspaces::Result<ExecutionFinalResult> {
    s.agent
        .call(s.contract.id(), "request_action")
        .args_json(json!({ "action": action }))
        .max_gas()
        .transact()
        .await
}

async fn view(s: &Setup, method: &str, args: Value) -> Value {
    s.contract
        .view(method)
        .args_json(args)
        .await
        .unwrap()
        .json()
        .unwrap()
}

#[tokio::test]
async fn init_is_private_and_runs_once() {
    let worker = near_workspaces::sandbox().await.unwrap();
    let contract_account = subaccount(&worker, "approvals", 20).await;
    let contract = contract_account
        .deploy(&wasm())
        .await
        .unwrap()
        .into_result()
        .unwrap();
    let stranger = subaccount(&worker, "stranger", 10).await;
    let init = json!({ "owner_id": stranger.id() });

    assert_fails_with(
        stranger
            .call(contract.id(), "new")
            .args_json(&init)
            .transact()
            .await,
        "Method new is private",
    );
    // Uninitialized state can't be used.
    assert_fails_with(
        stranger
            .call(contract.id(), "add_agent")
            .args_json(json!({ "account_id": stranger.id(), "public_key": pk(&stranger) }))
            .transact()
            .await,
        "The contract is not initialized",
    );

    contract
        .call("new")
        .args_json(&init)
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();
    let owner: AccountId = contract.view("get_owner").await.unwrap().json().unwrap();
    assert_eq!(&owner, stranger.id());

    assert_fails_with(
        contract.call("new").args_json(&init).transact().await,
        "The contract has already been initialized",
    );
}

#[tokio::test]
async fn function_call_keys_identify_the_signer() {
    let s = setup(false, KeyType::ED25519).await;
    let c = s.contract.id();

    // The request is attributed to the function-call key that signed it.
    let outcome = request_action(&s, "deploy v2").await.unwrap();
    assert!(outcome.is_success(), "{:?}", outcome.failures());
    let event = single_event(&outcome);
    assert_eq!(event["event"], "approval_requested");
    assert_eq!(event["data"]["agent_account_id"], json!(s.agent.id()));
    assert_eq!(event["data"]["agent_public_key"], json!(pk(&s.agent)));
    let id: u64 = outcome.json().unwrap();

    // The agent account's own full-access key is not a registered key.
    assert_fails_with(
        s.agent_account
            .call(c, "request_action")
            .args_json(json!({ "action": "x" }))
            .transact()
            .await,
        "signing key is unknown",
    );
    // A key registered to the agent account but signing for another account
    // fails the account binding.
    let other = subaccount(&s.worker, "other", 5).await;
    s.owner
        .call(c, "add_agent")
        .args_json(json!({ "account_id": s.agent.id(), "public_key": pk(&other) }))
        .transact()
        .await
        .unwrap()
        .into_result()
        .unwrap();
    assert_fails_with(
        other
            .call(c, "request_action")
            .args_json(json!({ "action": "x" }))
            .transact()
            .await,
        "signing key belongs to another account",
    );

    // The agent's key is scoped to `request_action`: the runtime refuses any
    // other method before the contract runs.
    assert_fails_with(
        s.agent
            .call(c, "approve")
            .args_json(json!({ "request_id": id, "action": "deploy v2" }))
            .transact()
            .await,
        "MethodNameMismatch",
    );

    // The approver's restatement must match.
    assert_fails_with(
        s.approver
            .call(c, "approve")
            .args_json(json!({ "request_id": id, "action": "deploy v3" }))
            .transact()
            .await,
        "action does not match the request",
    );
    let outcome = s
        .approver
        .call(c, "approve")
        .args_json(json!({ "request_id": id, "action": "deploy v2" }))
        .transact()
        .await
        .unwrap();
    assert!(outcome.is_success(), "{:?}", outcome.failures());
    let event = single_event(&outcome);
    assert_eq!(event["event"], "action_approved");
    assert_eq!(event["data"]["approver_public_key"], json!(pk(&s.approver)));
    assert_eq!(event["data"]["agent_public_key"], json!(pk(&s.agent)));

    // Views take the documented argument names.
    let proof = view(&s, "get_approval", json!({ "request_id": id })).await;
    assert_eq!(proof, event["data"]);
    let page = view(&s, "get_approvals", json!({ "from_index": 0, "limit": 10 })).await;
    assert_eq!(page, json!([event["data"]]));
    let request = view(&s, "get_request", json!({ "request_id": id })).await;
    assert_eq!(request["status"], "approved");
    let principal = view(&s, "get_principal", json!({ "public_key": pk(&s.agent) })).await;
    assert_eq!(principal["role"], "agent");

    // Rejection through the approver's scoped key.
    let rejected: u64 = request_action(&s, "rm -rf /")
        .await
        .unwrap()
        .json()
        .unwrap();
    let outcome = s
        .approver
        .call(c, "reject")
        .args_json(json!({ "request_id": rejected }))
        .transact()
        .await
        .unwrap();
    assert!(outcome.is_success(), "{:?}", outcome.failures());
    assert_eq!(single_event(&outcome)["event"], "action_rejected");
    let rejection = view(&s, "get_rejection", json!({ "request_id": rejected })).await;
    assert_eq!(rejection["approver_public_key"], json!(pk(&s.approver)));

    // Non-payable methods refuse deposits.
    assert_fails_with(
        s.owner
            .call(c, "add_agent")
            .args_json(json!({ "account_id": s.owner.id(), "public_key": pk(&s.owner) }))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await,
        "doesn't accept deposit",
    );

    // Revocation is recorded and reported on the proof.
    let outcome = s
        .owner
        .call(c, "revoke_key")
        .args_json(json!({ "public_key": pk(&s.approver) }))
        .transact()
        .await
        .unwrap();
    assert!(outcome.is_success(), "{:?}", outcome.failures());
    let event = single_event(&outcome);
    assert_eq!(event["event"], "key_revoked");
    let proof = view(&s, "get_approval", json!({ "request_id": id })).await;
    assert_eq!(
        proof["approver_key_revoked_at"]["block"],
        event["data"]["revoked_at_block"]
    );
    let revocation = view(
        &s,
        "get_revocation",
        json!({ "registration_id": event["data"]["registration_id"] }),
    )
    .await;
    assert_eq!(revocation, proof["approver_key_revoked_at"]);
}

#[tokio::test]
async fn storage_staking_limits_requests() {
    let s = setup(false, KeyType::ED25519).await;
    let action = "a".repeat(MAX_ACTION_LEN);

    // Leave the contract account enough balance for its current storage
    // plus about one maximum-size request.
    let details = s.contract.view_account().await.unwrap();
    let headroom = 3_000u128;
    let balance = (details.storage_usage as u128 + headroom) * YOCTO_PER_BYTE;
    s.worker
        .patch(s.contract.id())
        .account_from_current(move |current| {
            AccountDetailsPatch::from(current).balance(NearToken::from_yoctonear(balance))
        })
        .transact()
        .await
        .unwrap();

    request_action(&s, &action)
        .await
        .unwrap()
        .into_result()
        .unwrap();
    assert_fails_with(request_action(&s, &action).await, "LackBalanceForState");
    // The failed receipt left no state behind.
    let count: u64 = view(&s, "get_request_count", json!({}))
        .await
        .as_u64()
        .unwrap();
    assert_eq!(count, 1);
    let principal = view(&s, "get_principal", json!({ "public_key": pk(&s.agent) })).await;
    assert_eq!(principal["pending"], 1);

    // Anyone can top the account up, after which requests succeed again.
    s.owner
        .transfer_near(s.contract.id(), NearToken::from_near(1))
        .await
        .unwrap()
        .into_result()
        .unwrap();
    let id: u64 = request_action(&s, &action).await.unwrap().json().unwrap();
    assert_eq!(id, 1);
}

#[tokio::test]
async fn worst_case_events_fit_the_log_limit() {
    // 64-character accounts, secp256k1 keys (the longest key encoding) and
    // a maximum-size action of control characters, each of which JSON
    // escapes to six bytes.
    let s = setup(true, KeyType::SECP256K1).await;
    assert_eq!(s.agent.id().as_str().len(), 64);
    assert_eq!(s.approver.id().as_str().len(), 64);
    let action = "\u{1}".repeat(MAX_ACTION_LEN);
    let c = s.contract.id();

    let mut sizes = Vec::new();
    let requested = request_action(&s, &action).await.unwrap();
    assert!(requested.is_success(), "{:?}", requested.failures());
    sizes.push(("approval_requested", max_receipt_log_len(&requested)));
    let id: u64 = requested.json().unwrap();

    let approved = s
        .approver
        .call(c, "approve")
        .args_json(json!({ "request_id": id, "action": action }))
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(approved.is_success(), "{:?}", approved.failures());
    assert_eq!(single_event(&approved)["data"]["action"], json!(action));
    sizes.push(("action_approved", max_receipt_log_len(&approved)));

    let id: u64 = request_action(&s, &action).await.unwrap().json().unwrap();
    let rejected = s
        .approver
        .call(c, "reject")
        .args_json(json!({ "request_id": id }))
        .max_gas()
        .transact()
        .await
        .unwrap();
    assert!(rejected.is_success(), "{:?}", rejected.failures());
    sizes.push(("action_rejected", max_receipt_log_len(&rejected)));

    for (event, size) in sizes {
        eprintln!("{event}: {size} bytes of {MAX_TOTAL_LOG_LEN}");
        // Keep a margin so small schema additions don't hit the limit.
        assert!(
            size < MAX_TOTAL_LOG_LEN * 7 / 8,
            "{event} logs {size} bytes"
        );
    }
}
