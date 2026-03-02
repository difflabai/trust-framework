# Plan: Integrate Rust Adjudicator into Guard Server

## Context

The trust framework has three implementations:
1. **Python adjudicator** (`src/adjudicator/`, `tests/`, `pyproject.toml`) - the original behavior adjudicator
2. **Rust adjudicator** (`adjudicator/`) - a direct port of the Python adjudicator
3. **Rust guard system** (`guards/`) - a modular guard pipeline with HTTP server

The Rust adjudicator and guard system are independent crates with parallel type systems (both define `Verdict`, `RiskLevel`, `Domain`, `OperatingContext`). This plan integrates them and removes the now-redundant Python implementation.

## Step 1: Add adjudicator dependency to guard-adapters

**File**: `guards/crates/guard-adapters/Cargo.toml`

Add `adjudicator = { path = "../../../adjudicator" }` to dependencies.

## Step 2: Create AdjudicatorGuard adapter

**New file**: `guards/crates/guard-adapters/src/adjudicator_guard.rs`

Create a struct `AdjudicatorGuard` that:
- Wraps `adjudicator::BehaviorAdjudicator` (behind `Arc` for `Send + Sync`)
- Implements `guard_core::Guard` trait
- Converts between the two type systems:
  - `guard_core::Verdict` <-> `adjudicator::Verdict` (identical except guard has `Quarantine`)
  - `guard_core::RiskLevel` <-> `adjudicator::RiskLevel` (identical)
  - `guard_core::Domain` <-> `adjudicator::Domain` (guard has extra `Custom(String)`)
  - `guard_core::OperatingContext` -> `adjudicator::OperatingContext` (Vec<String> -> BTreeSet<String>)
- Extracts `content` from `GuardPayload::to_json_value()` to create `ProposedOutput`
- Maps adjudicator verdicts to guard `DirectResult`

Conversion functions:
- `fn guard_verdict_from_adj(adjudicator::Verdict) -> guard_core::Verdict`
- `fn guard_risk_from_adj(adjudicator::RiskLevel) -> guard_core::RiskLevel`
- `fn adj_context_from_guard(guard_core::OperatingContext) -> adjudicator::OperatingContext`

## Step 3: Add adjudicate endpoints to server

**File**: `guards/crates/guard-adapters/src/server.rs`

Add to `EvalServerHandler`:
- Field: `adjudicator: Option<Arc<adjudicator::BehaviorAdjudicator>>`
- New constructor that accepts adjudicator
- `adjudicate_input(&self, request: AdjudicateRequest) -> Result<AdjudicateResponse, GuardError>` - POST /v1/adjudicate/input
- `adjudicate_output(&self, request: AdjudicateRequest) -> Result<AdjudicateResponse, GuardError>` - POST /v1/adjudicate/output

Define `AdjudicateRequest` and `AdjudicateResponse` types that map to adjudicator types, keeping the existing `EvalRequest`/`EvalResponse` for guard pipeline evaluation.

## Step 4: Export new module from guard-adapters

**File**: `guards/crates/guard-adapters/src/lib.rs`

Add `pub mod adjudicator_guard;` and re-export `AdjudicatorGuard`.

## Step 5: Remove Python implementation

Delete:
- `src/adjudicator/` directory (8 files)
- `tests/` directory (7 files)
- `pyproject.toml`

## Step 6: Create Architecture.md

**New file**: `Architecture.md` at project root

Document:
- System overview: guard pipeline + behavior adjudicator
- Guard lifecycle (definition, pipeline assembly, execution, aggregation)
- Adjudicator pipeline (observe, assess risk, evaluate policies, aggregate, record)
- How they integrate (AdjudicatorGuard adapter)
- Server API endpoints
- Type system (Verdict, RiskLevel, Domain, OperatingContext)
- Crate structure

## Critical Files

- `adjudicator/src/engine.rs` - BehaviorAdjudicator (the core to wrap)
- `adjudicator/src/types.rs` - adjudicator types needing conversion
- `guards/crates/guard-core/src/guard.rs` - Guard trait to implement
- `guards/crates/guard-core/src/verdict.rs` - guard Verdict/RiskLevel/Domain
- `guards/crates/guard-core/src/context.rs` - guard OperatingContext
- `guards/crates/guard-adapters/src/server.rs` - server handler to extend
- `guards/crates/guard-adapters/src/lib.rs` - module exports

## Verification

1. `cd guards && cargo build` - verify the workspace compiles with adjudicator dependency
2. `cd guards && cargo test` - all existing tests pass
3. `cd adjudicator && cargo test` - adjudicator tests still pass
4. New tests in `adjudicator_guard.rs` verify type conversions and guard trait behavior
5. New tests in `server.rs` verify adjudicate endpoints
