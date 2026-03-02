# Trust Framework Architecture

## Overview

The trust framework provides a layered security system for AI agent interactions. It combines two complementary evaluation approaches:

1. **Guard Pipeline** - Modular, async guards that evaluate payloads flowing through an AI system
2. **Behavior Adjudicator** - Policy-based behavioral evaluation that assesses outputs against configurable rules

Both systems share the same verdict model and can be composed together: the adjudicator can run as a guard within the pipeline.

## Crate Structure

```
manado/
├── adjudicator/                  # Behavior adjudicator library
│   └── src/
│       ├── engine.rs             # BehaviorAdjudicator - orchestrates the 5-stage pipeline
│       ├── types.rs              # Verdict, RiskLevel, Domain, OperatingContext, etc.
│       ├── policy.rs             # PolicyRule trait + built-in policies
│       ├── observer.rs           # Input signal extraction (topics, intent)
│       ├── risk.rs               # Weighted risk scoring
│       ├── audit.rs              # Append-only audit trail
│       └── error.rs              # Error types
├── guards/                       # Guard system workspace
│   └── crates/
│       ├── guard-core/           # Core types, Guard trait, pipeline, layers
│       ├── guard-continuation/   # Async continuation handles
│       ├── guard-adapters/       # Server, builder, hooks, MCP, adjudicator adapter
│       ├── guard-eval-client/    # HTTP client for remote evaluation
│       └── guard-plugins/        # Pluggable backends (Prolog, FFI)
└── Architecture.md               # This file
```

## Guard System

### Core Concepts

**Guard** - The fundamental evaluation unit. Each guard inspects a payload and returns a verdict:

```
Payload + Context → Guard → GuardOutput (Direct | Continuation | Warning | AsyncTrigger | Quarantine)
```

**Pipeline** - Executes guards sequentially by priority (highest first). Aggregates verdicts using precedence:

```
Deny > Quarantine > Escalate > Modify > Permit
```

**Layers** - `InputGuards` and `OutputGuards` wrap a pipeline with logging:

```
LLM Request → InputGuards → [LLM/Tool Execution] → OutputGuards → Response
```

### Guard Lifecycle

1. Define a struct implementing the `Guard` trait (descriptor + async evaluate method)
2. Add it to a `GuardPipeline` via `pipeline.add_guard()`
3. Wrap the pipeline in `InputGuards` or `OutputGuards`
4. Call `layer.evaluate(payload, context)` to run the pipeline

### Guard Output Types

| Type | Description |
|------|-------------|
| `Direct` | Immediate verdict with optional payload modification |
| `Continuation` | Deferred async evaluation resolved later |
| `Warning` | Advisory-only, no verdict change |
| `AsyncTrigger` | Fire-and-forget background task |
| `Quarantine` | Payload held for human review |

## Behavior Adjudicator

### Five-Stage Pipeline

```
Raw Input → Observe → Assess Risk → Evaluate Policies → Aggregate → Record
```

1. **Observe** - Extract signals from raw input: detected topics, intent (question/request/instruction/comparison), language
2. **Assess Risk** - Score the proposed output using weighted heuristics (content length, denied topic proximity, trust level)
3. **Evaluate Policies** - Run all applicable policy rules against the output
4. **Aggregate** - Combine verdicts (highest precedence wins) and risk levels (maximum wins)
5. **Record** - Append the result to an immutable audit trail

### Built-in Policies

| Policy | Priority | Action |
|--------|----------|--------|
| `ContentSafetyPolicy` | 200 | Denies outputs matching blocked regex patterns |
| `RiskThresholdPolicy` | 150 | Denies when assessed risk exceeds context maximum |
| `DeniedTopicPolicy` | 100 | Denies outputs referencing context-denied topics |
| `ScopeAdherencePolicy` | 90 | Escalates outputs that fall outside allowed topics |
| `InputOutputCoherencePolicy` | 50 | Escalates outputs unrelated to input topics |

Custom policies implement the `PolicyRule` trait and are added via `adjudicator.add_policy()`.

## Integration: AdjudicatorGuard

The `AdjudicatorGuard` adapter bridges the adjudicator into the guard pipeline. It:

1. Extracts content from the guard payload
2. Converts the guard `OperatingContext` to the adjudicator's context format
3. Runs `adjudicate_output_only()` through the full policy pipeline
4. Maps the adjudicator verdict back to a guard `DirectResult`

This lets the adjudicator's behavioral policies participate alongside regex guards, Prolog guards, and other custom guards in the same pipeline.

## Server API

The `EvalServerHandler` exposes the system as an HTTP/JSON service. Application code (axum, actix-web, etc.) routes requests to these handler methods.

### Guard Pipeline Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/evaluate/input` | Run input guard pipeline on payload |
| POST | `/v1/evaluate/output` | Run output guard pipeline on payload |

Request: `EvalRequest { request_id, payload, context?, metadata? }`
Response: `EvalResponse { request_id, verdict, reason, modified_payload?, warnings, evaluations }`

### Adjudication Endpoint

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/adjudicate` | Run behavior adjudicator on content |

Request: `AdjudicateRequest { request_id, content, raw_input?, context? }`
Response: `AdjudicateResponse { request_id, adjudication_id, verdict, reason, risk_level, policy_evaluations, modified_output? }`

When `raw_input` is provided, the adjudicator also evaluates input-output coherence. Without it, only output-side policies run.

### Other Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/quarantine/:id` | Get quarantine ticket status |
| POST | `/v1/quarantine/:id` | Resolve a quarantine ticket |
| POST | `/v1/guards/build` | Generate guard source code from a specification |

## Type System

### Shared Enums

Both systems use the same semantic types with separate Rust definitions (bridged by conversion functions in `adjudicator_guard`):

**Verdict**: `Permit`, `Modify`, `Escalate`, `Deny` (guards add `Quarantine`)

**RiskLevel**: `Low`, `Medium`, `High`, `Critical`

**Domain**: `General`, `Healthcare`, `Finance`, `Education`, `Legal`, `ContentModeration`, `CustomerService`, `CodeGeneration` (guards add `Custom(String)`)

### OperatingContext

Per-request configuration that governs evaluation behavior:

- `domain` - Operational domain for policy filtering
- `trust_level` - Float in [0.0, 1.0]; lower values increase risk scores
- `allowed_topics` - Scope restriction; outputs must address at least one
- `denied_topics` - Hard blocks; any mention triggers denial
- `max_risk_level` - Ceiling for acceptable risk
- `metadata` - Extensible key-value pairs

## Quarantine System

Guards can return a `Quarantine` verdict, placing payloads in a holding state for human review. The `QuarantineManager` tracks tickets with:

- Unique ticket IDs
- Pending/Approved/Denied states
- TTL-based automatic cleanup
- Resolution via the server API
