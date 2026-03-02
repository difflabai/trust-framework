# Architecture: InputGuards and OutputGuards

## Context

The Cambridge trust-framework has an existing Python `BehaviorAdjudicator` that evaluates AI outputs via composable policies, risk scoring, and audit logging. We need a new Rust-based guard infrastructure that sits at a lower level -- intercepting **all** tool calls and results in real-time, before they reach or leave an agentic system. The Python adjudicator can be called as one guard within this system, but the guard layers themselves must be fast, deployment-flexible, and support advanced evaluation semantics (continuations, quarantine, async triggers).

---

## Crate Layout

New Rust workspace at `guards/` alongside existing Python code:

```
cambridge/
  src/adjudicator/         # existing Python (unchanged)
  guards/                  # NEW Rust workspace
    Cargo.toml             # workspace manifest
    crates/
      guard-core/          # traits, pipeline, types, quarantine, audit
      guard-continuation/  # proxy value / continuation system
      guard-eval-client/   # remote evaluation server client + always-on logger
      guard-plugins/       # external evaluator plugin system (Prolog, FFI, WASM)
      guard-adapters/      # deployment adapters (hooks, MCP middleware, gRPC server)
```

**Key workspace dependencies**: `tokio`, `async-trait`, `serde`/`serde_json`, `reqwest` (HTTP transport, phase 1), `tonic`/`prost` (gRPC transport, phase 2, behind feature flag), `tracing`, `thiserror`, `uuid`, `chrono`, `scryer-prolog` (embedded Prolog)

---

## Core Type System (`guard-core`)

### Verdict (extended from Python)

```rust
enum Verdict { Permit, Modify, Escalate, Quarantine, Deny }
```

Precedence: `Deny(4) > Quarantine(3) > Escalate(2) > Modify(1) > Permit(0)`. Aggregation takes the max. Adds `Quarantine` over the Python model; Python's `ESCALATE` is the fallback mapping.

### WarningMetadata

Accumulates through the pipeline without blocking:
- `risk_score: f64` (0.0-1.0)
- `risk_level: RiskLevel` (Low/Medium/High/Critical -- matches Python)
- `warnings: Vec<Warning>` (source guard, level, message, code)
- `annotations: HashMap<String, Value>` (arbitrary KV)

### GuardPayload trait

Type-erased payload flowing through the pipeline. Concrete types defined per adapter (e.g., `ToolCallPayload`, `McpRequest`). Requires `Any + Send + Sync + Debug + clone_payload()`.

### Guard trait

```rust
#[async_trait]
trait Guard: Send + Sync {
    fn descriptor(&self) -> &GuardDescriptor;  // name, priority, short_circuits, domains
    async fn evaluate(&self, payload: &dyn GuardPayload, ctx: &GuardContext)
        -> Result<GuardOutput, GuardError>;
}
```

### GuardOutput enum (5 return semantics)

| Variant | Meaning | Pipeline behavior |
|---|---|---|
| `Direct(verdict, reason, modified_payload?, warnings)` | Immediate result | May short-circuit on Deny |
| `Continuation(handle, warnings)` | Proxy value for deferred eval | Pipeline continues; all continuations resolved before return |
| `Warning(warnings)` | Scoring/metadata only | Pipeline continues, warnings accumulate |
| `AsyncTrigger(JoinHandle, warnings)` | Fire-and-forget background eval | Pipeline continues, handle detached |
| `Quarantine(ticket, reason, warnings)` | Hold pending approval | Ticket created, pipeline may continue |

### GuardContext

Carries both static `OperatingContext` (domain, trust_level, allowed/denied topics, max_risk_level -- matching Python) and mutable `accumulated_warnings` + `request_meta` (request_id, timestamp, source_adapter, trace_id).

---

## Continuation System (`guard-continuation`)

**Not a Future/Promise.** A `ContinuationHandle` is a composable proxy value that represents a deferred evaluation. Downstream consumers can transform and compose over it while the actual guard evaluation completes asynchronously.

### ContinuationHandle API

- `map(F)` -- register a transform applied to the payload when resolved with Permit/Modify (transforms compose left-to-right)
- `flat_map(F)` -- chain with another guard evaluation that produces a new continuation
- `on_resolve(F)` -- observer callback fired on resolution
- `await_resolution(timeout)` -- block until settled (returns `Resolution`)
- `is_resolved()` -- non-blocking check

### Creation and Resolution

Created as `(ContinuationHandle, ContinuationResolver)` pair. The guard holds the `ContinuationResolver` and settles it asynchronously:

```rust
enum Resolution {
    Resolved { verdict: Verdict, payload: Option<Arc<dyn GuardPayload>>, warnings },
    Denied { reason, warnings },
    TimedOut { default_verdict: Verdict },
    Failed(GuardError),
}
```

On resolution, accumulated `map` transforms are applied (if Permit/Modify), then observers are notified, then the `watch` channel signals completion.

### Pipeline integration: resolve-before-return

**Continuations must always resolve before the value reaches the agent.** When a guard returns `Continuation`:
1. The pipeline records the handle and continues executing subsequent guards against the original payload
2. After all guards execute, the pipeline **awaits all outstanding continuations** (with a configurable timeout per the `PipelineConfig`)
3. Continuation verdicts are aggregated into the final `PipelineResult` using the same max-precedence rule
4. The pipeline returns only after all continuations have resolved (or timed out)

This means continuations provide **intra-pipeline concurrency** (a guard can kick off expensive evaluation, let other guards run in parallel, then the pipeline collects all results at the end) but the agent never receives an unresolved value. Timeout behavior: `PipelineConfig::continuation_timeout` with a configurable `timeout_verdict` (default: `Escalate`).

This model is simpler than optimistic-with-revocation while still allowing guards to perform expensive async work without serializing the entire pipeline.

---

## Guard Pipeline (`guard-core::pipeline`)

```rust
struct GuardPipeline { guards: Vec<Box<dyn Guard>>, config: PipelineConfig }
```

Execution:
1. Filter guards by domain applicability
2. Sort by priority (descending)
3. Execute sequentially with timeout enforcement
4. Short-circuit on Deny if configured
5. After all guards run, **await all outstanding continuations** (with `continuation_timeout`)
6. Aggregate all verdicts -- direct + resolved continuations (max precedence wins)
7. Accumulate warnings across all guards and resolved continuations
8. Return `PipelineResult` with verdict, payload, warnings, quarantine tickets, per-guard evaluations

### InputGuards and OutputGuards

Each wraps a `GuardPipeline` + `EvalLogger`. The `GuardLayer` trait provides `evaluate()`. **Base behavior**: both always call `eval_logger.log_input/log_output` before running the pipeline -- this is the minimum behavior even with zero custom guards.

---

## Quarantine State Machine (`guard-core::quarantine`)

States: `Pending -> Approved { reviewer, reason } | Denied { reviewer, reason } | Expired`

`QuarantineManager` creates tickets with TTL, spawns expiry timers, and provides `resolve(ticket_id, approved, reviewer, reason)`. Tickets carry a `payload_summary` for reviewer UI. State changes broadcast via `watch::Receiver<QuarantineState>`.

---

## Deployment Adapters (`guard-adapters`)

### 1. Claude Code Hooks (`hooks.rs`)
- Reads JSON from stdin, writes JSON to stdout (line-delimited)
- Maps `PreToolCall`/`PreMessage` -> OutputGuards, `PostToolCall`/`PostMessage` -> InputGuards
- Continuations resolve within the pipeline before the hook responds (resolve-before-return model)
- Produces a `HookResponse { verdict, reason, modified_payload?, warnings }`

### 2. MCP Gateway Middleware (`mcp.rs`)
- Wraps an inner `McpTransport`, interposes guard evaluation on request/response
- OutputGuard evaluates outgoing MCP requests; InputGuard evaluates responses
- Deny -> returns MCP error; Modify -> rewrites payload; Quarantine -> returns pending indicator

### 3. Standalone Evaluation Server (`server.rs`)
- HTTP/JSON server (phase 1), gRPC upgrade behind feature flag (phase 2)
- Exposes the `EvalTransport` API surface as endpoints
- Multiple agent instances can call this shared service
- Quarantine management endpoints for human review workflows

---

## Remote Evaluation Server Protocol (`guard-eval-client`)

### Transport: HTTP/JSON first, gRPC later

The client is built behind an `EvalTransport` trait so the transport is swappable:

```rust
#[async_trait]
trait EvalTransport: Send + Sync {
    async fn log_events(&self, events: Vec<LogEvent>) -> Result<LogAck, GuardError>;
    async fn evaluate_input(&self, req: EvaluateRequest) -> Result<EvaluateResponse, GuardError>;
    async fn evaluate_output(&self, req: EvaluateRequest) -> Result<EvaluateResponse, GuardError>;
    async fn get_quarantine_status(&self, id: &str) -> Result<QuarantineStatus, GuardError>;
    async fn resolve_quarantine(&self, resolution: QuarantineResolution) -> Result<QuarantineStatus, GuardError>;
}
```

**Phase 1 (initial dev)**: `HttpTransport` using `reqwest` -- POST JSON to REST endpoints. Simpler to debug and test.
**Phase 2 (after system eval)**: `GrpcTransport` using `tonic` -- streaming `LogEvents`, strongly typed protos. Swap via config.

### Always-On Logger (base behavior)
`EvalServerLogger` wraps an `EvalTransport` and:
- Buffers `LogEvent` messages in an mpsc channel (capacity 1024)
- Flushes batches every 100ms or 64 events
- Non-blocking: `try_send` drops events if buffer full (fail-open)
- Configurable `fail_open: bool` -- if eval server unreachable, guards still run

### API Surface (transport-agnostic)
```
POST /v1/evaluate/input     -> EvaluateResponse
POST /v1/evaluate/output    -> EvaluateResponse
POST /v1/log/events         -> LogAck (batch)
GET  /v1/quarantine/:id     -> QuarantineStatus
POST /v1/quarantine/:id     -> QuarantineStatus (resolve)
GET  /v1/audit              -> AuditResponse (query params)
```

All request/response types are serde-serializable structs that map 1:1 to future protobuf messages.

---

## Plugin System (`guard-plugins`)

### EvaluatorPlugin trait
```rust
#[async_trait]
trait EvaluatorPlugin: Send + Sync {
    fn name(&self) -> &str;
    async fn evaluate(&self, query: &Value, facts: &Value) -> Result<EvaluationResult, GuardError>;
    async fn health_check(&self) -> Result<(), GuardError>;
}
```

Returns `EvaluationResult { succeeded, bindings, score?, metadata }`.

### Implementations
- **PrologEvaluator**: Embeds **Scryer Prolog** (pure Rust, zero external dependencies). Guards construct Prolog queries and assert facts, submit to the embedded engine, and interpret variable bindings as guard results. Knowledge base files loaded from configured paths and cached in compiled form.
- **FfiPlugin**: Loads `.so/.dylib` via `libloading`. C ABI: `guard_plugin_evaluate(query, facts) -> result`.
- **Future**: WASM evaluator via `wasmtime` for sandboxed plugin execution.

`PluginRegistry` manages loaded plugins by name. Guards reference plugins by name from the registry.

---

## Python Adjudicator Integration

- **Shared types** serialize to JSON compatible with Python's dataclass serialization (Verdict, RiskLevel, Domain, OperatingContext, AdjudicationResult)
- **PythonAdjudicatorGuard**: A `Guard` impl that calls the Python adjudicator via subprocess (stdin/stdout JSON) or HTTP, maps its `AdjudicationResult` back to `GuardOutput::Direct`
- **Shared audit format**: Both systems write JSON-Lines audit records with the same schema

---

## Error Handling

`GuardError` enum with variants for: evaluation failures, guard conflicts, invalid context, pipeline timeout, continuation timeout/cancellation, quarantine not found/already resolved, plugin/FFI errors, eval server connection, serialization, gRPC, IO, internal.

**Philosophy**: Individual guard failures are caught, logged to audit, and the pipeline continues. Only `PipelineTimeout` and fatal `PipelineError` halt the entire pipeline.

---

## Implementation Order

| Phase | Crate | Key deliverables |
|---|---|---|
| 1 | `guard-core` (types only) | Verdict, RiskLevel, Domain, WarningMetadata, GuardPayload, GuardContext, GuardError |
| 2 | `guard-continuation` | ContinuationHandle, ContinuationResolver, Resolution |
| 3 | `guard-core` (traits + pipeline) | Guard trait, GuardOutput, GuardDescriptor, GuardPipeline, PipelineResult, InputGuards/OutputGuards, QuarantineManager |
| 4 | `guard-eval-client` | EvalTransport trait, HttpTransport (reqwest), EvalServerLogger (always-on) |
| 5 | `guard-plugins` | EvaluatorPlugin trait, PluginRegistry, PrologEvaluator, FfiPlugin |
| 6 | `guard-adapters` | Hooks adapter, MCP middleware, HTTP evaluation server |

## Verification

- Unit tests for each crate (verdict aggregation, pipeline execution with mock guards, continuation resolution/timeout, quarantine state transitions)
- Integration test: build a `GuardSystem` with a mix of Direct/Continuation/Warning/AsyncTrigger/Quarantine guards, run through the pipeline, verify aggregate behavior
- Continuation test: verify that continuations resolve before `PipelineResult` is returned, test timeout behavior, verify transform composition
- Adapter tests: simulate Claude Code hook stdin/stdout, mock MCP transport, HTTP eval server round-trip
- Python interop test: call Python adjudicator from `PythonAdjudicatorGuard`, verify JSON round-trip
- `cargo clippy` and `cargo test` across the workspace

## Key reference files (existing Python, unchanged)
- `src/adjudicator/types.py` -- Verdict, RiskLevel, Domain, OperatingContext (wire-compatible targets)
- `src/adjudicator/engine.py` -- Pipeline pattern: observe -> assess -> evaluate -> aggregate -> record
- `src/adjudicator/policy.py` -- PolicyRule ABC, priority ordering, domain filtering, registry
- `src/adjudicator/audit.py` -- Audit trail JSON format, thread-safety model
- `src/adjudicator/risk.py` -- Weighted scorer pattern informing WarningMetadata accumulation
