# Claude Guardrails Integration Plan

**Status:** Proposed  
**Author:** Dr. Ethan Blackwell  
**Date:** 2026-04-10  

## 1. Overview

[claude-guardrails](https://github.com/leegonzales/claude-guardrails) is a Rust-based security guardrails system designed for Claude Code's YOLO mode. It provides AST-based analysis of tool invocations using tree-sitter-bash, with 80+ rules covering dangerous commands, secrets protection, and exfiltration detection — all executing in sub-100ms with a fail-closed design.

### Why integrate it?

Trust-framework's guard pipeline evaluates AI agent payloads and returns verdicts (Deny > Quarantine > Escalate > Modify > Permit). Today, our input guards focus on behavioral policy (adjudicator), content patterns (prompt_bonk_guard), and file-level controls (file_sharing_guard). **None of them deeply understand shell commands or tool invocations at the AST level.**

Claude-guardrails fills a critical gap: it can catch `rm -rf /`, credential exfiltration via `curl`, reverse shells, and dozens of other dangerous patterns that regex-based guards would miss or over-match. Integrating it as an InputGuard means every agent payload flowing through trust-framework gets battle-tested command-level security analysis before execution.

The value is compounding — claude-guardrails already maintains 80+ rules across three safety tiers. Rather than duplicating that rule engineering effort, we gain it wholesale and focus our energy on the trust-framework-specific concerns (verdict aggregation, quarantine workflows, audit trail, ledger integration).

## 2. Architecture

### Where it fits

Claude-guardrails slots in as an **InputGuard** in the guard pipeline. It evaluates tool invocation payloads *before* they reach the LLM or tool execution layer:

```
Agent Request
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  InputGuards Pipeline                               │
│                                                     │
│  ┌──────────────────┐  ┌────────────────────────┐   │
│  │ prompt_bonk_guard │  │ file_sharing_guard     │   │
│  │ (priority: 100)  │  │ (priority: 90)         │   │
│  └──────────────────┘  └────────────────────────┘   │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │ claude_guardrails_guard  (NEW)               │   │
│  │ (priority: 200 — high, runs first)           │   │
│  │                                              │   │
│  │ AST-based shell analysis, secrets detection, │   │
│  │ exfiltration prevention, 80+ rules           │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
└─────────────────────────────────────────────────────┘
    │
    ▼
[LLM / Tool Execution]
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  OutputGuards Pipeline                              │
│  (adjudicator_guard, etc.)                          │
└─────────────────────────────────────────────────────┘
    │
    ▼
Agent Response
```

The guard should run at **high priority (200)** so dangerous commands are caught early, enabling `short_circuit_on_deny` to skip remaining guards when a critical threat is detected.

### Two integration options

| Approach | Description | Pros | Cons |
|----------|-------------|------|------|
| **Subprocess wrapper** | Spawn `claude-guardrails` binary, pipe JSON via stdin/stdout | Zero coupling, works today | Process spawn overhead (~5-10ms), serialization cost, harder to map types, binary must be installed |
| **Native Rust integration** | Import claude-guardrails as a library crate via `Cargo.toml` | Direct type access, zero IPC overhead, compile-time guarantees, shared Rust ecosystem | Requires claude-guardrails to expose a library interface (or we vendor/fork the analysis modules) |

**Recommendation: Native Rust integration** (see §3).

## 3. Integration Approach

### Why native Rust over subprocess

Both projects are Rust. Both deal with the same fundamental problem: evaluating agent actions for safety. The conceptual alignment is strong enough that a native integration is clearly superior:

1. **No serialization boundary.** Claude-guardrails reads JSON from stdin and writes JSON to stdout — that's its CLI interface. As a library, we call Rust functions directly with proper types. No JSON round-trip, no process spawn.

2. **Shared type semantics.** Claude-guardrails has rules that produce allow/deny decisions with reasons. Trust-framework has `Verdict` + `PolicyEvaluation`. These map naturally at the type level — a conversion layer is trivial (we already do this for the adjudicator, see `adjudicator_guard.rs`).

3. **Compile-time safety.** If claude-guardrails changes its rule output format, we get a compile error, not a runtime JSON parsing failure.

4. **Performance.** Claude-guardrails already targets sub-100ms. As a library call within the same process, we eliminate ~5-10ms of process spawn + IPC overhead and gain the ability to cache tree-sitter parsers across evaluations.

5. **Conditional compilation.** We can feature-gate the integration (`features = ["claude-guardrails"]`) so it's opt-in for builds that need it.

### Prerequisites

Claude-guardrails currently ships as a binary. To integrate natively, we need:

- **Option A (preferred):** Upstream PR to claude-guardrails refactoring the analysis engine into a `lib.rs` with a public API (e.g., `pub fn evaluate(tool_name: &str, input: &serde_json::Value, level: SafetyLevel) -> Vec<RuleResult>`). The binary's `main.rs` would then call this library.
- **Option B (interim):** Vendor the relevant modules (rule definitions, AST analysis, tree-sitter integration) into trust-framework as a local crate under `guards/crates/guard-claude-guardrails/`. Keep attribution and license compliance.
- **Option C (fallback):** Start with a subprocess adapter (call the binary), then migrate to native once the library API exists. This gets us running immediately.

**Recommended path:** Start with Option C (subprocess adapter) for immediate value, file an upstream PR for Option A, then migrate to native integration when the library API lands.

## 4. Concept Mapping

### Verdicts & Decisions

| claude-guardrails | trust-framework | Notes |
|---|---|---|
| `"allowed"` (rule passes) | `Verdict::Permit` | Rule matched no violations |
| `"denied"` / `"blocked"` (rule fires) | `Verdict::Deny` | Critical/high-severity rule violation |
| Rule fires at `strict` level only | `Verdict::Escalate` | Strict-only rules may warrant human review rather than hard deny |
| N/A | `Verdict::Quarantine` | Could be used for medium-confidence detections pending review |
| N/A | `Verdict::Modify` | Could strip dangerous portions while allowing safe parts through |

### Safety Levels → Risk Levels

| claude-guardrails Safety Level | trust-framework RiskLevel | Behavior |
|---|---|---|
| `critical` | `RiskLevel::Critical` | Only the most dangerous patterns blocked (rm -rf /, reverse shells). Minimal false positives. |
| `high` | `RiskLevel::High` | Adds secrets exposure, broad exfiltration patterns. Good default. |
| `strict` | `RiskLevel::Medium` (inverted — stricter checking = lower risk tolerance) | Maximum coverage — catches subtle patterns. May produce Escalate verdicts for edge cases. |

The mapping is inverted: claude-guardrails' `strict` level means "check everything" while trust-framework's `RiskLevel::Critical` means "maximum risk detected." The guard adapter maps between these:

```rust
fn safety_level_from_context(ctx: &OperatingContext) -> SafetyLevel {
    match ctx.max_risk_level {
        RiskLevel::Low => SafetyLevel::Strict,      // Low risk tolerance → strict checking
        RiskLevel::Medium => SafetyLevel::High,      // Medium tolerance → high checking
        RiskLevel::High => SafetyLevel::Critical,    // High tolerance → critical-only
        RiskLevel::Critical => SafetyLevel::Critical, // Maximum tolerance → critical-only
    }
}
```

### Rules → Guard Evaluations

Each claude-guardrails rule maps to a `PolicyEvaluation` (or the guard-core equivalent `GuardEvaluation`):

| claude-guardrails Rule Field | trust-framework Field | Example |
|---|---|---|
| Rule name/ID (e.g., `dangerous_rm`) | `policy_name` / `guard_name` | `"cg:dangerous_rm"` (namespaced with `cg:` prefix) |
| Rule description | `reason` | `"Detected rm with recursive force flags targeting root"` |
| Rule category (dangerous_commands, secrets, exfiltration) | `domain` metadata | Stored in evaluation metadata |
| Rule severity (critical, high, strict) | `risk_level` | Mapped per table above |
| Match details (line number, matched text) | `warnings` / evaluation metadata | Preserved for audit |

### Audit Trail

Claude-guardrails writes an audit log at `~/.claude/guardrails/audit.log`. Trust-framework has its own append-only audit trail (`adjudicator::audit`). The integration should:

1. **Primary:** Write all evaluations to trust-framework's audit trail via the standard `GuardEvaluation` recording path
2. **Optional:** Also emit to claude-guardrails' native audit format for compatibility with its existing tooling
3. **Correlation:** Include the trust-framework `request_id` in any claude-guardrails audit entries for cross-referencing

## 5. Implementation Steps

### Phase 1: Subprocess Adapter (1-2 days)

**Goal:** Get claude-guardrails running as an InputGuard immediately.

1. **Create `guards/crates/guard-adapters/src/claude_guardrails_guard.rs`**
   - Implement the `Guard` trait
   - Convert `GuardPayload` to the Claude Code hook JSON format (`{ "tool_name": "Bash", "tool_input": { "command": "..." } }`)
   - Spawn `claude-guardrails` binary, pipe JSON via stdin, parse stdout
   - Map the response to `GuardOutput::Direct` with appropriate verdict
   - Handle binary-not-found gracefully (log warning, return `Permit` — or `Deny` if fail-closed is configured)

2. **Add configuration**
   - Binary path (default: `~/.claude/guardrails/claude-guardrails`)
   - Safety level override (default: derive from `OperatingContext.max_risk_level`)
   - Fail-closed toggle (default: true — if binary fails, deny)
   - Timeout (default: 200ms — claude-guardrails targets sub-100ms, so 200ms is generous)

3. **Register in guard factory**
   - Update `guard_factory.rs` to support a `"claude-guardrails"` guard type
   - Wire into `GuardSystemBuilder`

4. **Tests**
   - Unit tests with mocked binary output
   - Integration test with the real binary (gated behind `#[cfg(feature = "claude-guardrails-integration-test")]`)

### Phase 2: Upstream Library PR (1 week)

**Goal:** Get claude-guardrails to expose a library API.

1. Open a PR on `leegonzales/claude-guardrails` proposing a refactor:
   - Move rule definitions and analysis engine into `src/lib.rs`
   - Expose `pub fn evaluate_tool_use(tool_name: &str, tool_input: &serde_json::Value, config: &Config) -> EvaluationResult`
   - Keep binary `main.rs` as a thin wrapper over the library
2. Collaborate with maintainer on API design

### Phase 3: Native Integration (2-3 days, after Phase 2 lands)

**Goal:** Replace subprocess with direct Rust calls.

1. **Add dependency:** `claude-guardrails = { git = "https://github.com/leegonzales/claude-guardrails", features = ["lib"] }` (or crates.io once published)
2. **Refactor `claude_guardrails_guard.rs`:**
   - Remove subprocess spawning code
   - Call library functions directly
   - Implement proper type conversions (similar to `adjudicator_guard.rs`)
3. **Feature gate:** `guard-adapters/Cargo.toml` gets `claude-guardrails = ["dep:claude-guardrails"]`
4. **Cache tree-sitter parsers** across evaluations for performance
5. **Benchmark:** Verify sub-100ms target is maintained (should be faster without IPC)

### Phase 4: Advanced Integration (future)

- **Rule customization:** Allow trust-framework config to enable/disable specific claude-guardrails rules
- **Modify verdicts:** Instead of hard deny, strip dangerous portions of commands and return `Verdict::Modify` with a sanitized payload
- **Quarantine for edge cases:** Route low-confidence detections to the quarantine system for human review
- **Ledger recording:** Write critical deny events to the trust-framework ledger for immutable audit
- **Trust-proxy integration:** Wire claude-guardrails into the `ironclaw` and `openclaw` proxy modes for inline enforcement

## 6. Configuration

### Guard System Config

Within trust-framework's `GuardSystemConfig`, the claude-guardrails guard is configured like any other guard:

```rust
/// Configuration for the claude-guardrails input guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeGuardrailsConfig {
    /// Whether the guard is enabled.
    pub enabled: bool,

    /// Path to the claude-guardrails binary (Phase 1 only).
    /// Default: "~/.claude/guardrails/claude-guardrails"
    pub binary_path: Option<String>,

    /// Safety level override. If None, derived from OperatingContext.max_risk_level.
    /// Values: "critical", "high", "strict"
    pub safety_level: Option<String>,

    /// If true, deny when the guard fails to execute (binary not found, timeout, crash).
    /// Default: true (fail-closed)
    pub fail_closed: bool,

    /// Maximum execution time before the guard times out.
    /// Default: 200ms
    pub timeout_ms: u64,

    /// Guard priority in the pipeline. Higher runs first.
    /// Default: 200
    pub priority: u32,

    /// Whether a deny from this guard short-circuits the pipeline.
    /// Default: true
    pub short_circuits: bool,

    /// Tool types to evaluate. Maps to claude-guardrails' tool matching.
    /// Default: ["Bash", "Read", "Edit", "Write"]
    pub tool_types: Vec<String>,

    /// Specific rule IDs to disable (empty = all rules active).
    pub disabled_rules: Vec<String>,
}

impl Default for ClaudeGuardrailsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            binary_path: None,
            safety_level: None,
            fail_closed: true,
            timeout_ms: 200,
            priority: 200,
            short_circuits: true,
            tool_types: vec![
                "Bash".into(),
                "Read".into(),
                "Edit".into(),
                "Write".into(),
            ],
            disabled_rules: Vec::new(),
        }
    }
}
```

### TOML Configuration (for trust-proxy / trust-server)

```toml
[guards.claude-guardrails]
enabled = true
safety_level = "high"        # "critical" | "high" | "strict"
fail_closed = true
timeout_ms = 200
priority = 200
short_circuits = true
tool_types = ["Bash", "Read", "Edit", "Write"]
disabled_rules = []

# Phase 1 only — path to binary
binary_path = "~/.claude/guardrails/claude-guardrails"
```

### Runtime Override via OperatingContext

The safety level can be dynamically adjusted per-request through `OperatingContext.metadata`:

```json
{
  "domain": "CodeGeneration",
  "trust_level": 0.3,
  "max_risk_level": "Low",
  "metadata": {
    "claude_guardrails_safety_level": "strict"
  }
}
```

When present, the metadata override takes precedence over the static config. This allows callers to tighten security for specific requests (e.g., untrusted user input) without changing the system-wide default.

---

## Summary

| What | Detail |
|------|--------|
| **Guard name** | `claude-guardrails` |
| **Type** | InputGuard |
| **Priority** | 200 (high — runs early) |
| **New crate** | `guards/crates/guard-adapters/src/claude_guardrails_guard.rs` |
| **Dependencies** | Phase 1: binary on PATH. Phase 3: `claude-guardrails` crate |
| **Effort** | Phase 1: 1-2 days. Phase 3: 2-3 days. Total: ~1 week |
| **Risk** | Low — additive guard, feature-gated, fail-closed default |
