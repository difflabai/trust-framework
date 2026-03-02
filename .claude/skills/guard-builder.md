# GuardBuilder

Build InputGuard and OutputGuard implementations for the Perth trust framework guard system.

## Trigger

USE WHEN user says "build guard", "create guard", "new guard", "guard builder", "input guard", "output guard", "regex guard", "prolog guard", or asks to create security rules for input/output filtering.

## Overview

This skill helps users create Guards that plug into the Perth guard pipeline. Guards evaluate payloads flowing through the system and return verdicts (Permit, Modify, Escalate, Quarantine, Deny). There are two placement types:

- **InputGuard**: Evaluates incoming payloads (responses from tools/LLMs) before they reach the agent
- **OutputGuard**: Evaluates outgoing payloads (requests to tools/LLMs) before they execute

And two implementation approaches:

- **Regex**: Pattern-matching against payload content using regular expressions
- **Prolog**: Logic programming rules evaluated against payload facts

## Workflow

### Step 1: Gather Requirements

Ask the user for the following. If they haven't provided it, ask for what's missing before proceeding:

1. **Guard name** (kebab-case, e.g., `pii-detector`, `sql-injection-blocker`)
2. **Guard type**: InputGuard or OutputGuard
   - InputGuard: filters responses coming back (post-execution)
   - OutputGuard: filters requests going out (pre-execution)
3. **What should it detect?** Natural language description of what the guard should catch
4. **What should happen when triggered?** Map to a Verdict:
   - `Deny` - Block the payload entirely
   - `Quarantine` - Hold for human review
   - `Escalate` - Flag for elevated review
   - `Modify` - Sanitize/redact and allow through
   - `Permit` - Allow (with optional warnings)
5. **Domain** (optional): General, Healthcare, Finance, Education, Legal, ContentModeration, CustomerService, CodeGeneration, or Custom(string)
6. **Priority** (0-1000, higher = evaluated first, default 100)
7. **Risk level**: Low, Medium, High, Critical
8. **Examples**: At least 2 examples of content that SHOULD trigger and 2 that should NOT

### Step 2: Choose Approach

Based on the requirements, recommend an approach:

**Use Regex when:**
- Detecting known patterns (PII, URLs, SQL injection, secrets, profanity)
- Matching structural patterns in text content
- Simple pattern presence/absence checks
- Performance is critical (regex is faster)

**Use Prolog when:**
- Logic involves relationships between multiple fields
- Rules have conditionals/exceptions (e.g., "allow admin users to access X but not Y")
- Decision depends on context + payload together
- Rules need composability (multiple rules interact)

Present the recommendation with reasoning and let the user confirm or override.

### Step 3: Generate the Guard

#### Regex Approach

Generate a Rust module implementing the `Guard` trait that:
1. Compiles regex patterns at construction time (in `new()`)
2. Extracts text content from the `GuardPayload` by downcasting to `JsonPayload`
3. Checks configured fields against the regex patterns
4. Returns the configured verdict on match, or `Permit` on no match

Use this template structure:

```rust
use async_trait::async_trait;
use guard_core::{
    DirectResult, Guard, GuardContext, GuardDescriptor, GuardError,
    GuardOutput, GuardPayload, JsonPayload, Verdict, WarningMetadata,
    RiskLevel, Warning, WarningLevel,
};
use regex::Regex;

pub struct {{GuardName}} {
    descriptor: GuardDescriptor,
    patterns: Vec<Regex>,
    match_fields: Vec<String>,
    verdict_on_match: Verdict,
    risk_level: RiskLevel,
}

impl {{GuardName}} {
    pub fn new() -> Result<Self, GuardError> {
        let patterns: Vec<Regex> = vec![
            {{#each patterns}}
            Regex::new(r#"{{this}}"#).map_err(|e| GuardError::Internal(format!("Invalid regex: {e}")))?,
            {{/each}}
        ];

        Ok(Self {
            descriptor: GuardDescriptor {
                name: "{{guard_name}}".into(),
                priority: {{priority}},
                short_circuits: {{short_circuits}},
                domains: {{domains}},
            },
            patterns,
            match_fields: vec![{{match_fields}}],
            verdict_on_match: Verdict::{{verdict}},
            risk_level: RiskLevel::{{risk_level}},
        })
    }

    fn extract_text(&self, payload: &dyn GuardPayload) -> Option<String> {
        let json = payload.downcast_ref::<JsonPayload>()?;
        let mut texts = Vec::new();
        for field in &self.match_fields {
            if let Some(val) = json.data.get(field) {
                match val {
                    serde_json::Value::String(s) => texts.push(s.clone()),
                    other => texts.push(other.to_string()),
                }
            }
        }
        if texts.is_empty() {
            // Fall back to full JSON serialization
            texts.push(json.data.to_string());
        }
        Some(texts.join(" "))
    }
}

#[async_trait]
impl Guard for {{GuardName}} {
    fn descriptor(&self) -> &GuardDescriptor {
        &self.descriptor
    }

    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        _ctx: &GuardContext,
    ) -> Result<GuardOutput, GuardError> {
        let text = self.extract_text(payload).unwrap_or_default();

        for pattern in &self.patterns {
            if let Some(m) = pattern.find(&text) {
                let mut warnings = WarningMetadata::new();
                warnings.risk_score = {{risk_score}};
                warnings.risk_level = self.risk_level;
                warnings.warnings.push(Warning {
                    source_guard: self.descriptor.name.clone(),
                    level: WarningLevel::{{warning_level}},
                    message: format!(
                        "Pattern '{}' matched: '{}'",
                        pattern.as_str(),
                        &text[m.start()..m.end()]
                    ),
                    code: Some("REGEX_MATCH".into()),
                });

                return Ok(GuardOutput::Direct(DirectResult {
                    verdict: self.verdict_on_match,
                    reason: format!("{{guard_name}}: pattern matched in payload"),
                    modified_payload: None, // Set to Some(...) for Modify verdict
                    warnings,
                }));
            }
        }

        Ok(GuardOutput::Direct(DirectResult {
            verdict: Verdict::Permit,
            reason: "{{guard_name}}: no patterns matched".into(),
            modified_payload: None,
            warnings: WarningMetadata::new(),
        }))
    }
}
```

For `Modify` verdicts, also generate payload modification logic that redacts/sanitizes matched content.

#### Prolog Approach

Generate a Rust module that:
1. Defines Prolog rules as a string constant
2. Translates the `GuardPayload` into Prolog facts (JSON -> assertions)
3. Runs a query against the `EvaluatorPlugin` interface
4. Maps the result to a verdict

Use this template structure:

```rust
use async_trait::async_trait;
use guard_core::{
    DirectResult, Guard, GuardContext, GuardDescriptor, GuardError,
    GuardOutput, GuardPayload, JsonPayload, Verdict, WarningMetadata,
    RiskLevel, Warning, WarningLevel,
};
use guard_plugins::EvaluatorPlugin;
use std::sync::Arc;

/// Prolog rules for this guard.
const PROLOG_RULES: &str = r#"
{{prolog_rules}}
"#;

pub struct {{GuardName}} {
    descriptor: GuardDescriptor,
    evaluator: Arc<dyn EvaluatorPlugin>,
    risk_level: RiskLevel,
}

impl {{GuardName}} {
    pub fn new(evaluator: Arc<dyn EvaluatorPlugin>) -> Self {
        Self {
            descriptor: GuardDescriptor {
                name: "{{guard_name}}".into(),
                priority: {{priority}},
                short_circuits: {{short_circuits}},
                domains: {{domains}},
            },
            evaluator,
            risk_level: RiskLevel::{{risk_level}},
        }
    }

    fn payload_to_facts(&self, payload: &dyn GuardPayload) -> serde_json::Value {
        let json = payload.downcast_ref::<JsonPayload>()
            .map(|j| j.data.clone())
            .unwrap_or(serde_json::json!({}));

        serde_json::json!({
            "rules": PROLOG_RULES,
            "payload": json,
            {{#each fact_mappings}}
            "{{this.prolog_name}}": json.get("{{this.json_field}}").cloned().unwrap_or(serde_json::Value::Null),
            {{/each}}
        })
    }
}

#[async_trait]
impl Guard for {{GuardName}} {
    fn descriptor(&self) -> &GuardDescriptor {
        &self.descriptor
    }

    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<GuardOutput, GuardError> {
        let facts = self.payload_to_facts(payload);
        let query = serde_json::json!({
            "goal": "{{prolog_query}}",
            "context": {
                "domain": format!("{:?}", ctx.operating.domain),
                "trust_level": ctx.operating.trust_level,
            }
        });

        let result = self.evaluator.evaluate(&query, &facts).await?;

        if result.succeeded {
            // Query succeeded = action is allowed
            Ok(GuardOutput::Direct(DirectResult {
                verdict: Verdict::Permit,
                reason: format!("{{guard_name}}: prolog query succeeded"),
                modified_payload: None,
                warnings: WarningMetadata::new(),
            }))
        } else {
            let mut warnings = WarningMetadata::new();
            warnings.risk_score = {{risk_score}};
            warnings.risk_level = self.risk_level;
            warnings.warnings.push(Warning {
                source_guard: self.descriptor.name.clone(),
                level: WarningLevel::{{warning_level}},
                message: format!("{{guard_name}}: prolog query denied action"),
                code: Some("PROLOG_DENY".into()),
            });

            Ok(GuardOutput::Direct(DirectResult {
                verdict: Verdict::{{verdict}},
                reason: format!(
                    "{{guard_name}}: action not permitted by rules. Bindings: {:?}",
                    result.bindings
                ),
                modified_payload: None,
                warnings,
            }))
        }
    }
}
```

### Step 4: Generate Evaluation Cases

Always generate a set of evaluation cases alongside the guard. Format them as a test module and a JSON file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::{GuardContext, JsonPayload, Verdict};

    // Cases that SHOULD trigger the guard
    {{#each trigger_cases}}
    #[tokio::test]
    async fn triggers_on_{{this.name}}() {
        let guard = {{GuardName}}::new({{constructor_args}}).unwrap();
        let payload = JsonPayload { data: serde_json::json!({{this.payload}}) };
        let ctx = GuardContext::default();
        let result = guard.evaluate(&payload, &ctx).await.unwrap();
        match result {
            GuardOutput::Direct(d) => assert_eq!(d.verdict, Verdict::{{verdict}}),
            _ => panic!("Expected Direct result"),
        }
    }
    {{/each}}

    // Cases that should NOT trigger the guard
    {{#each permit_cases}}
    #[tokio::test]
    async fn permits_{{this.name}}() {
        let guard = {{GuardName}}::new({{constructor_args}}).unwrap();
        let payload = JsonPayload { data: serde_json::json!({{this.payload}}) };
        let ctx = GuardContext::default();
        let result = guard.evaluate(&payload, &ctx).await.unwrap();
        match result {
            GuardOutput::Direct(d) => assert_eq!(d.verdict, Verdict::Permit),
            _ => panic!("Expected Direct result"),
        }
    }
    {{/each}}
}
```

Also generate a JSON eval cases file:

```json
{
  "guard_name": "{{guard_name}}",
  "guard_type": "{{guard_type}}",
  "approach": "{{approach}}",
  "cases": [
    {
      "description": "...",
      "payload": { ... },
      "expected_verdict": "Deny",
      "should_trigger": true
    },
    {
      "description": "...",
      "payload": { ... },
      "expected_verdict": "Permit",
      "should_trigger": false
    }
  ]
}
```

Generate at least:
- 3 positive cases (should trigger) covering different variations
- 3 negative cases (should not trigger) including edge cases
- 1 boundary/edge case

### Step 5: Server Endpoint

The guard builder is also available via the evaluation server at `POST /v1/guards/build`. The skill can optionally call this endpoint or generate code directly.

**Request format:**
```json
{
  "name": "pii-detector",
  "description": "Detects personally identifiable information in outputs",
  "guard_type": "output",
  "approach": "regex",
  "domain": "general",
  "priority": 200,
  "verdict_on_match": "Deny",
  "risk_level": "High",
  "short_circuits": true,
  "spec": {
    "patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b", "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"],
    "match_fields": ["content", "text", "output"],
    "case_sensitive": false
  },
  "examples": {
    "should_trigger": [
      {"content": "My SSN is 123-45-6789"},
      {"content": "Email me at user@example.com"}
    ],
    "should_not_trigger": [
      {"content": "The weather is nice today"},
      {"content": "Order number: 12345"}
    ]
  }
}
```

**Response format:**
```json
{
  "guard_name": "pii-detector",
  "guard_type": "output",
  "approach": "regex",
  "guard_code": "... generated Rust source code ...",
  "eval_cases": [
    {
      "description": "Detects SSN pattern",
      "payload": {"content": "My SSN is 123-45-6789"},
      "expected_verdict": "Deny",
      "should_trigger": true
    }
  ],
  "metadata": {
    "patterns_compiled": 2,
    "fields_checked": ["content", "text", "output"]
  }
}
```

## Important Codebase References

- Guard trait: `guards/crates/guard-core/src/guard.rs`
- GuardDescriptor, GuardOutput, DirectResult types: same file
- Verdict enum (Permit/Modify/Escalate/Quarantine/Deny): `guards/crates/guard-core/src/verdict.rs`
- InputGuards/OutputGuards: `guards/crates/guard-core/src/layer.rs`
- GuardPayload/JsonPayload: `guards/crates/guard-core/src/payload.rs`
- GuardContext/OperatingContext: `guards/crates/guard-core/src/context.rs`
- WarningMetadata/Warning: `guards/crates/guard-core/src/warning.rs`
- EvaluatorPlugin trait: `guards/crates/guard-plugins/src/plugin.rs`
- Server endpoint: `guards/crates/guard-adapters/src/server.rs`
- Builder module: `guards/crates/guard-adapters/src/builder.rs`
