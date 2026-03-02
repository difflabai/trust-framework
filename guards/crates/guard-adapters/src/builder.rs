//! Guard builder: generates Guard implementations from specifications.
//!
//! Supports two approaches:
//! - **Regex**: Pattern-matching guards using regular expressions
//! - **Prolog**: Logic-programming guards using Prolog rules
//!
//! Each approach produces:
//! 1. Rust source code implementing the `Guard` trait
//! 2. Evaluation test cases (triggers and non-triggers)

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public API types
// ---------------------------------------------------------------------------

/// Whether the guard runs on inputs or outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardType {
    Input,
    Output,
}

/// The code-generation approach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildApproach {
    Regex,
    Prolog,
}

/// A single evaluation test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalCase {
    pub description: String,
    pub payload: serde_json::Value,
    pub expected_verdict: String,
    pub should_trigger: bool,
}

/// Approach-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexSpec {
    /// Regular expression patterns to match against.
    pub patterns: Vec<String>,
    /// JSON field names to extract text from (falls back to full payload).
    #[serde(default)]
    pub match_fields: Vec<String>,
    /// Whether patterns are case-sensitive (default: false).
    #[serde(default)]
    pub case_sensitive: bool,
}

/// Prolog-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrologSpec {
    /// Prolog rules source code.
    pub rules: String,
    /// Mapping from JSON payload field to Prolog fact name.
    #[serde(default)]
    pub fact_mappings: Vec<FactMapping>,
    /// The Prolog goal to query (e.g., `"denied(Action)"`).
    pub query: String,
    /// If true, query success means deny; if false, success means permit.
    #[serde(default = "default_deny_on_success")]
    pub deny_on_success: bool,
}

fn default_deny_on_success() -> bool {
    true
}

/// Maps a JSON payload field to a Prolog fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactMapping {
    pub json_field: String,
    pub prolog_name: String,
}

/// Request to build a guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardBuildRequest {
    pub name: String,
    pub description: String,
    pub guard_type: GuardType,
    pub approach: BuildApproach,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_verdict")]
    pub verdict_on_match: String,
    #[serde(default = "default_risk_level")]
    pub risk_level: String,
    #[serde(default)]
    pub short_circuits: bool,
    /// Approach-specific configuration (RegexSpec or PrologSpec JSON).
    pub spec: serde_json::Value,
    /// Optional user-supplied examples for eval case generation.
    #[serde(default)]
    pub examples: Option<ExampleSet>,
}

fn default_priority() -> u32 {
    100
}
fn default_verdict() -> String {
    "Deny".into()
}
fn default_risk_level() -> String {
    "Medium".into()
}

/// User-supplied positive and negative examples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleSet {
    #[serde(default)]
    pub should_trigger: Vec<serde_json::Value>,
    #[serde(default)]
    pub should_not_trigger: Vec<serde_json::Value>,
}

/// The result of a guard build operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardBuildResponse {
    pub guard_name: String,
    pub guard_type: GuardType,
    pub approach: BuildApproach,
    /// Generated Rust source code for the guard.
    pub guard_code: String,
    /// Generated evaluation test cases.
    pub eval_cases: Vec<EvalCase>,
    /// Approach-specific metadata.
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Builder entry point
// ---------------------------------------------------------------------------

/// Build a guard from the given specification.
pub fn build_guard(request: &GuardBuildRequest) -> Result<GuardBuildResponse, String> {
    match request.approach {
        BuildApproach::Regex => build_regex_guard(request),
        BuildApproach::Prolog => build_prolog_guard(request),
    }
}

// ---------------------------------------------------------------------------
// Regex builder
// ---------------------------------------------------------------------------

fn build_regex_guard(req: &GuardBuildRequest) -> Result<GuardBuildResponse, String> {
    let spec: RegexSpec = serde_json::from_value(req.spec.clone())
        .map_err(|e| format!("Invalid regex spec: {e}"))?;

    if spec.patterns.is_empty() {
        return Err("At least one regex pattern is required".into());
    }

    // Validate patterns are compilable
    for (i, pat) in spec.patterns.iter().enumerate() {
        let test_pat = if spec.case_sensitive {
            pat.clone()
        } else {
            format!("(?i){pat}")
        };
        regex::Regex::new(&test_pat)
            .map_err(|e| format!("Pattern {i} ({pat:?}) is invalid: {e}"))?;
    }

    let struct_name = to_pascal_case(&req.name);
    let guard_code = generate_regex_code(req, &spec, &struct_name);
    let eval_cases = generate_regex_eval_cases(req, &spec);

    Ok(GuardBuildResponse {
        guard_name: req.name.clone(),
        guard_type: req.guard_type,
        approach: BuildApproach::Regex,
        guard_code,
        eval_cases,
        metadata: serde_json::json!({
            "patterns_compiled": spec.patterns.len(),
            "fields_checked": spec.match_fields,
            "case_sensitive": spec.case_sensitive,
        }),
    })
}

fn generate_regex_code(req: &GuardBuildRequest, spec: &RegexSpec, struct_name: &str) -> String {
    let case_prefix = if spec.case_sensitive { "" } else { "(?i)" };

    let pattern_lines: String = spec
        .patterns
        .iter()
        .map(|p| {
            format!(
                "            Regex::new(r#\"{case_prefix}{p}\"#).map_err(|e| GuardError::Internal(format!(\"Invalid regex: {{e}}\")))?,",
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let match_fields_str: String = spec
        .match_fields
        .iter()
        .map(|f| format!("\"{f}\".into()"))
        .collect::<Vec<_>>()
        .join(", ");

    let domains_expr = match &req.domain {
        Some(d) => format!("Some(vec![\"{d}\".into()])"),
        None => "None".into(),
    };

    let risk_score = match req.risk_level.as_str() {
        "Low" => "0.2",
        "Medium" => "0.5",
        "High" => "0.8",
        "Critical" => "1.0",
        _ => "0.5",
    };

    let warning_level = match req.risk_level.as_str() {
        "Low" => "Info",
        "Medium" => "Medium",
        "High" => "High",
        "Critical" => "Critical",
        _ => "Medium",
    };

    let modify_payload_section = if req.verdict_on_match == "Modify" {
        r#"
                // Redact the matched content
                let mut modified = json.clone();
                let redacted = pattern.replace_all(&text, "[REDACTED]").to_string();
                // Replace the first matching field with redacted content
                for field in &self.match_fields {
                    if let Some(val) = modified.data.get(field) {
                        if val.is_string() {
                            modified.data[field] = serde_json::Value::String(redacted.clone());
                            break;
                        }
                    }
                }
                let modified_payload: Option<Box<dyn GuardPayload>> = Some(Box::new(modified));"#
    } else {
        "                let modified_payload: Option<Box<dyn GuardPayload>> = None;"
    };

    format!(
        r##"//! Auto-generated guard: {name}
//! {description}
//!
//! Type: {guard_type:?}Guard | Approach: Regex
//! Verdict on match: {verdict} | Risk: {risk_level}

use async_trait::async_trait;
use regex::Regex;

use guard_core::{{
    DirectResult, Guard, GuardContext, GuardDescriptor, GuardError,
    GuardOutput, GuardPayload, JsonPayload, Verdict, WarningMetadata,
    RiskLevel, Warning, WarningLevel,
}};

/// {description}
pub struct {struct_name} {{
    descriptor: GuardDescriptor,
    patterns: Vec<Regex>,
    match_fields: Vec<String>,
    verdict_on_match: Verdict,
    risk_level: RiskLevel,
}}

impl {struct_name} {{
    pub fn new() -> Result<Self, GuardError> {{
        let patterns: Vec<Regex> = vec![
{pattern_lines}
        ];

        Ok(Self {{
            descriptor: GuardDescriptor {{
                name: "{name}".into(),
                priority: {priority},
                short_circuits: {short_circuits},
                domains: {domains},
            }},
            patterns,
            match_fields: vec![{match_fields}],
            verdict_on_match: Verdict::{verdict},
            risk_level: RiskLevel::{risk_level},
        }})
    }}

    fn extract_text(&self, payload: &dyn GuardPayload) -> Option<String> {{
        let json = payload.downcast_ref::<JsonPayload>()?;
        let mut texts = Vec::new();
        for field in &self.match_fields {{
            if let Some(val) = json.data.get(field) {{
                match val {{
                    serde_json::Value::String(s) => texts.push(s.clone()),
                    other => texts.push(other.to_string()),
                }}
            }}
        }}
        if texts.is_empty() {{
            texts.push(json.data.to_string());
        }}
        Some(texts.join(" "))
    }}
}}

#[async_trait]
impl Guard for {struct_name} {{
    fn descriptor(&self) -> &GuardDescriptor {{
        &self.descriptor
    }}

    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        _ctx: &GuardContext,
    ) -> Result<GuardOutput, GuardError> {{
        let text = self.extract_text(payload).unwrap_or_default();

        for pattern in &self.patterns {{
            if let Some(m) = pattern.find(&text) {{
                let mut warnings = WarningMetadata::new();
                warnings.risk_score = {risk_score};
                warnings.risk_level = self.risk_level;
                warnings.warnings.push(Warning {{
                    source_guard: self.descriptor.name.clone(),
                    level: WarningLevel::{warning_level},
                    message: format!(
                        "Pattern '{{}}' matched: '{{}}'",
                        pattern.as_str(),
                        &text[m.start()..m.end()]
                    ),
                    code: Some("REGEX_MATCH".into()),
                }});

{modify_payload}

                return Ok(GuardOutput::Direct(DirectResult {{
                    verdict: self.verdict_on_match,
                    reason: format!("{name}: pattern matched in payload"),
                    modified_payload,
                    warnings,
                }}));
            }}
        }}

        Ok(GuardOutput::Direct(DirectResult {{
            verdict: Verdict::Permit,
            reason: "{name}: no patterns matched".into(),
            modified_payload: None,
            warnings: WarningMetadata::new(),
        }}))
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;
    use guard_core::{{GuardContext, JsonPayload, Verdict}};

{test_code}
}}
"##,
        name = req.name,
        description = req.description,
        guard_type = req.guard_type,
        struct_name = struct_name,
        pattern_lines = pattern_lines,
        priority = req.priority,
        short_circuits = req.short_circuits,
        domains = domains_expr,
        match_fields = match_fields_str,
        verdict = req.verdict_on_match,
        risk_level = req.risk_level,
        risk_score = risk_score,
        warning_level = warning_level,
        modify_payload = modify_payload_section,
        test_code = generate_regex_test_code(req, spec, struct_name),
    )
}

fn generate_regex_test_code(req: &GuardBuildRequest, spec: &RegexSpec, struct_name: &str) -> String {
    let mut tests = String::new();
    let examples = req.examples.as_ref();

    // Generate trigger tests from user examples
    if let Some(ex) = examples {
        for (i, payload) in ex.should_trigger.iter().enumerate() {
            tests.push_str(&format!(
                r#"    #[tokio::test]
    async fn triggers_on_example_{i}() {{
        let guard = {struct_name}::new().unwrap();
        let payload = JsonPayload {{ data: serde_json::json!({payload}) }};
        let ctx = GuardContext::default();
        let result = guard.evaluate(&payload, &ctx).await.unwrap();
        match result {{
            GuardOutput::Direct(d) => assert_eq!(d.verdict, Verdict::{verdict}),
            _ => panic!("Expected Direct result"),
        }}
    }}

"#,
                i = i,
                struct_name = struct_name,
                payload = payload,
                verdict = req.verdict_on_match,
            ));
        }

        for (i, payload) in ex.should_not_trigger.iter().enumerate() {
            tests.push_str(&format!(
                r#"    #[tokio::test]
    async fn permits_example_{i}() {{
        let guard = {struct_name}::new().unwrap();
        let payload = JsonPayload {{ data: serde_json::json!({payload}) }};
        let ctx = GuardContext::default();
        let result = guard.evaluate(&payload, &ctx).await.unwrap();
        match result {{
            GuardOutput::Direct(d) => assert_eq!(d.verdict, Verdict::Permit),
            _ => panic!("Expected Direct result"),
        }}
    }}

"#,
                i = i,
                struct_name = struct_name,
                payload = payload,
            ));
        }
    }

    // Always generate a construction test
    tests.push_str(&format!(
        r#"    #[test]
    fn guard_constructs_successfully() {{
        let guard = {struct_name}::new();
        assert!(guard.is_ok());
    }}

    #[test]
    fn guard_descriptor_is_correct() {{
        let guard = {struct_name}::new().unwrap();
        let desc = guard.descriptor();
        assert_eq!(desc.name, "{name}");
        assert_eq!(desc.priority, {priority});
    }}

    #[tokio::test]
    async fn permits_empty_payload() {{
        let guard = {struct_name}::new().unwrap();
        let payload = JsonPayload {{ data: serde_json::json!({{}}) }};
        let ctx = GuardContext::default();
        let result = guard.evaluate(&payload, &ctx).await.unwrap();
        match result {{
            GuardOutput::Direct(d) => assert_eq!(d.verdict, Verdict::Permit),
            _ => panic!("Expected Direct result"),
        }}
    }}
"#,
        struct_name = struct_name,
        name = req.name,
        priority = req.priority,
    ));

    // Generate a pattern-specific trigger test if no examples given
    if examples.is_none() || examples.unwrap().should_trigger.is_empty() {
        if let Some(first_pattern) = spec.patterns.first() {
            let sample = generate_sample_match(first_pattern);
            let field = spec.match_fields.first().map(|s| s.as_str()).unwrap_or("content");
            tests.push_str(&format!(
                r#"
    #[tokio::test]
    async fn triggers_on_pattern_match() {{
        let guard = {struct_name}::new().unwrap();
        let payload = JsonPayload {{ data: serde_json::json!({{"{field}": "{sample}"}}) }};
        let ctx = GuardContext::default();
        let result = guard.evaluate(&payload, &ctx).await.unwrap();
        match result {{
            GuardOutput::Direct(d) => assert_ne!(d.verdict, Verdict::Permit),
            _ => panic!("Expected Direct result"),
        }}
    }}
"#,
                struct_name = struct_name,
                field = field,
                sample = sample,
            ));
        }
    }

    tests
}

fn generate_regex_eval_cases(req: &GuardBuildRequest, spec: &RegexSpec) -> Vec<EvalCase> {
    let mut cases = Vec::new();
    let field = spec
        .match_fields
        .first()
        .map(|s| s.as_str())
        .unwrap_or("content");

    // From user examples
    if let Some(ref examples) = req.examples {
        for (i, payload) in examples.should_trigger.iter().enumerate() {
            cases.push(EvalCase {
                description: format!("User example trigger #{}", i + 1),
                payload: payload.clone(),
                expected_verdict: req.verdict_on_match.clone(),
                should_trigger: true,
            });
        }
        for (i, payload) in examples.should_not_trigger.iter().enumerate() {
            cases.push(EvalCase {
                description: format!("User example permit #{}", i + 1),
                payload: payload.clone(),
                expected_verdict: "Permit".into(),
                should_trigger: false,
            });
        }
    }

    // Generate pattern-based cases
    for (i, pattern) in spec.patterns.iter().enumerate() {
        let sample = generate_sample_match(pattern);
        cases.push(EvalCase {
            description: format!("Pattern {} match: {}", i, pattern),
            payload: serde_json::json!({ field: sample }),
            expected_verdict: req.verdict_on_match.clone(),
            should_trigger: true,
        });
    }

    // Negative cases
    cases.push(EvalCase {
        description: "Empty payload".into(),
        payload: serde_json::json!({}),
        expected_verdict: "Permit".into(),
        should_trigger: false,
    });

    cases.push(EvalCase {
        description: "Benign content".into(),
        payload: serde_json::json!({ field: "Hello, world! This is perfectly normal content." }),
        expected_verdict: "Permit".into(),
        should_trigger: false,
    });

    cases.push(EvalCase {
        description: "Numeric-only content".into(),
        payload: serde_json::json!({ field: "42" }),
        expected_verdict: "Permit".into(),
        should_trigger: false,
    });

    cases
}

/// Generate a sample string that would match a regex pattern.
/// This is a best-effort heuristic for common pattern shapes.
fn generate_sample_match(pattern: &str) -> String {
    // Strip common regex prefixes/suffixes
    let p = pattern
        .trim_start_matches("(?i)")
        .trim_start_matches('^')
        .trim_end_matches('$');

    // Common pattern recognition
    if p.contains("\\d{3}-\\d{2}-\\d{4}") {
        return "contains SSN 123-45-6789 here".into();
    }
    if p.contains("@") && p.contains("\\.") {
        return "email is user@example.com here".into();
    }
    if p.to_lowercase().contains("select") && p.to_lowercase().contains("from") {
        return "SELECT * FROM users WHERE id=1".into();
    }
    if p.contains("<script") || p.contains("<img") {
        return "<script>alert('xss')</script>".into();
    }
    if p.contains("bearer") || p.contains("token") {
        return "Authorization: Bearer sk-abc123def456".into();
    }
    if p.contains("password") || p.contains("passwd") {
        return "my password is hunter2".into();
    }

    // Fallback: use the pattern itself as a literal (works for simple patterns)
    let literal: String = p
        .replace("\\b", "")
        .replace("\\d", "0")
        .replace("\\w", "a")
        .replace("\\s", " ")
        .replace("[A-Za-z]", "a")
        .replace("[0-9]", "0")
        .replace(".*", "test")
        .replace(".+", "test")
        .replace('+', "")
        .replace('*', "")
        .replace('?', "");

    if literal.is_empty() {
        "sample-match-text".into()
    } else {
        format!("text containing {literal} here")
    }
}

// ---------------------------------------------------------------------------
// Prolog builder
// ---------------------------------------------------------------------------

fn build_prolog_guard(req: &GuardBuildRequest) -> Result<GuardBuildResponse, String> {
    let spec: PrologSpec = serde_json::from_value(req.spec.clone())
        .map_err(|e| format!("Invalid prolog spec: {e}"))?;

    if spec.rules.trim().is_empty() {
        return Err("Prolog rules cannot be empty".into());
    }
    if spec.query.trim().is_empty() {
        return Err("Prolog query cannot be empty".into());
    }

    let struct_name = to_pascal_case(&req.name);
    let guard_code = generate_prolog_code(req, &spec, &struct_name);
    let eval_cases = generate_prolog_eval_cases(req, &spec);

    Ok(GuardBuildResponse {
        guard_name: req.name.clone(),
        guard_type: req.guard_type,
        approach: BuildApproach::Prolog,
        guard_code,
        eval_cases,
        metadata: serde_json::json!({
            "rules_length": spec.rules.len(),
            "query": spec.query,
            "fact_mappings": spec.fact_mappings.len(),
            "deny_on_success": spec.deny_on_success,
        }),
    })
}

fn generate_prolog_code(req: &GuardBuildRequest, spec: &PrologSpec, struct_name: &str) -> String {
    let domains_expr = match &req.domain {
        Some(d) => format!("Some(vec![\"{d}\".into()])"),
        None => "None".into(),
    };

    let risk_score = match req.risk_level.as_str() {
        "Low" => "0.2",
        "Medium" => "0.5",
        "High" => "0.8",
        "Critical" => "1.0",
        _ => "0.5",
    };

    let warning_level = match req.risk_level.as_str() {
        "Low" => "Info",
        "Medium" => "Medium",
        "High" => "High",
        "Critical" => "Critical",
        _ => "Medium",
    };

    // Build the fact extraction code
    let fact_extraction: String = spec
        .fact_mappings
        .iter()
        .map(|fm| {
            format!(
                "        if let Some(v) = json.get(\"{json_field}\") {{\n            facts[\"{prolog_name}\"] = v.clone();\n        }}",
                json_field = fm.json_field,
                prolog_name = fm.prolog_name,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    // For deny_on_success, the logic inverts: query success = deny
    let (success_verdict, failure_verdict, success_reason, failure_reason) = if spec.deny_on_success
    {
        (
            format!("Verdict::{}", req.verdict_on_match),
            "Verdict::Permit".to_string(),
            format!("{}: prolog rule matched — action denied", req.name),
            format!("{}: prolog rule did not match — action permitted", req.name),
        )
    } else {
        (
            "Verdict::Permit".to_string(),
            format!("Verdict::{}", req.verdict_on_match),
            format!("{}: prolog query succeeded — action permitted", req.name),
            format!(
                "{}: prolog query failed — action not permitted",
                req.name
            ),
        )
    };

    format!(
        r##"//! Auto-generated guard: {name}
//! {description}
//!
//! Type: {guard_type:?}Guard | Approach: Prolog
//! Verdict on match: {verdict} | Risk: {risk_level}
//! Query: {query}

use async_trait::async_trait;
use std::sync::Arc;

use guard_core::{{
    DirectResult, Guard, GuardContext, GuardDescriptor, GuardError,
    GuardOutput, GuardPayload, JsonPayload, Verdict, WarningMetadata,
    RiskLevel, Warning, WarningLevel,
}};
use guard_plugins::EvaluatorPlugin;

/// Prolog rules for this guard.
const PROLOG_RULES: &str = r#"
{rules}
"#;

/// {description}
pub struct {struct_name} {{
    descriptor: GuardDescriptor,
    evaluator: Arc<dyn EvaluatorPlugin>,
    risk_level: RiskLevel,
}}

impl {struct_name} {{
    pub fn new(evaluator: Arc<dyn EvaluatorPlugin>) -> Self {{
        Self {{
            descriptor: GuardDescriptor {{
                name: "{name}".into(),
                priority: {priority},
                short_circuits: {short_circuits},
                domains: {domains},
            }},
            evaluator,
            risk_level: RiskLevel::{risk_level},
        }}
    }}

    fn payload_to_facts(&self, payload: &dyn GuardPayload) -> serde_json::Value {{
        let json = payload
            .downcast_ref::<JsonPayload>()
            .map(|j| j.data.clone())
            .unwrap_or(serde_json::json!({{}}));

        let mut facts = serde_json::json!({{
            "rules": PROLOG_RULES,
            "payload": json.clone(),
        }});

{fact_extraction}

        facts
    }}
}}

#[async_trait]
impl Guard for {struct_name} {{
    fn descriptor(&self) -> &GuardDescriptor {{
        &self.descriptor
    }}

    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<GuardOutput, GuardError> {{
        let facts = self.payload_to_facts(payload);
        let query = serde_json::json!({{
            "goal": "{query}",
            "context": {{
                "domain": format!("{{:?}}", ctx.operating.domain),
                "trust_level": ctx.operating.trust_level,
            }}
        }});

        let result = self.evaluator.evaluate(&query, &facts).await?;

        if result.succeeded {{
            let mut warnings = WarningMetadata::new();
            if "{success_verdict}" != "Verdict::Permit" {{
                warnings.risk_score = {risk_score};
                warnings.risk_level = self.risk_level;
                warnings.warnings.push(Warning {{
                    source_guard: self.descriptor.name.clone(),
                    level: WarningLevel::{warning_level},
                    message: "{success_reason}".into(),
                    code: Some("PROLOG_EVAL".into()),
                }});
            }}

            Ok(GuardOutput::Direct(DirectResult {{
                verdict: {success_verdict},
                reason: format!(
                    "{success_reason}. Bindings: {{:?}}",
                    result.bindings
                ),
                modified_payload: None,
                warnings,
            }}))
        }} else {{
            let mut warnings = WarningMetadata::new();
            if "{failure_verdict}" != "Verdict::Permit" {{
                warnings.risk_score = {risk_score};
                warnings.risk_level = self.risk_level;
                warnings.warnings.push(Warning {{
                    source_guard: self.descriptor.name.clone(),
                    level: WarningLevel::{warning_level},
                    message: "{failure_reason}".into(),
                    code: Some("PROLOG_EVAL".into()),
                }});
            }}

            Ok(GuardOutput::Direct(DirectResult {{
                verdict: {failure_verdict},
                reason: "{failure_reason}".into(),
                modified_payload: None,
                warnings,
            }}))
        }}
    }}
}}
"##,
        name = req.name,
        description = req.description,
        guard_type = req.guard_type,
        struct_name = struct_name,
        rules = spec.rules,
        query = spec.query,
        priority = req.priority,
        short_circuits = req.short_circuits,
        domains = domains_expr,
        verdict = req.verdict_on_match,
        risk_level = req.risk_level,
        risk_score = risk_score,
        warning_level = warning_level,
        fact_extraction = fact_extraction,
        success_verdict = success_verdict,
        failure_verdict = failure_verdict,
        success_reason = success_reason,
        failure_reason = failure_reason,
    )
}

fn generate_prolog_eval_cases(req: &GuardBuildRequest, spec: &PrologSpec) -> Vec<EvalCase> {
    let mut cases = Vec::new();

    // From user examples
    if let Some(ref examples) = req.examples {
        for (i, payload) in examples.should_trigger.iter().enumerate() {
            cases.push(EvalCase {
                description: format!("User example trigger #{}", i + 1),
                payload: payload.clone(),
                expected_verdict: req.verdict_on_match.clone(),
                should_trigger: true,
            });
        }
        for (i, payload) in examples.should_not_trigger.iter().enumerate() {
            cases.push(EvalCase {
                description: format!("User example permit #{}", i + 1),
                payload: payload.clone(),
                expected_verdict: "Permit".into(),
                should_trigger: false,
            });
        }
    }

    // Generate fact-mapping based cases
    for fm in &spec.fact_mappings {
        cases.push(EvalCase {
            description: format!(
                "Payload with {} field mapped to {}",
                fm.json_field, fm.prolog_name
            ),
            payload: serde_json::json!({ &fm.json_field: "test_value" }),
            expected_verdict: req.verdict_on_match.clone(),
            should_trigger: true,
        });
    }

    // Empty payload case
    cases.push(EvalCase {
        description: "Empty payload — no facts to assert".into(),
        payload: serde_json::json!({}),
        expected_verdict: if spec.deny_on_success {
            "Permit".into()
        } else {
            req.verdict_on_match.clone()
        },
        should_trigger: !spec.deny_on_success,
    });

    // Benign payload
    cases.push(EvalCase {
        description: "Benign payload with unrelated fields".into(),
        payload: serde_json::json!({"unrelated_field": "safe_value"}),
        expected_verdict: "Permit".into(),
        should_trigger: false,
    });

    cases
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert kebab-case or snake_case to PascalCase.
fn to_pascal_case(s: &str) -> String {
    s.split(|c: char| c == '-' || c == '_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    let upper: String = first.to_uppercase().collect();
                    upper + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_pascal_case_converts_kebab() {
        assert_eq!(to_pascal_case("pii-detector"), "PiiDetector");
        assert_eq!(to_pascal_case("sql-injection-blocker"), "SqlInjectionBlocker");
    }

    #[test]
    fn to_pascal_case_converts_snake() {
        assert_eq!(to_pascal_case("pii_detector"), "PiiDetector");
    }

    #[test]
    fn to_pascal_case_single_word() {
        assert_eq!(to_pascal_case("guard"), "Guard");
    }

    #[test]
    fn build_regex_guard_succeeds() {
        let req = GuardBuildRequest {
            name: "pii-detector".into(),
            description: "Detects PII in output".into(),
            guard_type: GuardType::Output,
            approach: BuildApproach::Regex,
            domain: None,
            priority: 200,
            verdict_on_match: "Deny".into(),
            risk_level: "High".into(),
            short_circuits: true,
            spec: serde_json::json!({
                "patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b"],
                "match_fields": ["content"],
                "case_sensitive": false
            }),
            examples: Some(ExampleSet {
                should_trigger: vec![serde_json::json!({"content": "SSN: 123-45-6789"})],
                should_not_trigger: vec![serde_json::json!({"content": "Hello world"})],
            }),
        };

        let result = build_guard(&req).unwrap();
        assert_eq!(result.guard_name, "pii-detector");
        assert_eq!(result.approach, BuildApproach::Regex);
        assert!(result.guard_code.contains("PiiDetector"));
        assert!(result.guard_code.contains("Regex::new"));
        assert!(!result.eval_cases.is_empty());
    }

    #[test]
    fn build_regex_guard_rejects_empty_patterns() {
        let req = GuardBuildRequest {
            name: "empty".into(),
            description: "test".into(),
            guard_type: GuardType::Input,
            approach: BuildApproach::Regex,
            domain: None,
            priority: 100,
            verdict_on_match: "Deny".into(),
            risk_level: "Low".into(),
            short_circuits: false,
            spec: serde_json::json!({
                "patterns": [],
                "match_fields": [],
                "case_sensitive": false
            }),
            examples: None,
        };

        let result = build_guard(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("At least one regex pattern"));
    }

    #[test]
    fn build_regex_guard_rejects_invalid_regex() {
        let req = GuardBuildRequest {
            name: "bad-regex".into(),
            description: "test".into(),
            guard_type: GuardType::Input,
            approach: BuildApproach::Regex,
            domain: None,
            priority: 100,
            verdict_on_match: "Deny".into(),
            risk_level: "Low".into(),
            short_circuits: false,
            spec: serde_json::json!({
                "patterns": ["[invalid("],
                "match_fields": [],
                "case_sensitive": false
            }),
            examples: None,
        };

        let result = build_guard(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid"));
    }

    #[test]
    fn build_prolog_guard_succeeds() {
        let req = GuardBuildRequest {
            name: "rbac-guard".into(),
            description: "Role-based access control".into(),
            guard_type: GuardType::Output,
            approach: BuildApproach::Prolog,
            domain: Some("general".into()),
            priority: 300,
            verdict_on_match: "Deny".into(),
            risk_level: "High".into(),
            short_circuits: true,
            spec: serde_json::json!({
                "rules": "allowed(read) :- role(admin).\nallowed(read) :- role(viewer).\ndenied(Action) :- \\+ allowed(Action).",
                "fact_mappings": [
                    {"json_field": "role", "prolog_name": "role"},
                    {"json_field": "action", "prolog_name": "action"}
                ],
                "query": "denied(Action)",
                "deny_on_success": true
            }),
            examples: Some(ExampleSet {
                should_trigger: vec![serde_json::json!({"role": "guest", "action": "delete"})],
                should_not_trigger: vec![serde_json::json!({"role": "admin", "action": "read"})],
            }),
        };

        let result = build_guard(&req).unwrap();
        assert_eq!(result.guard_name, "rbac-guard");
        assert_eq!(result.approach, BuildApproach::Prolog);
        assert!(result.guard_code.contains("RbacGuard"));
        assert!(result.guard_code.contains("PROLOG_RULES"));
        assert!(result.guard_code.contains("EvaluatorPlugin"));
        assert!(!result.eval_cases.is_empty());
    }

    #[test]
    fn build_prolog_guard_rejects_empty_rules() {
        let req = GuardBuildRequest {
            name: "empty-rules".into(),
            description: "test".into(),
            guard_type: GuardType::Input,
            approach: BuildApproach::Prolog,
            domain: None,
            priority: 100,
            verdict_on_match: "Deny".into(),
            risk_level: "Low".into(),
            short_circuits: false,
            spec: serde_json::json!({
                "rules": "   ",
                "query": "test(X)",
                "fact_mappings": []
            }),
            examples: None,
        };

        let result = build_guard(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn eval_cases_include_user_examples() {
        let req = GuardBuildRequest {
            name: "test-guard".into(),
            description: "test".into(),
            guard_type: GuardType::Input,
            approach: BuildApproach::Regex,
            domain: None,
            priority: 100,
            verdict_on_match: "Deny".into(),
            risk_level: "Low".into(),
            short_circuits: false,
            spec: serde_json::json!({
                "patterns": ["bad-word"],
                "match_fields": ["text"],
                "case_sensitive": false
            }),
            examples: Some(ExampleSet {
                should_trigger: vec![
                    serde_json::json!({"text": "this has bad-word"}),
                    serde_json::json!({"text": "bad-word at start"}),
                ],
                should_not_trigger: vec![serde_json::json!({"text": "clean text"})],
            }),
        };

        let result = build_guard(&req).unwrap();
        let trigger_count = result.eval_cases.iter().filter(|c| c.should_trigger).count();
        let permit_count = result.eval_cases.iter().filter(|c| !c.should_trigger).count();

        assert!(trigger_count >= 3); // 2 user + 1 pattern-generated
        assert!(permit_count >= 3); // 1 user + 2 auto-generated (empty + benign)
    }

    #[test]
    fn generate_sample_match_ssn() {
        let sample = generate_sample_match("\\b\\d{3}-\\d{2}-\\d{4}\\b");
        assert!(sample.contains("123-45-6789"));
    }

    #[test]
    fn generate_sample_match_email() {
        let sample = generate_sample_match("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}");
        assert!(sample.contains("@"));
    }

    #[test]
    fn guard_build_response_serializes() {
        let resp = GuardBuildResponse {
            guard_name: "test".into(),
            guard_type: GuardType::Output,
            approach: BuildApproach::Regex,
            guard_code: "fn main() {}".into(),
            eval_cases: vec![EvalCase {
                description: "test case".into(),
                payload: serde_json::json!({"x": 1}),
                expected_verdict: "Deny".into(),
                should_trigger: true,
            }],
            metadata: serde_json::json!({"patterns": 1}),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let back: GuardBuildResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.guard_name, "test");
        assert_eq!(back.eval_cases.len(), 1);
    }

    #[test]
    fn regex_guard_with_modify_verdict_generates_redaction() {
        let req = GuardBuildRequest {
            name: "redactor".into(),
            description: "Redacts sensitive data".into(),
            guard_type: GuardType::Output,
            approach: BuildApproach::Regex,
            domain: None,
            priority: 100,
            verdict_on_match: "Modify".into(),
            risk_level: "Medium".into(),
            short_circuits: false,
            spec: serde_json::json!({
                "patterns": ["secret-\\w+"],
                "match_fields": ["content"],
                "case_sensitive": false
            }),
            examples: None,
        };

        let result = build_guard(&req).unwrap();
        assert!(result.guard_code.contains("REDACTED"));
        assert!(result.guard_code.contains("Verdict::Modify"));
    }

    #[test]
    fn regex_guard_with_domain_generates_domain_filter() {
        let req = GuardBuildRequest {
            name: "healthcare-pii".into(),
            description: "Healthcare PII filter".into(),
            guard_type: GuardType::Output,
            approach: BuildApproach::Regex,
            domain: Some("healthcare".into()),
            priority: 250,
            verdict_on_match: "Deny".into(),
            risk_level: "Critical".into(),
            short_circuits: true,
            spec: serde_json::json!({
                "patterns": ["\\b\\d{3}-\\d{2}-\\d{4}\\b"],
                "match_fields": ["content"],
                "case_sensitive": false
            }),
            examples: None,
        };

        let result = build_guard(&req).unwrap();
        assert!(result.guard_code.contains("\"healthcare\""));
        assert!(result.guard_code.contains("RiskLevel::Critical"));
    }
}
