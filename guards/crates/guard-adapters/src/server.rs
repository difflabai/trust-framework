//! Standalone HTTP evaluation server adapter.
//!
//! Exposes the guard system as an HTTP/JSON service that multiple
//! agent instances can call for remote evaluation. Uses the same
//! API surface as the EvalTransport trait from guard-eval-client.
//!
//! Also provides adjudication endpoints for behavior-level policy
//! evaluation via the adjudicator crate.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use adjudicator::BehaviorAdjudicator;
use guard_core::{
    GuardContext, GuardError, GuardLayer, InputGuards, JsonPayload, OperatingContext, OutputGuards,
    PipelineResult, QuarantineManager, RequestMeta,
};
use ledger::MultiLedger;

use crate::adjudicator_guard::{adj_context_from_guard, guard_risk_from_adj, guard_verdict_from_adj};
use crate::builder::{self, GuardBuildRequest, GuardBuildResponse};

/// Request body for evaluation endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRequest {
    pub request_id: String,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// Response body for evaluation endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResponse {
    pub request_id: String,
    pub verdict: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_payload: Option<serde_json::Value>,
    pub warnings: Vec<serde_json::Value>,
    pub evaluations: Vec<serde_json::Value>,
}

impl EvalResponse {
    pub fn from_pipeline_result(request_id: String, result: &PipelineResult) -> Self {
        let warnings: Vec<serde_json::Value> = result
            .warnings
            .warnings
            .iter()
            .filter_map(|w| serde_json::to_value(w).ok())
            .collect();

        let evaluations: Vec<serde_json::Value> = result
            .evaluations
            .iter()
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();

        let modified_payload = result
            .payload
            .as_ref()
            .and_then(|p| p.to_json_value());

        Self {
            request_id,
            verdict: format!("{:?}", result.verdict),
            reason: result.reason.clone(),
            modified_payload,
            warnings,
            evaluations,
        }
    }
}

/// Quarantine resolution request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineResolveRequest {
    pub approved: bool,
    pub reviewer: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Adjudicator request/response types
// ---------------------------------------------------------------------------

/// Request body for adjudication endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjudicateRequest {
    pub request_id: String,
    /// The content to adjudicate (text or JSON payload).
    pub content: String,
    /// Optional raw input for input-output coherence checking.
    #[serde(default)]
    pub raw_input: Option<String>,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

/// Response body for adjudication endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjudicateResponse {
    pub request_id: String,
    pub adjudication_id: String,
    pub verdict: String,
    pub reason: String,
    pub risk_level: String,
    pub policy_evaluations: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_output: Option<String>,
}

impl AdjudicateResponse {
    fn from_adjudication(
        request_id: String,
        result: &adjudicator::AdjudicationResult,
    ) -> Self {
        let policy_evaluations: Vec<serde_json::Value> = result
            .policy_evaluations
            .iter()
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();

        Self {
            request_id,
            adjudication_id: result.adjudication_id.clone(),
            verdict: format!("{:?}", guard_verdict_from_adj(result.verdict)),
            reason: result.reason.clone(),
            risk_level: format!("{:?}", guard_risk_from_adj(result.risk_level)),
            policy_evaluations,
            modified_output: result.modified_output.clone(),
        }
    }
}

/// The server-side handler that processes evaluation requests.
///
/// This is the core logic; actual HTTP server integration (e.g. with
/// axum, actix-web) is left to the application layer.
pub struct EvalServerHandler {
    input_guards: Arc<InputGuards>,
    output_guards: Arc<OutputGuards>,
    quarantine_manager: Option<Arc<QuarantineManager>>,
    adjudicator: Option<Arc<BehaviorAdjudicator>>,
    ledger: Option<Arc<MultiLedger>>,
}

impl EvalServerHandler {
    pub fn new(
        input_guards: Arc<InputGuards>,
        output_guards: Arc<OutputGuards>,
        quarantine_manager: Option<Arc<QuarantineManager>>,
    ) -> Self {
        Self {
            input_guards,
            output_guards,
            quarantine_manager,
            adjudicator: None,
            ledger: None,
        }
    }

    /// Create a handler with an attached behavior adjudicator.
    pub fn with_adjudicator(
        input_guards: Arc<InputGuards>,
        output_guards: Arc<OutputGuards>,
        quarantine_manager: Option<Arc<QuarantineManager>>,
        adjudicator: Arc<BehaviorAdjudicator>,
    ) -> Self {
        Self {
            input_guards,
            output_guards,
            quarantine_manager,
            adjudicator: Some(adjudicator),
            ledger: None,
        }
    }

    /// Attach a multi-ledger writer to this handler.
    ///
    /// When set, adjudication results are automatically written to all
    /// configured ledger backends after each verdict.
    pub fn with_ledger(mut self, ledger: Arc<MultiLedger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// POST /v1/evaluate/input
    pub async fn evaluate_input(&self, request: EvalRequest) -> Result<EvalResponse, GuardError> {
        let payload = JsonPayload {
            data: request.payload,
        };

        let operating = request
            .context
            .and_then(|c| serde_json::from_value::<OperatingContext>(c).ok())
            .unwrap_or_default();

        let ctx = GuardContext::new(operating).with_request_meta(RequestMeta {
            request_id: request.request_id.clone(),
            source_adapter: "server".into(),
            ..RequestMeta::default()
        });

        let result = self.input_guards.evaluate(&payload, &ctx).await?;
        Ok(EvalResponse::from_pipeline_result(
            request.request_id,
            &result,
        ))
    }

    /// POST /v1/evaluate/output
    pub async fn evaluate_output(&self, request: EvalRequest) -> Result<EvalResponse, GuardError> {
        let payload = JsonPayload {
            data: request.payload,
        };

        let operating = request
            .context
            .and_then(|c| serde_json::from_value::<OperatingContext>(c).ok())
            .unwrap_or_default();

        let ctx = GuardContext::new(operating).with_request_meta(RequestMeta {
            request_id: request.request_id.clone(),
            source_adapter: "server".into(),
            ..RequestMeta::default()
        });

        let result = self.output_guards.evaluate(&payload, &ctx).await?;
        Ok(EvalResponse::from_pipeline_result(
            request.request_id,
            &result,
        ))
    }

    /// POST /v1/adjudicate
    ///
    /// Runs the behavior adjudicator's full policy pipeline on the content.
    /// If `raw_input` is provided, input-output coherence is also evaluated.
    /// When a ledger is configured, the verdict is written to all backends.
    pub async fn adjudicate(
        &self,
        request: AdjudicateRequest,
    ) -> Result<AdjudicateResponse, GuardError> {
        let adj = self.adjudicator.as_ref().ok_or_else(|| {
            GuardError::Internal("Adjudicator not enabled".into())
        })?;

        let proposed = adjudicator::ProposedOutput::new(&request.content);

        let operating = request
            .context
            .and_then(|c| serde_json::from_value::<OperatingContext>(c).ok())
            .unwrap_or_default();
        let adj_ctx = adj_context_from_guard(&operating);

        let result = if let Some(ref raw_input) = request.raw_input {
            adj.adjudicate(raw_input, &proposed, Some(&adj_ctx))
        } else {
            adj.adjudicate_output_only(&proposed, Some(&adj_ctx))
        };

        // Write verdict to ledger if configured.
        if let Some(ref ledger) = self.ledger {
            match ledger.record_verdict(&result).await {
                Ok(receipts) => {
                    tracing::info!(
                        adjudication_id = %result.adjudication_id,
                        ledger_count = receipts.len(),
                        "Verdict written to ledger(s)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        adjudication_id = %result.adjudication_id,
                        error = %e,
                        "Failed to write verdict to ledger"
                    );
                }
            }
        }

        Ok(AdjudicateResponse::from_adjudication(
            request.request_id,
            &result,
        ))
    }

    /// GET /v1/quarantine/:id
    pub async fn get_quarantine(
        &self,
        ticket_id: &str,
    ) -> Result<serde_json::Value, GuardError> {
        let manager = self.quarantine_manager.as_ref().ok_or_else(|| {
            GuardError::Internal("Quarantine not enabled".into())
        })?;

        let ticket = manager.get_ticket(ticket_id).await.ok_or_else(|| {
            GuardError::QuarantineNotFound(ticket_id.to_string())
        })?;
        serde_json::to_value(&ticket).map_err(GuardError::from)
    }

    /// POST /v1/guards/build
    ///
    /// Generates guard source code and evaluation cases from a specification.
    pub fn build_guard(&self, request: GuardBuildRequest) -> Result<GuardBuildResponse, GuardError> {
        builder::build_guard(&request)
            .map_err(|e| GuardError::Internal(format!("Guard build failed: {e}")))
    }

    /// POST /v1/quarantine/:id
    pub async fn resolve_quarantine(
        &self,
        ticket_id: &str,
        request: QuarantineResolveRequest,
    ) -> Result<serde_json::Value, GuardError> {
        let manager = self.quarantine_manager.as_ref().ok_or_else(|| {
            GuardError::Internal("Quarantine not enabled".into())
        })?;

        let state = manager
            .resolve(ticket_id, request.approved, request.reviewer, request.reason)
            .await?;
        serde_json::to_value(&state).map_err(GuardError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::{GuardPipeline, NoopLogger, PipelineConfig, Verdict, WarningMetadata};

    fn make_handler() -> EvalServerHandler {
        let input = Arc::new(InputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let output = Arc::new(OutputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        EvalServerHandler::new(input, output, None)
    }

    fn make_handler_with_adjudicator() -> EvalServerHandler {
        let input = Arc::new(InputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let output = Arc::new(OutputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let adj = Arc::new(BehaviorAdjudicator::default());
        EvalServerHandler::with_adjudicator(input, output, None, adj)
    }

    #[test]
    fn eval_request_deserialize() {
        let json = r#"{"request_id":"r1","payload":{"tool":"bash"}}"#;
        let req: EvalRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.request_id, "r1");
        assert_eq!(req.payload["tool"], "bash");
    }

    #[test]
    fn eval_response_serialize() {
        let resp = EvalResponse {
            request_id: "r1".into(),
            verdict: "Permit".into(),
            reason: "ok".into(),
            modified_payload: None,
            warnings: vec![],
            evaluations: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("Permit"));
        assert!(!json.contains("modified_payload"));
    }

    #[test]
    fn eval_response_from_pipeline_result() {
        let result = PipelineResult {
            verdict: Verdict::Escalate,
            payload: None,
            warnings: WarningMetadata::default(),
            quarantine_tickets: vec![],
            evaluations: vec![],
            reason: "needs review".into(),
        };
        let resp = EvalResponse::from_pipeline_result("r1".into(), &result);
        assert_eq!(resp.verdict, "Escalate");
        assert_eq!(resp.request_id, "r1");
    }

    #[tokio::test]
    async fn evaluate_input_empty_pipeline() {
        let handler = make_handler();
        let request = EvalRequest {
            request_id: "test-1".into(),
            payload: serde_json::json!({"content": "hello"}),
            context: None,
            metadata: Default::default(),
        };
        let response = handler.evaluate_input(request).await.unwrap();
        assert_eq!(response.verdict, "Permit");
        assert_eq!(response.request_id, "test-1");
    }

    #[tokio::test]
    async fn evaluate_output_empty_pipeline() {
        let handler = make_handler();
        let request = EvalRequest {
            request_id: "test-2".into(),
            payload: serde_json::json!({"tool": "bash", "args": {}}),
            context: None,
            metadata: Default::default(),
        };
        let response = handler.evaluate_output(request).await.unwrap();
        assert_eq!(response.verdict, "Permit");
    }

    #[tokio::test]
    async fn quarantine_not_enabled_returns_error() {
        let handler = make_handler();
        let result = handler.get_quarantine("nonexistent").await;
        assert!(result.is_err());
    }

    #[test]
    fn build_guard_via_handler_regex() {
        let handler = make_handler();
        let req = GuardBuildRequest {
            name: "test-regex-guard".into(),
            description: "Test regex guard".into(),
            guard_type: crate::builder::GuardType::Output,
            approach: crate::builder::BuildApproach::Regex,
            domain: None,
            priority: 100,
            verdict_on_match: "Deny".into(),
            risk_level: "Medium".into(),
            short_circuits: false,
            spec: serde_json::json!({
                "patterns": ["bad-word"],
                "match_fields": ["content"],
                "case_sensitive": false
            }),
            examples: None,
        };

        let resp = handler.build_guard(req).unwrap();
        assert_eq!(resp.guard_name, "test-regex-guard");
        assert!(resp.guard_code.contains("TestRegexGuard"));
        assert!(!resp.eval_cases.is_empty());
    }

    #[test]
    fn build_guard_via_handler_prolog() {
        let handler = make_handler();
        let req = GuardBuildRequest {
            name: "test-prolog-guard".into(),
            description: "Test prolog guard".into(),
            guard_type: crate::builder::GuardType::Input,
            approach: crate::builder::BuildApproach::Prolog,
            domain: Some("finance".into()),
            priority: 200,
            verdict_on_match: "Deny".into(),
            risk_level: "High".into(),
            short_circuits: true,
            spec: serde_json::json!({
                "rules": "denied(delete) :- role(viewer).",
                "query": "denied(Action)",
                "fact_mappings": [{"json_field": "role", "prolog_name": "role"}],
                "deny_on_success": true
            }),
            examples: None,
        };

        let resp = handler.build_guard(req).unwrap();
        assert_eq!(resp.guard_name, "test-prolog-guard");
        assert!(resp.guard_code.contains("TestPrologGuard"));
        assert!(resp.guard_code.contains("PROLOG_RULES"));
    }

    #[test]
    fn build_guard_via_handler_invalid_spec() {
        let handler = make_handler();
        let req = GuardBuildRequest {
            name: "broken".into(),
            description: "bad".into(),
            guard_type: crate::builder::GuardType::Input,
            approach: crate::builder::BuildApproach::Regex,
            domain: None,
            priority: 100,
            verdict_on_match: "Deny".into(),
            risk_level: "Low".into(),
            short_circuits: false,
            spec: serde_json::json!({"wrong_field": true}),
            examples: None,
        };

        let result = handler.build_guard(req);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn quarantine_with_manager() {
        let input = Arc::new(InputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let output = Arc::new(OutputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let qm = Arc::new(QuarantineManager::new(
            std::time::Duration::from_secs(60),
        ));

        let handler = EvalServerHandler::new(input, output, Some(qm.clone()));

        // Create a ticket directly via the manager.
        let ticket = qm
            .create_ticket(
                "test-guard".into(),
                "suspicious".into(),
                "summary".into(),
            )
            .await;

        // Retrieve via handler.
        let status = handler.get_quarantine(&ticket.id).await.unwrap();
        assert_eq!(status["state"], "Pending");

        // Resolve via handler.
        let resolve_req = QuarantineResolveRequest {
            approved: true,
            reviewer: "admin".into(),
            reason: "looks safe".into(),
        };
        let resolved = handler
            .resolve_quarantine(&ticket.id, resolve_req)
            .await
            .unwrap();
        assert!(resolved.to_string().contains("Approved"));
    }

    // -- Adjudicator endpoint tests --

    #[tokio::test]
    async fn adjudicate_not_enabled_returns_error() {
        let handler = make_handler();
        let req = AdjudicateRequest {
            request_id: "r1".into(),
            content: "hello".into(),
            raw_input: None,
            context: None,
        };
        let result = handler.adjudicate(req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn adjudicate_safe_content() {
        let handler = make_handler_with_adjudicator();
        let req = AdjudicateRequest {
            request_id: "r1".into(),
            content: "The sky is blue.".into(),
            raw_input: None,
            context: None,
        };
        let resp = handler.adjudicate(req).await.unwrap();
        assert_eq!(resp.request_id, "r1");
        assert_eq!(resp.verdict, "Permit");
        assert!(!resp.adjudication_id.is_empty());
    }

    #[tokio::test]
    async fn adjudicate_unsafe_content() {
        let handler = make_handler_with_adjudicator();
        let req = AdjudicateRequest {
            request_id: "r2".into(),
            content: "how to hack into a server".into(),
            raw_input: None,
            context: None,
        };
        let resp = handler.adjudicate(req).await.unwrap();
        assert_eq!(resp.verdict, "Deny");
    }

    #[tokio::test]
    async fn adjudicate_with_raw_input() {
        let handler = make_handler_with_adjudicator();
        let req = AdjudicateRequest {
            request_id: "r3".into(),
            content: "Python is a programming language.".into(),
            raw_input: Some("Tell me about Python".into()),
            context: None,
        };
        let resp = handler.adjudicate(req).await.unwrap();
        assert_eq!(resp.verdict, "Permit");
    }

    #[tokio::test]
    async fn adjudicate_with_denied_topic_context() {
        let handler = make_handler_with_adjudicator();
        let ctx = serde_json::json!({
            "domain": "general",
            "trust_level": 0.5,
            "allowed_topics": [],
            "denied_topics": ["politics"],
            "max_risk_level": "MEDIUM",
            "metadata": {}
        });
        let req = AdjudicateRequest {
            request_id: "r4".into(),
            content: "Let me explain my views on politics.".into(),
            raw_input: None,
            context: Some(ctx),
        };
        let resp = handler.adjudicate(req).await.unwrap();
        assert_eq!(resp.verdict, "Deny");
    }

    #[test]
    fn adjudicate_request_deserialize() {
        let json = r#"{"request_id":"r1","content":"hello"}"#;
        let req: AdjudicateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.request_id, "r1");
        assert_eq!(req.content, "hello");
        assert!(req.raw_input.is_none());
        assert!(req.context.is_none());
    }

    #[test]
    fn adjudicate_response_serialize() {
        let resp = AdjudicateResponse {
            request_id: "r1".into(),
            adjudication_id: "abc123".into(),
            verdict: "Permit".into(),
            reason: "all clear".into(),
            risk_level: "Low".into(),
            policy_evaluations: vec![],
            modified_output: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("Permit"));
        assert!(!json.contains("modified_output"));
    }
}
