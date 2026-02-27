//! Standalone HTTP evaluation server adapter.
//!
//! Exposes the guard system as an HTTP/JSON service that multiple
//! agent instances can call for remote evaluation. Uses the same
//! API surface as the EvalTransport trait from guard-eval-client.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use guard_core::{
    GuardContext, GuardError, GuardLayer, InputGuards, JsonPayload, OperatingContext, OutputGuards,
    PipelineResult, QuarantineManager, RequestMeta,
};

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

        Self {
            request_id,
            verdict: format!("{:?}", result.verdict),
            reason: result.reason.clone(),
            modified_payload: None,
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

/// The server-side handler that processes evaluation requests.
///
/// This is the core logic; actual HTTP server integration (e.g. with
/// axum, actix-web) is left to the application layer.
pub struct EvalServerHandler {
    input_guards: Arc<InputGuards>,
    output_guards: Arc<OutputGuards>,
    quarantine_manager: Option<Arc<QuarantineManager>>,
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
        }
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
}
