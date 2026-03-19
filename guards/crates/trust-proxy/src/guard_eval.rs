use std::collections::HashMap;
use std::sync::Arc;

use guard_core::{
    GuardContext, GuardError, GuardLayer, InputGuards, JsonPayload, OperatingContext,
    OutputGuards, RequestMeta, Verdict,
};
use guard_eval_client::{EvalTransport, EvaluateRequest, EvaluateResponse, HttpTransport};

/// Result of a guard evaluation.
pub struct EvalResult {
    pub verdict: Verdict,
    pub reason: String,
    /// The modified payload, if the verdict was Modify.
    pub modified_payload: Option<serde_json::Value>,
    /// Quarantine ticket IDs, if the verdict was Quarantine.
    pub quarantine_tickets: Vec<String>,
}

/// Wraps guard evaluation for use by the proxy.
///
/// Supports local guards, remote trust server evaluation, or both:
/// - **Local**: guards run in-process within the proxy
/// - **Remote**: guards run on a trust server, called via HTTP
/// - **Both**: local guards run first, then remote; strictest verdict wins
pub struct GuardEvaluator {
    /// Local guard pipelines (may be empty if no local guards configured).
    input_guards: Arc<InputGuards>,
    output_guards: Arc<OutputGuards>,
    operating_context: OperatingContext,
    /// Optional remote trust server transport.
    remote_transport: Option<Arc<HttpTransport>>,
}

impl GuardEvaluator {
    /// Create an evaluator with local guard pipelines only.
    pub fn local(
        input_guards: Arc<InputGuards>,
        output_guards: Arc<OutputGuards>,
        operating_context: OperatingContext,
    ) -> Self {
        Self {
            input_guards,
            output_guards,
            operating_context,
            remote_transport: None,
        }
    }

    /// Create an evaluator that delegates to a remote trust server only
    /// (with empty local pipelines).
    pub fn remote(trust_server_url: &str, operating_context: OperatingContext) -> Self {
        Self {
            input_guards: Arc::new(InputGuards::new(
                guard_core::GuardPipeline::new(guard_core::PipelineConfig::default()),
                Box::new(guard_core::NoopLogger),
            )),
            output_guards: Arc::new(OutputGuards::new(
                guard_core::GuardPipeline::new(guard_core::PipelineConfig::default()),
                Box::new(guard_core::NoopLogger),
            )),
            operating_context,
            remote_transport: Some(Arc::new(HttpTransport::new(trust_server_url))),
        }
    }

    /// Create an evaluator with both local guards and a remote trust server.
    /// Local guards run first; if both produce results, the strictest verdict wins.
    pub fn combined(
        input_guards: Arc<InputGuards>,
        output_guards: Arc<OutputGuards>,
        trust_server_url: &str,
        operating_context: OperatingContext,
    ) -> Self {
        Self {
            input_guards,
            output_guards,
            operating_context,
            remote_transport: Some(Arc::new(HttpTransport::new(trust_server_url))),
        }
    }

    /// Evaluate an outbound payload (agent → external) through OutputGuards.
    pub async fn evaluate_output(
        &self,
        payload: &serde_json::Value,
        adapter_name: &str,
    ) -> Result<EvalResult, GuardError> {
        let local_result = self.evaluate_output_local(payload, adapter_name).await?;

        if let Some(ref transport) = self.remote_transport {
            let remote_result =
                self.evaluate_output_remote(transport, payload, adapter_name).await?;
            Ok(merge_results(local_result, remote_result))
        } else {
            Ok(local_result)
        }
    }

    /// Evaluate an inbound payload (external → agent) through InputGuards.
    pub async fn evaluate_input(
        &self,
        payload: &serde_json::Value,
        adapter_name: &str,
    ) -> Result<EvalResult, GuardError> {
        let local_result = self.evaluate_input_local(payload, adapter_name).await?;

        if let Some(ref transport) = self.remote_transport {
            let remote_result =
                self.evaluate_input_remote(transport, payload, adapter_name).await?;
            Ok(merge_results(local_result, remote_result))
        } else {
            Ok(local_result)
        }
    }

    async fn evaluate_output_local(
        &self,
        payload: &serde_json::Value,
        adapter_name: &str,
    ) -> Result<EvalResult, GuardError> {
        let json_payload = JsonPayload {
            data: payload.clone(),
        };
        let ctx = make_local_context(&self.operating_context, adapter_name);
        let result = self.output_guards.evaluate(&json_payload, &ctx).await?;
        Ok(EvalResult {
            verdict: result.verdict,
            reason: result.reason,
            modified_payload: result.payload.as_ref().and_then(|p| p.to_json_value()),
            quarantine_tickets: result
                .quarantine_tickets
                .iter()
                .map(|t| t.id.clone())
                .collect(),
        })
    }

    async fn evaluate_input_local(
        &self,
        payload: &serde_json::Value,
        adapter_name: &str,
    ) -> Result<EvalResult, GuardError> {
        let json_payload = JsonPayload {
            data: payload.clone(),
        };
        let ctx = make_local_context(&self.operating_context, adapter_name);
        let result = self.input_guards.evaluate(&json_payload, &ctx).await?;
        Ok(EvalResult {
            verdict: result.verdict,
            reason: result.reason,
            modified_payload: result.payload.as_ref().and_then(|p| p.to_json_value()),
            quarantine_tickets: result
                .quarantine_tickets
                .iter()
                .map(|t| t.id.clone())
                .collect(),
        })
    }

    async fn evaluate_output_remote(
        &self,
        transport: &HttpTransport,
        payload: &serde_json::Value,
        adapter_name: &str,
    ) -> Result<EvalResult, GuardError> {
        let req =
            make_remote_request(payload, &self.operating_context, adapter_name, "output");
        let resp = transport.evaluate_output(req).await?;
        Ok(eval_result_from_response(resp))
    }

    async fn evaluate_input_remote(
        &self,
        transport: &HttpTransport,
        payload: &serde_json::Value,
        adapter_name: &str,
    ) -> Result<EvalResult, GuardError> {
        let req =
            make_remote_request(payload, &self.operating_context, adapter_name, "input");
        let resp = transport.evaluate_input(req).await?;
        Ok(eval_result_from_response(resp))
    }
}

fn make_local_context(operating_context: &OperatingContext, adapter_name: &str) -> GuardContext {
    GuardContext::new(operating_context.clone()).with_request_meta(RequestMeta {
        source_adapter: adapter_name.into(),
        ..RequestMeta::default()
    })
}

fn make_remote_request(
    payload: &serde_json::Value,
    operating_context: &OperatingContext,
    adapter_name: &str,
    layer: &str,
) -> EvaluateRequest {
    let context = serde_json::to_value(operating_context).unwrap_or(serde_json::json!({}));
    EvaluateRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        layer: layer.to_string(),
        payload: payload.clone(),
        context,
        metadata: HashMap::from([("source_adapter".to_string(), adapter_name.to_string())]),
    }
}

fn parse_verdict(s: &str) -> Verdict {
    match s.to_uppercase().as_str() {
        "DENY" | "Deny" => Verdict::Deny,
        "QUARANTINE" | "Quarantine" => Verdict::Quarantine,
        "ESCALATE" | "Escalate" => Verdict::Escalate,
        "MODIFY" | "Modify" => Verdict::Modify,
        _ => Verdict::Permit,
    }
}

fn eval_result_from_response(resp: EvaluateResponse) -> EvalResult {
    EvalResult {
        verdict: parse_verdict(&resp.verdict),
        reason: resp.reason,
        modified_payload: resp.modified_payload,
        quarantine_tickets: vec![],
    }
}

/// Merge two eval results, keeping the strictest verdict (highest precedence).
fn merge_results(a: EvalResult, b: EvalResult) -> EvalResult {
    if b.verdict.precedence() > a.verdict.precedence() {
        EvalResult {
            verdict: b.verdict,
            reason: b.reason,
            modified_payload: b.modified_payload,
            quarantine_tickets: if b.quarantine_tickets.is_empty() {
                a.quarantine_tickets
            } else {
                b.quarantine_tickets
            },
        }
    } else {
        EvalResult {
            verdict: a.verdict,
            reason: a.reason,
            modified_payload: a.modified_payload,
            quarantine_tickets: if a.quarantine_tickets.is_empty() {
                b.quarantine_tickets
            } else {
                a.quarantine_tickets
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::{GuardPipeline, NoopLogger, PipelineConfig};

    fn make_local_evaluator() -> GuardEvaluator {
        let input = Arc::new(InputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let output = Arc::new(OutputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        GuardEvaluator::local(input, output, OperatingContext::default())
    }

    #[tokio::test]
    async fn evaluate_output_empty_pipeline_permits() {
        let evaluator = make_local_evaluator();
        let payload = serde_json::json!({"tool": "bash", "args": {"cmd": "ls"}});
        let result = evaluator
            .evaluate_output(&payload, "test")
            .await
            .unwrap();
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[tokio::test]
    async fn evaluate_input_empty_pipeline_permits() {
        let evaluator = make_local_evaluator();
        let payload = serde_json::json!({"content": "hello world"});
        let result = evaluator
            .evaluate_input(&payload, "test")
            .await
            .unwrap();
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn parse_verdict_variants() {
        assert_eq!(parse_verdict("DENY"), Verdict::Deny);
        assert_eq!(parse_verdict("Deny"), Verdict::Deny);
        assert_eq!(parse_verdict("QUARANTINE"), Verdict::Quarantine);
        assert_eq!(parse_verdict("MODIFY"), Verdict::Modify);
        assert_eq!(parse_verdict("ESCALATE"), Verdict::Escalate);
        assert_eq!(parse_verdict("PERMIT"), Verdict::Permit);
        assert_eq!(parse_verdict("unknown"), Verdict::Permit);
    }

    #[test]
    fn remote_evaluator_constructs() {
        let evaluator =
            GuardEvaluator::remote("http://localhost:9090", OperatingContext::default());
        assert!(evaluator.remote_transport.is_some());
    }

    #[test]
    fn combined_evaluator_constructs() {
        let input = Arc::new(InputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let output = Arc::new(OutputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let evaluator = GuardEvaluator::combined(
            input,
            output,
            "http://localhost:9090",
            OperatingContext::default(),
        );
        assert!(evaluator.remote_transport.is_some());
    }

    #[test]
    fn merge_results_strictest_wins() {
        let permit = EvalResult {
            verdict: Verdict::Permit,
            reason: "ok".into(),
            modified_payload: None,
            quarantine_tickets: vec![],
        };
        let deny = EvalResult {
            verdict: Verdict::Deny,
            reason: "blocked".into(),
            modified_payload: None,
            quarantine_tickets: vec![],
        };
        let merged = merge_results(permit, deny);
        assert_eq!(merged.verdict, Verdict::Deny);
        assert_eq!(merged.reason, "blocked");
    }

    #[test]
    fn merge_results_preserves_winner() {
        let escalate = EvalResult {
            verdict: Verdict::Escalate,
            reason: "needs review".into(),
            modified_payload: None,
            quarantine_tickets: vec![],
        };
        let permit = EvalResult {
            verdict: Verdict::Permit,
            reason: "ok".into(),
            modified_payload: None,
            quarantine_tickets: vec![],
        };
        let merged = merge_results(escalate, permit);
        assert_eq!(merged.verdict, Verdict::Escalate);
        assert_eq!(merged.reason, "needs review");
    }
}
