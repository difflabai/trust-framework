//! Claude Code hooks adapter.
//!
//! Translates between the stdin/stdout JSON hook protocol and the guard pipeline.
//! PreToolCall/PreMessage -> OutputGuards, PostToolCall/PostMessage -> InputGuards.

use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write as IoWrite};
use std::sync::Arc;

use guard_core::{
    GuardContext, GuardError, GuardLayer, GuardPayload, InputGuards, OperatingContext,
    OutputGuards, PipelineResult, RequestMeta,
};

/// Hook event types received from the agent harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookType {
    PreToolCall,
    PostToolCall,
    PreMessage,
    PostMessage,
}

/// A tool call payload flowing through the hooks adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallPayload {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub call_id: String,
}

impl GuardPayload for ToolCallPayload {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn clone_payload(&self) -> Box<dyn GuardPayload> {
        Box::new(self.clone())
    }
}

/// A tool result payload flowing back from tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultPayload {
    pub tool_name: String,
    pub result: serde_json::Value,
    pub call_id: String,
}

impl GuardPayload for ToolResultPayload {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn clone_payload(&self) -> Box<dyn GuardPayload> {
        Box::new(self.clone())
    }
}

/// A message payload (user or assistant message).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    pub role: String,
    pub content: serde_json::Value,
}

impl GuardPayload for MessagePayload {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn clone_payload(&self) -> Box<dyn GuardPayload> {
        Box::new(self.clone())
    }
}

/// The hook request format received on stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRequest {
    pub hook_type: HookType,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

/// The hook response format emitted on stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResponse {
    pub verdict: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_payload: Option<serde_json::Value>,
    #[serde(default)]
    pub warnings: Vec<serde_json::Value>,
}

impl HookResponse {
    pub fn from_pipeline_result(result: &PipelineResult) -> Self {
        let warnings: Vec<serde_json::Value> = result
            .warnings
            .warnings
            .iter()
            .filter_map(|w| serde_json::to_value(w).ok())
            .collect();

        Self {
            verdict: format!("{:?}", result.verdict),
            reason: result.reason.clone(),
            modified_payload: None,
            warnings,
        }
    }
}

/// Build a GuardContext from a hook request.
fn context_from_hook(request: &HookRequest) -> GuardContext {
    let operating = request
        .context
        .as_ref()
        .and_then(|c| serde_json::from_value::<OperatingContext>(c.clone()).ok())
        .unwrap_or_default();

    GuardContext::new(operating).with_request_meta(RequestMeta {
        source_adapter: "hooks".into(),
        ..RequestMeta::default()
    })
}

/// Classify which guard layer handles this hook type.
fn is_output_guard(hook_type: &HookType) -> bool {
    matches!(hook_type, HookType::PreToolCall | HookType::PreMessage)
}

/// Process a single hook request through the appropriate guard layer.
pub async fn process_hook_request(
    request: &HookRequest,
    input_guards: &InputGuards,
    output_guards: &OutputGuards,
) -> Result<HookResponse, GuardError> {
    let ctx = context_from_hook(request);

    let result = if is_output_guard(&request.hook_type) {
        // PreToolCall / PreMessage -> OutputGuards
        let payload: Box<dyn GuardPayload> = match request.hook_type {
            HookType::PreToolCall => {
                let p: ToolCallPayload = serde_json::from_value(request.payload.clone())?;
                Box::new(p)
            }
            HookType::PreMessage => {
                let p: MessagePayload = serde_json::from_value(request.payload.clone())?;
                Box::new(p)
            }
            _ => unreachable!(),
        };
        output_guards.evaluate(payload.as_ref(), &ctx).await?
    } else {
        // PostToolCall / PostMessage -> InputGuards
        let payload: Box<dyn GuardPayload> = match request.hook_type {
            HookType::PostToolCall => {
                let p: ToolResultPayload = serde_json::from_value(request.payload.clone())?;
                Box::new(p)
            }
            HookType::PostMessage => {
                let p: MessagePayload = serde_json::from_value(request.payload.clone())?;
                Box::new(p)
            }
            _ => unreachable!(),
        };
        input_guards.evaluate(payload.as_ref(), &ctx).await?
    };

    Ok(HookResponse::from_pipeline_result(&result))
}

/// Main loop for the hooks adapter. Reads JSON lines from stdin,
/// evaluates through guard pipelines, writes responses to stdout.
pub async fn run_hooks_loop(
    input_guards: Arc<InputGuards>,
    output_guards: Arc<OutputGuards>,
) -> Result<(), GuardError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: HookRequest = serde_json::from_str(&line)?;
        let response = process_hook_request(&request, &input_guards, &output_guards).await?;
        let json = serde_json::to_string(&response)?;
        writeln!(stdout_lock, "{json}")?;
        stdout_lock.flush()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::{Verdict, WarningMetadata};

    #[test]
    fn hook_request_deserialize_pre_tool_call() {
        let json = r#"{"hook_type":"pre_tool_call","payload":{"tool_name":"bash","arguments":{"command":"ls"},"call_id":"abc123"}}"#;
        let req: HookRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.hook_type, HookType::PreToolCall);
        assert_eq!(req.payload["tool_name"], "bash");
    }

    #[test]
    fn hook_request_deserialize_post_tool_call() {
        let json = r#"{"hook_type":"post_tool_call","payload":{"tool_name":"bash","result":"output","call_id":"abc123"}}"#;
        let req: HookRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.hook_type, HookType::PostToolCall);
    }

    #[test]
    fn hook_response_serialize() {
        let resp = HookResponse {
            verdict: "Permit".into(),
            reason: "All guards permit".into(),
            modified_payload: None,
            warnings: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("Permit"));
        assert!(!json.contains("modified_payload"));
    }

    #[test]
    fn hook_response_from_pipeline_result() {
        let result = PipelineResult {
            verdict: Verdict::Deny,
            payload: None,
            warnings: WarningMetadata::default(),
            quarantine_tickets: vec![],
            evaluations: vec![],
            reason: "Blocked by content safety".into(),
        };
        let resp = HookResponse::from_pipeline_result(&result);
        assert_eq!(resp.verdict, "Deny");
        assert_eq!(resp.reason, "Blocked by content safety");
    }

    #[test]
    fn tool_call_payload_roundtrip() {
        let payload = ToolCallPayload {
            tool_name: "bash".into(),
            arguments: serde_json::json!({"command": "ls"}),
            call_id: "test-123".into(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        let back: ToolCallPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back.tool_name, "bash");
        assert_eq!(back.call_id, "test-123");
    }

    #[test]
    fn is_output_guard_classification() {
        assert!(is_output_guard(&HookType::PreToolCall));
        assert!(is_output_guard(&HookType::PreMessage));
        assert!(!is_output_guard(&HookType::PostToolCall));
        assert!(!is_output_guard(&HookType::PostMessage));
    }

    #[tokio::test]
    async fn process_hook_request_with_empty_pipeline() {
        use guard_core::{GuardPipeline, NoopLogger, PipelineConfig};
        let input = InputGuards::new(GuardPipeline::new(PipelineConfig::default()), Box::new(NoopLogger));
        let output = OutputGuards::new(GuardPipeline::new(PipelineConfig::default()), Box::new(NoopLogger));

        let request = HookRequest {
            hook_type: HookType::PreToolCall,
            payload: serde_json::json!({
                "tool_name": "bash",
                "arguments": {"command": "ls"},
                "call_id": "test"
            }),
            context: None,
        };

        let response = process_hook_request(&request, &input, &output)
            .await
            .unwrap();
        assert_eq!(response.verdict, "Permit");
    }
}
