//! IronClaw proxy mode.
//!
//! Understands IronClaw's HTTP tool execution API and provides richer
//! guard payloads with IronClaw-specific fields. The proxy sits between
//! IronClaw's agent runtime and its tool/channel endpoints.
//!
//! IronClaw is a Rust-based secure AI assistant with:
//! - WASM-sandboxed tool execution
//! - Capability-based permissions
//! - Leak detection on requests and responses
//!
//! Guard mapping:
//! - Tool execution requests        → OutputGuards
//! - Tool execution responses       → InputGuards
//! - Channel inbound messages       → InputGuards
//! - Channel outbound messages      → OutputGuards
//!
//! IronClaw's tool execution pipeline:
//!   Allowlist → Leak Scan → Credential Inject → Execute → Response Leak Scan
//!
//! The trust-proxy sits *before* this pipeline, adding guard evaluation
//! as an additional layer.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use guard_core::GuardPayload;
use serde::{Deserialize, Serialize};

use crate::proxy::{apply_eval_result, forward_http, ProxyState};

/// An IronClaw tool execution request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IronClawToolPayload {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub execution_id: Option<String>,
    /// Whether this tool runs in a WASM sandbox.
    #[serde(default)]
    pub sandbox: bool,
    /// Original HTTP path used to classify this request.
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl GuardPayload for IronClawToolPayload {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn clone_payload(&self) -> Box<dyn GuardPayload> {
        Box::new(self.clone())
    }
    fn to_json_value(&self) -> Option<serde_json::Value> {
        serde_json::to_value(self).ok()
    }
}

/// An IronClaw channel message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IronClawChannelPayload {
    pub channel_id: String,
    pub content: serde_json::Value,
    #[serde(default)]
    pub sender: Option<String>,
    /// "inbound" or "outbound"
    pub direction: String,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

impl GuardPayload for IronClawChannelPayload {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn clone_payload(&self) -> Box<dyn GuardPayload> {
        Box::new(self.clone())
    }
    fn to_json_value(&self) -> Option<serde_json::Value> {
        serde_json::to_value(self).ok()
    }
}

/// Request classification based on the HTTP path.
enum RequestKind {
    /// Tool execution: POST /tools/execute, /sandbox/run, etc.
    ToolExecution,
    /// Channel outbound: POST /channels/*/send
    ChannelOutbound,
    /// Channel inbound: POST /channels/*/receive, webhooks
    ChannelInbound,
    /// Other: pass through with generic evaluation
    Other,
}

fn classify_path(path: &str, method: &Method) -> RequestKind {
    if method != Method::POST {
        return RequestKind::Other;
    }

    if path.contains("/tools/") || path.contains("/sandbox/") {
        RequestKind::ToolExecution
    } else if path.contains("/channels/") && path.contains("/send") {
        RequestKind::ChannelOutbound
    } else if path.contains("/channels/") && path.contains("/receive") {
        RequestKind::ChannelInbound
    } else if path.contains("/webhook") {
        RequestKind::ChannelInbound
    } else {
        RequestKind::Other
    }
}

/// Extract an IronClaw tool payload from a request body.
fn extract_tool_payload(
    body: &serde_json::Value,
    path: &str,
) -> IronClawToolPayload {
    IronClawToolPayload {
        tool_name: body["tool_name"]
            .as_str()
            .or_else(|| body["name"].as_str())
            .unwrap_or("unknown")
            .to_string(),
        arguments: body
            .get("arguments")
            .or_else(|| body.get("params"))
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        execution_id: body["execution_id"]
            .as_str()
            .or_else(|| body["id"].as_str())
            .map(String::from),
        sandbox: body["sandbox"].as_bool().unwrap_or(path.contains("/sandbox/")),
        endpoint: Some(path.to_string()),
    }
}

/// Extract an IronClaw channel payload from a request body.
fn extract_channel_payload(
    body: &serde_json::Value,
    path: &str,
    direction: &str,
) -> IronClawChannelPayload {
    // Try to extract channel_id from the path (e.g. /channels/telegram/send)
    let channel_id = path
        .split("/channels/")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .unwrap_or("unknown")
        .to_string();

    IronClawChannelPayload {
        channel_id,
        content: body
            .get("content")
            .or_else(|| body.get("message"))
            .cloned()
            .unwrap_or(body.clone()),
        sender: body["sender"].as_str().map(String::from),
        direction: direction.to_string(),
        metadata: body.get("metadata").cloned(),
    }
}

/// Build the axum router for IronClaw proxy mode.
pub fn router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/{*path}", any(handle_request))
        .route("/", any(handle_request))
        .with_state(state)
}

async fn handle_request(
    State(state): State<Arc<ProxyState>>,
    request: axum::extract::Request,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let path = uri.path().to_string();
    let kind = classify_path(&path, &method);

    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .unwrap_or_default();

    let body_json: serde_json::Value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => serde_json::Value::String(String::from_utf8_lossy(&body).into_owned()),
        }
    };

    match kind {
        RequestKind::ToolExecution => {
            handle_tool_execution(&state, method, uri, headers, &body_json, &path).await
        }
        RequestKind::ChannelOutbound => {
            handle_channel_outbound(&state, method, uri, headers, &body_json, &path).await
        }
        RequestKind::ChannelInbound => {
            handle_channel_inbound(&state, method, uri, headers, &body_json, &path).await
        }
        RequestKind::Other => {
            crate::proxy::proxy_http_request(state, method, uri, headers, body).await
        }
    }
}

/// Handle a tool execution request: OutputGuards on request, InputGuards on response.
async fn handle_tool_execution(
    state: &ProxyState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: &serde_json::Value,
    path: &str,
) -> Response {
    let tool_payload = extract_tool_payload(body, path);
    let eval_payload = serde_json::to_value(&tool_payload).unwrap_or(body.clone());

    // OutputGuards: agent is executing a tool (outbound action)
    let output_eval = match state
        .evaluator
        .evaluate_output(&eval_payload, "ironclaw")
        .await
    {
        Ok(eval) => eval,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("guard evaluation error: {e}"),
            )
                .into_response();
        }
    };

    let (blocked, forwarded) = apply_eval_result(&output_eval, body);
    if let Some(resp) = blocked {
        return resp;
    }

    // Forward to upstream
    let (status, _resp_headers, response_payload) =
        match forward_http(state, method, uri, headers, forwarded).await {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    // InputGuards: tool response coming back (inbound data)
    let input_eval = match state
        .evaluator
        .evaluate_input(&response_payload, "ironclaw")
        .await
    {
        Ok(eval) => eval,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("guard evaluation error: {e}"),
            )
                .into_response();
        }
    };

    let (blocked, final_payload) = apply_eval_result(&input_eval, &response_payload);
    if let Some(resp) = blocked {
        return resp;
    }

    (
        status,
        [("content-type", "application/json")],
        serde_json::to_string(&final_payload).unwrap_or_default(),
    )
        .into_response()
}

/// Handle a channel outbound message: OutputGuards (agent sending to user).
async fn handle_channel_outbound(
    state: &ProxyState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: &serde_json::Value,
    path: &str,
) -> Response {
    let channel_payload = extract_channel_payload(body, path, "outbound");
    let eval_payload = serde_json::to_value(&channel_payload).unwrap_or(body.clone());

    let output_eval = match state
        .evaluator
        .evaluate_output(&eval_payload, "ironclaw")
        .await
    {
        Ok(eval) => eval,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("guard evaluation error: {e}"),
            )
                .into_response();
        }
    };

    let (blocked, forwarded) = apply_eval_result(&output_eval, body);
    if let Some(resp) = blocked {
        return resp;
    }

    match forward_http(state, method, uri, headers, forwarded).await {
        Ok((status, _, resp_body)) => (
            status,
            [("content-type", "application/json")],
            serde_json::to_string(&resp_body).unwrap_or_default(),
        )
            .into_response(),
        Err(resp) => resp,
    }
}

/// Handle a channel inbound message: InputGuards (external data coming in).
async fn handle_channel_inbound(
    state: &ProxyState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: &serde_json::Value,
    path: &str,
) -> Response {
    let channel_payload = extract_channel_payload(body, path, "inbound");
    let eval_payload = serde_json::to_value(&channel_payload).unwrap_or(body.clone());

    let input_eval = match state
        .evaluator
        .evaluate_input(&eval_payload, "ironclaw")
        .await
    {
        Ok(eval) => eval,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("guard evaluation error: {e}"),
            )
                .into_response();
        }
    };

    let (blocked, forwarded) = apply_eval_result(&input_eval, body);
    if let Some(resp) = blocked {
        return resp;
    }

    match forward_http(state, method, uri, headers, forwarded).await {
        Ok((status, _, resp_body)) => (
            status,
            [("content-type", "application/json")],
            serde_json::to_string(&resp_body).unwrap_or_default(),
        )
            .into_response(),
        Err(resp) => resp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn classify_tool_execution_paths() {
        assert!(matches!(
            classify_path("/tools/execute", &Method::POST),
            RequestKind::ToolExecution
        ));
        assert!(matches!(
            classify_path("/sandbox/run", &Method::POST),
            RequestKind::ToolExecution
        ));
        assert!(matches!(
            classify_path("/tools/invoke", &Method::POST),
            RequestKind::ToolExecution
        ));
    }

    #[test]
    fn classify_channel_paths() {
        assert!(matches!(
            classify_path("/channels/telegram/send", &Method::POST),
            RequestKind::ChannelOutbound
        ));
        assert!(matches!(
            classify_path("/channels/slack/receive", &Method::POST),
            RequestKind::ChannelInbound
        ));
        assert!(matches!(
            classify_path("/webhook/telegram", &Method::POST),
            RequestKind::ChannelInbound
        ));
    }

    #[test]
    fn classify_other_paths() {
        assert!(matches!(
            classify_path("/health", &Method::GET),
            RequestKind::Other
        ));
        assert!(matches!(
            classify_path("/tools/execute", &Method::GET),
            RequestKind::Other
        ));
    }

    #[test]
    fn extract_tool_payload_basic() {
        let body = serde_json::json!({
            "tool_name": "shell",
            "arguments": {"command": "ls"},
            "execution_id": "exec-1",
            "sandbox": true,
        });
        let payload = extract_tool_payload(&body, "/tools/execute");
        assert_eq!(payload.tool_name, "shell");
        assert_eq!(payload.execution_id.as_deref(), Some("exec-1"));
        assert!(payload.sandbox);
    }

    #[test]
    fn extract_tool_payload_sandbox_from_path() {
        let body = serde_json::json!({
            "name": "file_read",
            "params": {"path": "/tmp/test"},
        });
        let payload = extract_tool_payload(&body, "/sandbox/run");
        assert_eq!(payload.tool_name, "file_read");
        assert!(payload.sandbox);
    }

    #[test]
    fn extract_channel_payload_from_path() {
        let body = serde_json::json!({
            "content": "Hello from user",
            "sender": "user-123",
            "metadata": {"platform": "telegram"},
        });
        let payload = extract_channel_payload(&body, "/channels/telegram/send", "outbound");
        assert_eq!(payload.channel_id, "telegram");
        assert_eq!(payload.direction, "outbound");
        assert_eq!(payload.sender.as_deref(), Some("user-123"));
    }

    #[test]
    fn ironclaw_tool_payload_roundtrip() {
        let payload = IronClawToolPayload {
            tool_name: "shell".into(),
            arguments: serde_json::json!({"cmd": "ls"}),
            execution_id: Some("exec-1".into()),
            sandbox: true,
            endpoint: Some("/tools/execute".into()),
        };
        let json = serde_json::to_value(&payload).unwrap();
        let back: IronClawToolPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back.tool_name, "shell");
        assert!(back.sandbox);
    }

    #[test]
    fn ironclaw_channel_payload_roundtrip() {
        let payload = IronClawChannelPayload {
            channel_id: "telegram".into(),
            content: serde_json::json!("Hello"),
            sender: Some("user-1".into()),
            direction: "inbound".into(),
            metadata: None,
        };
        let json = serde_json::to_value(&payload).unwrap();
        let back: IronClawChannelPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back.channel_id, "telegram");
        assert_eq!(back.direction, "inbound");
    }
}
