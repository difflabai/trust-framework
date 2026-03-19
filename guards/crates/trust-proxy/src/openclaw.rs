//! OpenClaw proxy mode.
//!
//! Understands OpenClaw's WebSocket protocol and provides richer guard
//! payloads with OpenClaw-specific fields. The proxy sits between an
//! OpenClaw client and the OpenClaw gateway, evaluating all messages
//! through the guard pipeline.
//!
//! OpenClaw uses a WebSocket protocol with three message types:
//! - Requests:  `{type:"req", id, method, params}`
//! - Responses: `{type:"res", id, ok, payload|error}`
//! - Events:    `{type:"event", event, payload}`
//!
//! Guard mapping (following PRISM hook semantics):
//! - Outbound requests from agent (tool invocations) → OutputGuards
//! - Inbound responses and events from gateway       → InputGuards

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequest, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use guard_core::{GuardPayload, Verdict};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

use crate::proxy::{proxy_http_request, ProxyState};

/// An OpenClaw tool invocation payload for richer guard evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenClawToolPayload {
    /// The WebSocket method (e.g. "tools/invoke", "sessions_send").
    pub method: String,
    /// Tool category: "shell", "file", "browser", "automation", etc.
    #[serde(default)]
    pub tool_type: Option<String>,
    /// Specific tool name.
    #[serde(default)]
    pub tool_name: Option<String>,
    /// Tool arguments or message content.
    pub arguments: serde_json::Value,
    /// The session this message belongs to.
    #[serde(default)]
    pub session_id: Option<String>,
    /// The original request ID from the WebSocket frame.
    #[serde(default)]
    pub request_id: Option<String>,
}

impl GuardPayload for OpenClawToolPayload {
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

/// An OpenClaw event payload (gateway → client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenClawEventPayload {
    pub event_type: String,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub session_id: Option<String>,
}

impl GuardPayload for OpenClawEventPayload {
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

/// Classify an OpenClaw request to extract tool information.
fn classify_request(msg: &serde_json::Value) -> OpenClawToolPayload {
    let method = msg["method"].as_str().unwrap_or("unknown").to_string();
    let params = msg.get("params").cloned().unwrap_or(serde_json::Value::Null);

    let tool_name = params["name"]
        .as_str()
        .or_else(|| params["tool_name"].as_str())
        .map(String::from);

    let tool_type = params["type"]
        .as_str()
        .or_else(|| params["tool_type"].as_str())
        .map(String::from);

    let session_id = params["session_id"]
        .as_str()
        .or_else(|| msg["session_id"].as_str())
        .map(String::from);

    OpenClawToolPayload {
        method,
        tool_type,
        tool_name,
        arguments: params,
        session_id,
        request_id: msg["id"].as_str().map(String::from),
    }
}

/// Classify an OpenClaw event from the gateway.
fn classify_event(msg: &serde_json::Value) -> OpenClawEventPayload {
    OpenClawEventPayload {
        event_type: msg["event"].as_str().unwrap_or("unknown").to_string(),
        payload: msg.get("payload").cloned().unwrap_or(serde_json::Value::Null),
        session_id: msg["session_id"].as_str().map(String::from),
    }
}

/// Build the axum router for OpenClaw proxy mode.
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
    let is_ws = request
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

    if is_ws {
        let (parts, body) = request.into_parts();
        let request = axum::extract::Request::from_parts(parts, body);
        match WebSocketUpgrade::from_request(request, &()).await {
            Ok(ws) => {
                return ws.on_upgrade(move |socket| openclaw_ws_connection(state, socket));
            }
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("ws upgrade failed: {e}"))
                    .into_response();
            }
        }
    }

    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .unwrap_or_default();

    proxy_http_request(state, method, uri, headers, body).await
}

/// Proxy an OpenClaw WebSocket connection with protocol-aware guard evaluation.
async fn openclaw_ws_connection(state: Arc<ProxyState>, agent_ws: WebSocket) {
    let upstream_url = state.upstream_url.as_str();
    let (upstream_ws, _) = match tokio_tungstenite::connect_async(upstream_url).await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("failed to connect to OpenClaw gateway: {e}");
            return;
        }
    };

    let (mut agent_sink, mut agent_stream) = agent_ws.split();
    let (mut upstream_sink, mut upstream_stream) = upstream_ws.split();

    let state2 = state.clone();

    // Agent → OpenClaw gateway: evaluate outbound requests through OutputGuards
    let agent_to_gateway = tokio::spawn(async move {
        while let Some(msg_result) = agent_stream.next().await {
            let msg: Message = match msg_result {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                Message::Text(text) => {
                    let text_str: &str = &text;
                    let raw: serde_json::Value = match serde_json::from_str(text_str) {
                        Ok(v) => v,
                        Err(_) => {
                            // Non-JSON text: forward as-is
                            if upstream_sink
                                .send(TungsteniteMessage::Text(text_str.to_string().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                    };

                    let msg_type = raw["type"].as_str().unwrap_or("");

                    if msg_type == "req" {
                        let tool_payload = classify_request(&raw);
                        let payload_json = serde_json::to_value(&tool_payload)
                            .unwrap_or(serde_json::Value::Null);

                        match state
                            .evaluator
                            .evaluate_output(&payload_json, "openclaw")
                            .await
                        {
                            Ok(eval) => match eval.verdict {
                                Verdict::Deny | Verdict::Quarantine => {
                                    tracing::warn!(
                                        "openclaw output guard blocked method={}: {}",
                                        tool_payload.method,
                                        eval.reason
                                    );
                                    continue;
                                }
                                Verdict::Modify => {
                                    let forwarded = serde_json::to_string(
                                        &eval.modified_payload.unwrap_or(raw),
                                    )
                                    .unwrap_or_default();
                                    if upstream_sink
                                        .send(TungsteniteMessage::Text(forwarded.into()))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                _ => {
                                    if upstream_sink
                                        .send(TungsteniteMessage::Text(
                                            text_str.to_string().into(),
                                        ))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            },
                            Err(e) => {
                                tracing::error!("openclaw output guard error: {e}");
                                break;
                            }
                        }
                    } else {
                        // Non-request frames (connect, ping, etc.) — pass through
                        if upstream_sink
                            .send(TungsteniteMessage::Text(text_str.to_string().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                Message::Close(_) => {
                    let _ = upstream_sink.send(TungsteniteMessage::Close(None)).await;
                    break;
                }
                _ => {}
            }
        }
    });

    // OpenClaw gateway → Agent: evaluate inbound events/responses through InputGuards
    let gateway_to_agent = tokio::spawn(async move {
        while let Some(msg_result) = upstream_stream.next().await {
            let msg: TungsteniteMessage = match msg_result {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                TungsteniteMessage::Text(text) => {
                    let text_str = text.to_string();
                    let raw: serde_json::Value = match serde_json::from_str(&text_str) {
                        Ok(v) => v,
                        Err(_) => {
                            if agent_sink
                                .send(Message::text(text_str))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                    };

                    let msg_type = raw["type"].as_str().unwrap_or("");
                    let eval_payload = if msg_type == "event" {
                        let event = classify_event(&raw);
                        serde_json::to_value(&event).unwrap_or(raw.clone())
                    } else {
                        raw.clone()
                    };

                    match state2
                        .evaluator
                        .evaluate_input(&eval_payload, "openclaw")
                        .await
                    {
                        Ok(eval) => match eval.verdict {
                            Verdict::Deny | Verdict::Quarantine => {
                                tracing::warn!(
                                    "openclaw input guard blocked gateway frame: {}",
                                    eval.reason
                                );
                                continue;
                            }
                            Verdict::Modify => {
                                let forwarded = serde_json::to_string(
                                    &eval.modified_payload.unwrap_or(raw),
                                )
                                .unwrap_or_default();
                                if agent_sink
                                    .send(Message::text(forwarded))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            _ => {
                                if agent_sink
                                    .send(Message::text(text_str))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        },
                        Err(e) => {
                            tracing::error!("openclaw input guard error: {e}");
                            break;
                        }
                    }
                }
                TungsteniteMessage::Close(_) => {
                    let _ = agent_sink.send(Message::Close(None)).await;
                    break;
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = agent_to_gateway => {},
        _ = gateway_to_agent => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_request_tools_invoke() {
        let msg = serde_json::json!({
            "type": "req",
            "id": "abc",
            "method": "tools/invoke",
            "params": {
                "name": "shell",
                "type": "shell",
                "session_id": "sess-1",
                "command": "ls -la"
            }
        });
        let classified = classify_request(&msg);
        assert_eq!(classified.method, "tools/invoke");
        assert_eq!(classified.tool_name.as_deref(), Some("shell"));
        assert_eq!(classified.tool_type.as_deref(), Some("shell"));
        assert_eq!(classified.session_id.as_deref(), Some("sess-1"));
        assert_eq!(classified.request_id.as_deref(), Some("abc"));
    }

    #[test]
    fn classify_request_sessions_send() {
        let msg = serde_json::json!({
            "type": "req",
            "id": "def",
            "method": "sessions_send",
            "params": {
                "session_id": "sess-2",
                "content": "Hello, world!"
            }
        });
        let classified = classify_request(&msg);
        assert_eq!(classified.method, "sessions_send");
        assert!(classified.tool_name.is_none());
        assert_eq!(classified.session_id.as_deref(), Some("sess-2"));
    }

    #[test]
    fn classify_event_message() {
        let msg = serde_json::json!({
            "type": "event",
            "event": "message",
            "payload": { "content": "Hi there" },
            "session_id": "sess-1"
        });
        let classified = classify_event(&msg);
        assert_eq!(classified.event_type, "message");
        assert_eq!(classified.session_id.as_deref(), Some("sess-1"));
    }

    #[test]
    fn openclaw_tool_payload_roundtrip() {
        let payload = OpenClawToolPayload {
            method: "tools/invoke".into(),
            tool_type: Some("shell".into()),
            tool_name: Some("bash".into()),
            arguments: serde_json::json!({"command": "ls"}),
            session_id: Some("sess-1".into()),
            request_id: Some("req-1".into()),
        };
        let json = serde_json::to_value(&payload).unwrap();
        let back: OpenClawToolPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back.method, "tools/invoke");
        assert_eq!(back.tool_name.as_deref(), Some("bash"));
    }

    #[test]
    fn openclaw_event_payload_roundtrip() {
        let payload = OpenClawEventPayload {
            event_type: "tool_result".into(),
            payload: serde_json::json!({"output": "file.txt"}),
            session_id: Some("sess-1".into()),
        };
        let json = serde_json::to_value(&payload).unwrap();
        let back: OpenClawEventPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back.event_type, "tool_result");
    }
}
