use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{FromRequest, WebSocketUpgrade};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use guard_core::Verdict;
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;
use url::Url;

use crate::guard_eval::{EvalResult, GuardEvaluator};

/// Serialize a JSON value to a text string for WebSocket frames.
/// If the value is a plain string (originally non-JSON text), return
/// the inner string to avoid double-quoting.
fn value_to_ws_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// Shared state for the proxy, available to all request handlers.
pub struct ProxyState {
    pub evaluator: GuardEvaluator,
    pub upstream_url: Url,
    pub adapter_name: String,
    pub http_client: reqwest::Client,
}

/// Build a deny response with the guard's reason.
fn deny_response(reason: &str) -> Response {
    let body = serde_json::json!({
        "error": "denied",
        "reason": reason,
    });
    (
        StatusCode::FORBIDDEN,
        [("content-type", "application/json")],
        serde_json::to_string(&body).unwrap(),
    )
        .into_response()
}

/// Build a quarantine response with ticket IDs.
fn quarantine_response(tickets: &[String], reason: &str) -> Response {
    let body = serde_json::json!({
        "quarantined": true,
        "tickets": tickets,
        "reason": reason,
    });
    (
        StatusCode::ACCEPTED,
        [("content-type", "application/json")],
        serde_json::to_string(&body).unwrap(),
    )
        .into_response()
}

/// Apply an eval result. Returns `Some(Response)` if the request should
/// be blocked, or `None` with the (possibly modified) payload to forward.
pub fn apply_eval_result(
    eval: &EvalResult,
    original_payload: &serde_json::Value,
) -> (Option<Response>, serde_json::Value) {
    match eval.verdict {
        Verdict::Deny => (Some(deny_response(&eval.reason)), original_payload.clone()),
        Verdict::Quarantine => (
            Some(quarantine_response(&eval.quarantine_tickets, &eval.reason)),
            original_payload.clone(),
        ),
        Verdict::Modify => {
            let payload = eval
                .modified_payload
                .clone()
                .unwrap_or_else(|| original_payload.clone());
            (None, payload)
        }
        // Permit, Escalate -> pass through
        _ => (None, original_payload.clone()),
    }
}

/// Forward an HTTP request to the upstream, preserving method, path, and headers.
pub async fn forward_http(
    state: &ProxyState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: serde_json::Value,
) -> Result<(StatusCode, HeaderMap, serde_json::Value), Response> {
    let mut upstream = state.upstream_url.clone();
    upstream.set_path(uri.path());
    upstream.set_query(uri.query());

    let mut req = state.http_client.request(method, upstream.as_str());
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if matches!(n, "host" | "connection" | "transfer-encoding" | "content-length") {
            continue;
        }
        req = req.header(name, value);
    }
    // If the body was originally non-JSON (wrapped as Value::String during parsing),
    // send it as raw bytes to preserve the original content type.
    match &body {
        serde_json::Value::String(s) => {
            req = req.body(s.clone());
        }
        serde_json::Value::Null => {}
        _ => {
            req = req.json(&body);
        }
    }

    let resp = req.send().await.map_err(|e| {
        (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response()
    })?;

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = resp.headers().clone();
    let resp_body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);

    Ok((status, resp_headers, resp_body))
}

/// Handle an HTTP request through the full proxy pipeline:
/// 1. OutputGuards evaluate the outbound request
/// 2. Forward to upstream if permitted
/// 3. InputGuards evaluate the response
pub async fn proxy_http_request(
    state: Arc<ProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Response {
    let request_payload: serde_json::Value = if body_bytes.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(_) => serde_json::Value::String(String::from_utf8_lossy(&body_bytes).into_owned()),
        }
    };

    // Step 1: OutputGuards evaluate the outbound request
    let output_eval = match state
        .evaluator
        .evaluate_output(&request_payload, &state.adapter_name)
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

    let (blocked, forwarded_payload) = apply_eval_result(&output_eval, &request_payload);
    if let Some(resp) = blocked {
        return resp;
    }

    // Step 2: Forward to upstream
    let (status, _resp_headers, response_payload) =
        match forward_http(&state, method, uri, headers, forwarded_payload).await {
            Ok(r) => r,
            Err(resp) => return resp,
        };

    // Step 3: InputGuards evaluate the response
    let input_eval = match state
        .evaluator
        .evaluate_input(&response_payload, &state.adapter_name)
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

/// Handle a WebSocket upgrade and proxy frames through guards.
pub async fn proxy_ws_upgrade(state: Arc<ProxyState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| proxy_ws_connection(state, socket))
}

/// Extract request parts and proxy as HTTP.
pub async fn proxy_http_from_request(
    state: Arc<ProxyState>,
    request: axum::extract::Request,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body_bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    proxy_http_request(state, method, uri, headers, body_bytes).await
}

/// Extract WebSocketUpgrade from a request and proxy it.
pub async fn proxy_ws_from_request(
    state: Arc<ProxyState>,
    request: axum::extract::Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let request = axum::extract::Request::from_parts(parts, body);
    match WebSocketUpgrade::from_request(request, &()).await {
        Ok(ws) => proxy_ws_upgrade(state, ws).await,
        Err(e) => {
            (StatusCode::BAD_REQUEST, format!("ws upgrade failed: {e}")).into_response()
        }
    }
}

/// Proxy a WebSocket connection, evaluating each frame through guards.
async fn proxy_ws_connection(state: Arc<ProxyState>, agent_ws: WebSocket) {
    // Connect to upstream WebSocket
    let upstream_url = state.upstream_url.as_str();
    let (upstream_ws, _) = match tokio_tungstenite::connect_async(upstream_url).await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("failed to connect to upstream WS: {e}");
            return;
        }
    };

    let (mut agent_sink, mut agent_stream) = agent_ws.split();
    let (mut upstream_sink, mut upstream_stream) = upstream_ws.split();

    let state2 = state.clone();

    // Agent → Upstream: evaluate as output (agent is sending outbound)
    let agent_to_upstream = tokio::spawn(async move {
        while let Some(msg_result) = agent_stream.next().await {
            let msg: Message = match msg_result {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                Message::Text(text) => {
                    let text_str: &str = &text;
                    let payload: serde_json::Value = serde_json::from_str(text_str)
                        .unwrap_or_else(|_| serde_json::Value::String(text_str.to_string()));

                    match state
                        .evaluator
                        .evaluate_output(&payload, &state.adapter_name)
                        .await
                    {
                        Ok(eval) => match eval.verdict {
                            Verdict::Deny | Verdict::Quarantine => {
                                tracing::warn!(
                                    "output guard blocked agent frame: {}",
                                    eval.reason
                                );
                                continue;
                            }
                            Verdict::Modify => {
                                let forwarded = eval.modified_payload.unwrap_or(payload);
                                let fwd_text = value_to_ws_text(&forwarded);
                                if upstream_sink
                                    .send(TungsteniteMessage::Text(fwd_text.into()))
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
                            tracing::error!("output guard error: {e}");
                            break;
                        }
                    }
                }
                Message::Binary(data) => {
                    if upstream_sink
                        .send(TungsteniteMessage::Binary(Bytes::from(data.to_vec())))
                        .await
                        .is_err()
                    {
                        break;
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

    // Upstream → Agent: evaluate as input (external data coming in)
    let upstream_to_agent = tokio::spawn(async move {
        while let Some(msg_result) = upstream_stream.next().await {
            let msg: TungsteniteMessage = match msg_result {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                TungsteniteMessage::Text(text) => {
                    let text_str = text.to_string();
                    let payload: serde_json::Value = serde_json::from_str(&text_str)
                        .unwrap_or_else(|_| serde_json::Value::String(text_str.clone()));

                    match state2
                        .evaluator
                        .evaluate_input(&payload, &state2.adapter_name)
                        .await
                    {
                        Ok(eval) => match eval.verdict {
                            Verdict::Deny | Verdict::Quarantine => {
                                tracing::warn!(
                                    "input guard blocked upstream frame: {}",
                                    eval.reason
                                );
                                continue;
                            }
                            Verdict::Modify => {
                                let forwarded = eval.modified_payload.unwrap_or(payload);
                                let fwd_text = value_to_ws_text(&forwarded);
                                if agent_sink
                                    .send(Message::text(fwd_text))
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
                            tracing::error!("input guard error: {e}");
                            break;
                        }
                    }
                }
                TungsteniteMessage::Binary(data) => {
                    if agent_sink
                        .send(Message::Binary(data.into()))
                        .await
                        .is_err()
                    {
                        break;
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
        _ = agent_to_upstream => {},
        _ = upstream_to_agent => {},
    }
}
