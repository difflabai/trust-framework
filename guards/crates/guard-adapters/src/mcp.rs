//! MCP Gateway middleware adapter.
//!
//! Wraps an inner MCP transport and interposes guard evaluation on
//! request/response. OutputGuard evaluates outgoing requests, InputGuard
//! evaluates incoming responses.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use guard_core::{
    GuardContext, GuardError, GuardLayer, GuardPayload, InputGuards, OperatingContext,
    OutputGuards, RequestMeta, Verdict,
};

/// An MCP request flowing through the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub method: String,
    pub params: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

impl GuardPayload for McpRequest {
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

/// An MCP response flowing back through the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

/// An MCP error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// The inner MCP transport that actually sends requests to an MCP server.
#[async_trait]
pub trait McpTransport: Send + Sync {
    async fn send_request(&self, request: McpRequest) -> Result<McpResponse, GuardError>;
}

/// The MCP guard middleware sits between a client and an MCP server.
/// It evaluates outgoing requests (OutputGuards) and incoming responses (InputGuards).
pub struct McpGuardMiddleware<T: McpTransport> {
    inner: T,
    input_guards: Arc<InputGuards>,
    output_guards: Arc<OutputGuards>,
    operating_context: OperatingContext,
}

impl<T: McpTransport> McpGuardMiddleware<T> {
    pub fn new(
        inner: T,
        input_guards: Arc<InputGuards>,
        output_guards: Arc<OutputGuards>,
        operating_context: OperatingContext,
    ) -> Self {
        Self {
            inner,
            input_guards,
            output_guards,
            operating_context,
        }
    }

    fn make_context(&self) -> GuardContext {
        GuardContext::new(self.operating_context.clone()).with_request_meta(RequestMeta {
            source_adapter: "mcp".into(),
            ..RequestMeta::default()
        })
    }

    /// Handle a request through the full guard pipeline:
    /// 1. OutputGuard evaluates the outgoing request
    /// 2. If permitted, forward to inner transport
    /// 3. InputGuard evaluates the response
    pub async fn handle_request(&self, request: McpRequest) -> Result<McpResponse, GuardError> {
        let ctx = self.make_context();

        // Step 1: OutputGuard evaluates the request before it leaves.
        let output_result = self
            .output_guards
            .evaluate(&request, &ctx)
            .await?;

        match output_result.verdict {
            Verdict::Deny => {
                return Ok(McpResponse {
                    result: None,
                    error: Some(McpError {
                        code: -32600,
                        message: output_result.reason,
                        data: None,
                    }),
                    id: request.id,
                });
            }
            Verdict::Quarantine => {
                let ticket_ids: Vec<&str> = output_result
                    .quarantine_tickets
                    .iter()
                    .map(|t| t.id.as_str())
                    .collect();
                return Ok(McpResponse {
                    result: Some(serde_json::json!({
                        "quarantined": true,
                        "tickets": ticket_ids,
                    })),
                    error: None,
                    id: request.id,
                });
            }
            _ => {} // Permit, Modify, Escalate -> proceed
        }

        // Step 2: Forward to inner MCP server.
        let response = self.inner.send_request(request.clone()).await?;

        // Step 3: InputGuard evaluates the response.
        let input_ctx = self.make_context();
        let input_result = self
            .input_guards
            .evaluate(&response, &input_ctx)
            .await?;

        match input_result.verdict {
            Verdict::Deny => Ok(McpResponse {
                result: None,
                error: Some(McpError {
                    code: -32600,
                    message: input_result.reason,
                    data: None,
                }),
                id: response.id,
            }),
            Verdict::Quarantine => {
                let ticket_ids: Vec<&str> = input_result
                    .quarantine_tickets
                    .iter()
                    .map(|t| t.id.as_str())
                    .collect();
                Ok(McpResponse {
                    result: Some(serde_json::json!({
                        "quarantined": true,
                        "tickets": ticket_ids,
                    })),
                    error: None,
                    id: response.id,
                })
            }
            _ => Ok(response), // Permit, Modify, Escalate -> pass through
        }
    }
}

impl GuardPayload for McpResponse {
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

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::{GuardPipeline, NoopLogger, PipelineConfig};

    struct EchoTransport;

    #[async_trait]
    impl McpTransport for EchoTransport {
        async fn send_request(&self, request: McpRequest) -> Result<McpResponse, GuardError> {
            Ok(McpResponse {
                result: Some(serde_json::json!({"echo": request.method})),
                error: None,
                id: request.id,
            })
        }
    }

    fn make_middleware(
        transport: impl McpTransport + 'static,
    ) -> McpGuardMiddleware<impl McpTransport> {
        let input = Arc::new(InputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let output = Arc::new(OutputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        McpGuardMiddleware::new(transport, input, output, OperatingContext::default())
    }

    #[test]
    fn mcp_request_serialize() {
        let req = McpRequest {
            method: "tools/call".into(),
            params: serde_json::json!({"name": "bash"}),
            id: Some(serde_json::json!(1)),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("tools/call"));
    }

    #[test]
    fn mcp_response_serialize() {
        let resp = McpResponse {
            result: Some(serde_json::json!("ok")),
            error: None,
            id: Some(serde_json::json!(1)),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("error"));
    }

    #[test]
    fn mcp_error_serialize() {
        let err = McpError {
            code: -32600,
            message: "denied".into(),
            data: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("-32600"));
    }

    #[tokio::test]
    async fn middleware_permits_with_empty_guards() {
        let mw = make_middleware(EchoTransport);
        let request = McpRequest {
            method: "tools/call".into(),
            params: serde_json::json!({}),
            id: Some(serde_json::json!(1)),
        };
        let response = mw.handle_request(request).await.unwrap();
        assert!(response.error.is_none());
        assert_eq!(response.result.unwrap()["echo"], "tools/call");
    }

    #[tokio::test]
    async fn middleware_preserves_request_id() {
        let mw = make_middleware(EchoTransport);
        let request = McpRequest {
            method: "test".into(),
            params: serde_json::json!({}),
            id: Some(serde_json::json!(42)),
        };
        let response = mw.handle_request(request).await.unwrap();
        assert_eq!(response.id, Some(serde_json::json!(42)));
    }
}
