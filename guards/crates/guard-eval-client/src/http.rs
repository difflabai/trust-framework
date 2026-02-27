use async_trait::async_trait;
use guard_core::GuardError;
use reqwest::Client;

use crate::transport::EvalTransport;
use crate::types::{
    EvaluateRequest, EvaluateResponse, LogAck, LogEvent, QuarantineResolution, QuarantineStatus,
};

/// HTTP-based transport for the evaluation server.
///
/// Communicates with a remote eval server using JSON over HTTP.
/// All endpoints follow the `/v1/` prefix convention.
pub struct HttpTransport {
    client: Client,
    base_url: String,
}

impl HttpTransport {
    /// Create a new HTTP transport pointing at the given base URL.
    ///
    /// The base URL should not have a trailing slash
    /// (e.g., `http://localhost:9090`).
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Returns the base URL this transport is configured with.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[async_trait]
impl EvalTransport for HttpTransport {
    async fn log_events(&self, events: Vec<LogEvent>) -> Result<LogAck, GuardError> {
        let url = format!("{}/v1/log/events", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&events)
            .send()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        let ack: LogAck = resp
            .json()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        Ok(ack)
    }

    async fn evaluate_input(&self, req: EvaluateRequest) -> Result<EvaluateResponse, GuardError> {
        let url = format!("{}/v1/evaluate/input", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        let eval_resp: EvaluateResponse = resp
            .json()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        Ok(eval_resp)
    }

    async fn evaluate_output(&self, req: EvaluateRequest) -> Result<EvaluateResponse, GuardError> {
        let url = format!("{}/v1/evaluate/output", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        let eval_resp: EvaluateResponse = resp
            .json()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        Ok(eval_resp)
    }

    async fn get_quarantine_status(&self, id: &str) -> Result<QuarantineStatus, GuardError> {
        let url = format!("{}/v1/quarantine/{}", self.base_url, id);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        let status: QuarantineStatus = resp
            .json()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        Ok(status)
    }

    async fn resolve_quarantine(
        &self,
        resolution: QuarantineResolution,
    ) -> Result<QuarantineStatus, GuardError> {
        let url = format!("{}/v1/quarantine/{}", self.base_url, resolution.id);
        let resp = self
            .client
            .post(&url)
            .json(&resolution)
            .send()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        let status: QuarantineStatus = resp
            .json()
            .await
            .map_err(|e| GuardError::EvalServerConnection(e.to_string()))?;

        Ok(status)
    }
}
