pub mod http;
pub mod logger;
pub mod transport;
pub mod types;

pub use http::HttpTransport;
pub use logger::EvalServerLogger;
pub use transport::{EvalTransport, NoopTransport};
pub use types::{
    EvaluateRequest, EvaluateResponse, LogAck, LogEvent, QuarantineResolution, QuarantineStatus,
};

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use guard_core::GuardError;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // ---------------------------------------------------------------
    // Serialization roundtrip tests
    // ---------------------------------------------------------------

    #[test]
    fn log_event_serde_roundtrip() {
        let event = LogEvent {
            event_id: "evt-001".to_string(),
            event_type: "guard_evaluation".to_string(),
            request_id: "req-123".to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            payload_summary: "sha256:abc123...".to_string(),
            verdict: Some("PERMIT".to_string()),
            metadata: HashMap::from([("guard".to_string(), "content_filter".to_string())]),
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: LogEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(back.event_id, "evt-001");
        assert_eq!(back.event_type, "guard_evaluation");
        assert_eq!(back.request_id, "req-123");
        assert_eq!(back.timestamp_ns, 1_700_000_000_000_000_000);
        assert_eq!(back.payload_summary, "sha256:abc123...");
        assert_eq!(back.verdict, Some("PERMIT".to_string()));
        assert_eq!(back.metadata.get("guard").unwrap(), "content_filter");
    }

    #[test]
    fn log_event_without_verdict_serde() {
        let event = LogEvent {
            event_id: "evt-002".to_string(),
            event_type: "request_started".to_string(),
            request_id: "req-456".to_string(),
            timestamp_ns: 1_700_000_000_000_000_001,
            payload_summary: "truncated...".to_string(),
            verdict: None,
            metadata: HashMap::new(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let back: LogEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(back.verdict, None);
        assert!(back.metadata.is_empty());
    }

    #[test]
    fn evaluate_request_serde_roundtrip() {
        let req = EvaluateRequest {
            request_id: "req-789".to_string(),
            layer: "input".to_string(),
            payload: serde_json::json!({"tool": "bash", "command": "ls"}),
            context: serde_json::json!({"domain": "general", "trust_level": 0.5}),
            metadata: HashMap::from([("adapter".to_string(), "hooks".to_string())]),
        };

        let json = serde_json::to_string(&req).unwrap();
        let back: EvaluateRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(back.request_id, "req-789");
        assert_eq!(back.layer, "input");
        assert_eq!(back.payload["tool"], "bash");
        assert_eq!(back.context["trust_level"], 0.5);
        assert_eq!(back.metadata.get("adapter").unwrap(), "hooks");
    }

    #[test]
    fn evaluate_response_serde_roundtrip() {
        let resp = EvaluateResponse {
            request_id: "req-789".to_string(),
            verdict: "MODIFY".to_string(),
            reason: "content sanitized".to_string(),
            modified_payload: Some(serde_json::json!({"sanitized": true})),
            warnings: vec![serde_json::json!({"level": "low", "message": "minor issue"})],
        };

        let json = serde_json::to_string(&resp).unwrap();
        let back: EvaluateResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(back.verdict, "MODIFY");
        assert_eq!(back.reason, "content sanitized");
        assert!(back.modified_payload.is_some());
        assert_eq!(back.warnings.len(), 1);
    }

    #[test]
    fn evaluate_response_without_modified_payload() {
        let resp = EvaluateResponse {
            request_id: "req-abc".to_string(),
            verdict: "PERMIT".to_string(),
            reason: "looks fine".to_string(),
            modified_payload: None,
            warnings: Vec::new(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let back: EvaluateResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(back.modified_payload, None);
        assert!(back.warnings.is_empty());
    }

    #[test]
    fn log_ack_serde_roundtrip() {
        let ack = LogAck {
            events_received: 42,
        };
        let json = serde_json::to_string(&ack).unwrap();
        let back: LogAck = serde_json::from_str(&json).unwrap();
        assert_eq!(back.events_received, 42);
    }

    #[test]
    fn quarantine_status_serde_roundtrip() {
        let status = QuarantineStatus {
            id: "q-001".to_string(),
            state: "pending".to_string(),
            reviewer: None,
            reason: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: QuarantineStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "q-001");
        assert_eq!(back.state, "pending");
        assert_eq!(back.reviewer, None);
    }

    #[test]
    fn quarantine_resolution_serde_roundtrip() {
        let res = QuarantineResolution {
            id: "q-001".to_string(),
            approved: true,
            reviewer: "admin@example.com".to_string(),
            reason: "content is safe".to_string(),
        };
        let json = serde_json::to_string(&res).unwrap();
        let back: QuarantineResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "q-001");
        assert!(back.approved);
        assert_eq!(back.reviewer, "admin@example.com");
    }

    // ---------------------------------------------------------------
    // NoopTransport tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn noop_transport_log_events() {
        let transport = NoopTransport;
        let events = vec![make_test_event("evt-1"), make_test_event("evt-2")];
        let ack = transport.log_events(events).await.unwrap();
        assert_eq!(ack.events_received, 2);
    }

    #[tokio::test]
    async fn noop_transport_log_events_empty() {
        let transport = NoopTransport;
        let ack = transport.log_events(Vec::new()).await.unwrap();
        assert_eq!(ack.events_received, 0);
    }

    #[tokio::test]
    async fn noop_transport_evaluate_input() {
        let transport = NoopTransport;
        let req = make_test_evaluate_request("req-1", "input");
        let resp = transport.evaluate_input(req).await.unwrap();
        assert_eq!(resp.request_id, "req-1");
        assert_eq!(resp.verdict, "PERMIT");
        assert!(resp.modified_payload.is_none());
    }

    #[tokio::test]
    async fn noop_transport_evaluate_output() {
        let transport = NoopTransport;
        let req = make_test_evaluate_request("req-2", "output");
        let resp = transport.evaluate_output(req).await.unwrap();
        assert_eq!(resp.request_id, "req-2");
        assert_eq!(resp.verdict, "PERMIT");
    }

    #[tokio::test]
    async fn noop_transport_quarantine_status() {
        let transport = NoopTransport;
        let status = transport.get_quarantine_status("q-99").await.unwrap();
        assert_eq!(status.id, "q-99");
        assert_eq!(status.state, "pending");
    }

    #[tokio::test]
    async fn noop_transport_resolve_quarantine_approved() {
        let transport = NoopTransport;
        let resolution = QuarantineResolution {
            id: "q-99".to_string(),
            approved: true,
            reviewer: "admin".to_string(),
            reason: "safe content".to_string(),
        };
        let status = transport.resolve_quarantine(resolution).await.unwrap();
        assert_eq!(status.state, "approved");
        assert_eq!(status.reviewer, Some("admin".to_string()));
    }

    #[tokio::test]
    async fn noop_transport_resolve_quarantine_denied() {
        let transport = NoopTransport;
        let resolution = QuarantineResolution {
            id: "q-100".to_string(),
            approved: false,
            reviewer: "moderator".to_string(),
            reason: "harmful content".to_string(),
        };
        let status = transport.resolve_quarantine(resolution).await.unwrap();
        assert_eq!(status.state, "denied");
        assert_eq!(status.reason, Some("harmful content".to_string()));
    }

    // ---------------------------------------------------------------
    // HttpTransport construction tests
    // ---------------------------------------------------------------

    #[test]
    fn http_transport_construction() {
        let transport = HttpTransport::new("http://localhost:9090");
        assert_eq!(transport.base_url(), "http://localhost:9090");
    }

    #[test]
    fn http_transport_strips_trailing_slash() {
        let transport = HttpTransport::new("http://localhost:9090/");
        assert_eq!(transport.base_url(), "http://localhost:9090");
    }

    #[test]
    fn http_transport_strips_multiple_trailing_slashes() {
        let transport = HttpTransport::new("http://localhost:9090///");
        assert_eq!(transport.base_url(), "http://localhost:9090");
    }

    // ---------------------------------------------------------------
    // EvalServerLogger tests (with mock transport)
    // ---------------------------------------------------------------

    /// A mock transport that records all log events it receives.
    struct MockTransport {
        received_events: Arc<Mutex<Vec<LogEvent>>>,
    }

    impl MockTransport {
        fn new() -> (Self, Arc<Mutex<Vec<LogEvent>>>) {
            let events = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    received_events: Arc::clone(&events),
                },
                events,
            )
        }
    }

    #[async_trait]
    impl EvalTransport for MockTransport {
        async fn log_events(&self, events: Vec<LogEvent>) -> Result<LogAck, GuardError> {
            let count = events.len() as i64;
            self.received_events.lock().unwrap().extend(events);
            Ok(LogAck {
                events_received: count,
            })
        }

        async fn evaluate_input(
            &self,
            req: EvaluateRequest,
        ) -> Result<EvaluateResponse, GuardError> {
            Ok(EvaluateResponse {
                request_id: req.request_id,
                verdict: "PERMIT".to_string(),
                reason: "mock".to_string(),
                modified_payload: None,
                warnings: Vec::new(),
            })
        }

        async fn evaluate_output(
            &self,
            req: EvaluateRequest,
        ) -> Result<EvaluateResponse, GuardError> {
            Ok(EvaluateResponse {
                request_id: req.request_id,
                verdict: "PERMIT".to_string(),
                reason: "mock".to_string(),
                modified_payload: None,
                warnings: Vec::new(),
            })
        }

        async fn get_quarantine_status(
            &self,
            id: &str,
        ) -> Result<QuarantineStatus, GuardError> {
            Ok(QuarantineStatus {
                id: id.to_string(),
                state: "pending".to_string(),
                reviewer: None,
                reason: None,
            })
        }

        async fn resolve_quarantine(
            &self,
            resolution: QuarantineResolution,
        ) -> Result<QuarantineStatus, GuardError> {
            Ok(QuarantineStatus {
                id: resolution.id,
                state: "resolved".to_string(),
                reviewer: Some(resolution.reviewer),
                reason: Some(resolution.reason),
            })
        }
    }

    #[tokio::test]
    async fn logger_enqueue_and_flush() {
        let (mock, received) = MockTransport::new();
        let transport: Arc<dyn EvalTransport> = Arc::new(mock);
        let logger = EvalServerLogger::new(Arc::clone(&transport));

        // Enqueue a few events.
        for i in 0..5 {
            logger.log_event(make_test_event(&format!("evt-{i}")));
        }

        // Give the background task time to flush (flush interval is 100ms).
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let events = received.lock().unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].event_id, "evt-0");
        assert_eq!(events[4].event_id, "evt-4");
    }

    #[tokio::test]
    async fn logger_batch_flush_at_capacity() {
        let (mock, received) = MockTransport::new();
        let transport: Arc<dyn EvalTransport> = Arc::new(mock);
        let logger = EvalServerLogger::new(Arc::clone(&transport));

        // Enqueue exactly 64 events to trigger a batch flush.
        for i in 0..64 {
            logger.log_event(make_test_event(&format!("batch-{i}")));
        }

        // The batch-size flush should happen quickly, no need to wait
        // for the timer. But give a small window for the async task.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let events = received.lock().unwrap();
        assert_eq!(events.len(), 64);
    }

    #[tokio::test]
    async fn logger_flush_on_drop() {
        let (mock, received) = MockTransport::new();
        let transport: Arc<dyn EvalTransport> = Arc::new(mock);
        let logger = EvalServerLogger::new(Arc::clone(&transport));

        logger.log_event(make_test_event("drop-evt"));

        // Drop the logger, which drops the sender, which closes the channel.
        // The background task should flush remaining events.
        drop(logger);

        // Give the background task time to notice the channel close and flush.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let events = received.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "drop-evt");
    }

    #[tokio::test]
    async fn logger_handles_empty_gracefully() {
        let (mock, received) = MockTransport::new();
        let transport: Arc<dyn EvalTransport> = Arc::new(mock);
        let _logger = EvalServerLogger::new(Arc::clone(&transport));

        // Don't enqueue anything. Wait for a flush interval.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let events = received.lock().unwrap();
        assert!(events.is_empty());
    }

    // ---------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------

    fn make_test_event(id: &str) -> LogEvent {
        LogEvent {
            event_id: id.to_string(),
            event_type: "test".to_string(),
            request_id: "req-test".to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            payload_summary: "test payload".to_string(),
            verdict: None,
            metadata: HashMap::new(),
        }
    }

    fn make_test_evaluate_request(id: &str, layer: &str) -> EvaluateRequest {
        EvaluateRequest {
            request_id: id.to_string(),
            layer: layer.to_string(),
            payload: serde_json::json!({"test": true}),
            context: serde_json::json!({}),
            metadata: HashMap::new(),
        }
    }
}
