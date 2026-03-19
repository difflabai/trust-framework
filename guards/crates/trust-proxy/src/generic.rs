//! Generic agent proxy mode.
//!
//! Protocol-agnostic HTTP/WebSocket reverse proxy. Treats every request
//! body as an opaque JSON payload, evaluates it through guards, and
//! forwards to the upstream. No domain-specific parsing.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use axum::routing::any;
use axum::Router;

use crate::proxy::{proxy_http_from_request, proxy_ws_from_request, ProxyState};

/// Build the axum router for generic agent proxy mode.
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
    if is_ws_upgrade(&request) {
        return proxy_ws_from_request(state, request).await;
    }
    proxy_http_from_request(state, request).await
}

fn is_ws_upgrade(request: &axum::extract::Request) -> bool {
    request
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard_eval::GuardEvaluator;
    use guard_core::{
        GuardPipeline, InputGuards, NoopLogger, OperatingContext, OutputGuards, PipelineConfig,
    };
    use url::Url;

    fn make_state() -> Arc<ProxyState> {
        let input = Arc::new(InputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let output = Arc::new(OutputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        Arc::new(ProxyState {
            evaluator: GuardEvaluator::local(input, output, OperatingContext::default()),
            upstream_url: Url::parse("http://localhost:9999").unwrap(),
            adapter_name: "generic-agent".into(),
            http_client: reqwest::Client::new(),
        })
    }

    #[test]
    fn router_builds_without_panic() {
        let state = make_state();
        let _router = router(state);
    }
}
