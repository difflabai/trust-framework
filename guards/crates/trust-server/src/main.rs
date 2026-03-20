use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use guard_adapters::guard_factory;
use guard_adapters::GuardBuildRequest;
use guard_adapters::server::{
    AdjudicateRequest, EvalRequest, EvalServerHandler, QuarantineResolveRequest,
};
use guard_core::error::GuardError;

#[derive(Parser)]
#[command(name = "trust-server", about = "Trust-framework evaluation server")]
struct Cli {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:9090")]
    listen: String,

    /// Path to guards TOML configuration file.
    #[arg(long)]
    guards_config: PathBuf,

    /// Enable behavior adjudicator endpoints.
    #[arg(long)]
    adjudicator: bool,
}

type AppState = Arc<EvalServerHandler>;

/// Centralized error type for axum handlers that maps `GuardError` variants
/// to appropriate HTTP status codes.
struct AppError(GuardError);

impl From<GuardError> for AppError {
    fn from(inner: GuardError) -> Self {
        Self(inner)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self.0 {
            GuardError::QuarantineNotFound(id) => {
                (StatusCode::NOT_FOUND, format!("Quarantine ticket not found: {id}"))
            }
            GuardError::QuarantineAlreadyResolved(id) => {
                (StatusCode::CONFLICT, format!("Quarantine ticket already resolved: {id}"))
            }
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        (status, message).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("trust_server=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!("loading guards from {}", cli.guards_config.display());
    let guards_config = guard_factory::load_config(&cli.guards_config)?;
    let (input_guards, output_guards) = guard_factory::build_pipelines(&guards_config)?;
    tracing::info!(
        "loaded {} input guard(s), {} output guard(s)",
        guards_config.input_guards.len(),
        guards_config.output_guards.len()
    );

    let handler = if cli.adjudicator {
        tracing::info!("adjudicator enabled");
        let adj = Arc::new(adjudicator::BehaviorAdjudicator::default());
        EvalServerHandler::with_adjudicator(input_guards, output_guards, None, adj)
    } else {
        EvalServerHandler::new(input_guards, output_guards, None)
    };

    let state: AppState = Arc::new(handler);

    let app = Router::new()
        .route("/v1/evaluate/input", post(evaluate_input))
        .route("/v1/evaluate/output", post(evaluate_output))
        .route("/v1/adjudicate", post(adjudicate))
        .route("/v1/quarantine/{id}", get(get_quarantine))
        .route("/v1/quarantine/{id}", post(resolve_quarantine))
        .route("/v1/guards/build", post(build_guard))
        .route("/health", get(health))
        .with_state(state);

    tracing::info!("trust-server listening on {}", cli.listen);
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn evaluate_input(
    State(handler): State<AppState>,
    Json(request): Json<EvalRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resp = handler.evaluate_input(request).await?;
    Ok(Json(resp))
}

async fn evaluate_output(
    State(handler): State<AppState>,
    Json(request): Json<EvalRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resp = handler.evaluate_output(request).await?;
    Ok(Json(resp))
}

async fn adjudicate(
    State(handler): State<AppState>,
    Json(request): Json<AdjudicateRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resp = handler.adjudicate(request).await?;
    Ok(Json(resp))
}

async fn get_quarantine(
    State(handler): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let resp = handler.get_quarantine(&id).await?;
    Ok(Json(resp))
}

async fn resolve_quarantine(
    State(handler): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<QuarantineResolveRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resp = handler.resolve_quarantine(&id, request).await?;
    Ok(Json(resp))
}

async fn build_guard(
    State(handler): State<AppState>,
    Json(request): Json<GuardBuildRequest>,
) -> Result<impl IntoResponse, AppError> {
    let resp = handler.build_guard(request)?;
    Ok(Json(resp))
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}
