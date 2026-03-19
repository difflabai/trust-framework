mod config;
mod generic;
mod guard_eval;
mod guard_factory;
mod ironclaw;
mod openclaw;
mod proxy;

use std::sync::Arc;

use clap::Parser;
use guard_core::{GuardPipeline, InputGuards, NoopLogger, OutputGuards, PipelineConfig};

use config::{Cli, Mode, ProxyConfig};
use guard_eval::GuardEvaluator;
use proxy::ProxyState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("trust_proxy=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let config = ProxyConfig::from_mode(&cli.mode);

    // Build guard pipelines from config file, or empty pipelines.
    let (input_guards, output_guards) = if let Some(ref path) = config.guards_config {
        tracing::info!("loading guards from {}", path.display());
        let guards_config = guard_factory::load_config(path)?;
        let (input, output) = guard_factory::build_pipelines(&guards_config)?;
        tracing::info!(
            "loaded {} input guard(s), {} output guard(s)",
            guards_config.input_guards.len(),
            guards_config.output_guards.len()
        );
        (input, output)
    } else {
        let input = Arc::new(InputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        let output = Arc::new(OutputGuards::new(
            GuardPipeline::new(PipelineConfig::default()),
            Box::new(NoopLogger),
        ));
        (input, output)
    };

    // Build evaluator based on whether trust server is configured.
    let evaluator = match config.trust_server_url {
        Some(ref trust_server_url) => {
            let has_local_guards = config.guards_config.is_some();
            if has_local_guards {
                tracing::info!(
                    "using combined evaluation: local guards + remote trust server ({})",
                    trust_server_url
                );
                GuardEvaluator::combined(
                    input_guards,
                    output_guards,
                    trust_server_url.as_str(),
                    config.operating_context.clone(),
                )
            } else {
                tracing::info!("using remote guard evaluation via {}", trust_server_url);
                GuardEvaluator::remote(
                    trust_server_url.as_str(),
                    config.operating_context.clone(),
                )
            }
        }
        None => {
            if config.guards_config.is_some() {
                tracing::info!("using local guard evaluation");
            } else {
                tracing::info!(
                    "no guards configured — all traffic permitted (use --guards-config or --trust-server)"
                );
            }
            GuardEvaluator::local(input_guards, output_guards, config.operating_context.clone())
        }
    };

    let adapter_name = match &cli.mode {
        Mode::Generic { .. } => "generic-agent",
        Mode::Openclaw { .. } => "openclaw",
        Mode::Ironclaw { .. } => "ironclaw",
    };

    let state = Arc::new(ProxyState {
        evaluator,
        upstream_url: config.upstream_url,
        adapter_name: adapter_name.into(),
        http_client: reqwest::Client::new(),
    });

    let app = match &cli.mode {
        Mode::Generic { .. } => generic::router(state),
        Mode::Openclaw { .. } => openclaw::router(state),
        Mode::Ironclaw { .. } => ironclaw::router(state),
    };

    tracing::info!(
        "trust-proxy ({}) listening on {} → {}",
        adapter_name,
        config.listen_addr,
        cli.mode.upstream_url(),
    );

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

impl Mode {
    fn upstream_url(&self) -> &url::Url {
        match self {
            Mode::Generic { upstream, .. } => upstream,
            Mode::Openclaw { upstream, .. } => upstream,
            Mode::Ironclaw { upstream, .. } => upstream,
        }
    }
}
