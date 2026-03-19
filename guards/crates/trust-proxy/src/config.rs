use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use guard_core::OperatingContext;
use url::Url;

/// Trust Framework sidecar proxy.
///
/// Sits between an AI agent and its external endpoints, evaluating all
/// traffic through the guard pipeline before forwarding.
#[derive(Debug, Parser)]
#[command(name = "trust-proxy", version)]
pub struct Cli {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Debug, Subcommand)]
pub enum Mode {
    /// Generic agent proxy — protocol-agnostic HTTP/WS reverse proxy.
    Generic {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// Upstream URL to forward permitted requests to.
        #[arg(long)]
        upstream: Url,
        /// Trust server URL for remote guard evaluation.
        #[arg(long)]
        trust_server: Option<Url>,
        /// Path to a TOML file declaring local guards to load.
        #[arg(long)]
        guards_config: Option<PathBuf>,
    },
    /// OpenClaw proxy — understands OpenClaw's WebSocket message protocol.
    Openclaw {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// OpenClaw gateway WebSocket URL (e.g. ws://localhost:18789).
        #[arg(long)]
        upstream: Url,
        /// Trust server URL for remote guard evaluation.
        #[arg(long)]
        trust_server: Option<Url>,
        /// Path to a TOML file declaring local guards to load.
        #[arg(long)]
        guards_config: Option<PathBuf>,
    },
    /// IronClaw proxy — understands IronClaw's HTTP tool execution API.
    Ironclaw {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// IronClaw HTTP API URL.
        #[arg(long)]
        upstream: Url,
        /// Trust server URL for remote guard evaluation.
        #[arg(long)]
        trust_server: Option<Url>,
        /// Path to a TOML file declaring local guards to load.
        #[arg(long)]
        guards_config: Option<PathBuf>,
    },
}

/// Resolved configuration for the proxy server.
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub upstream_url: Url,
    /// When set, guards also execute on a remote trust server.
    pub trust_server_url: Option<Url>,
    /// Path to a TOML guards config file.
    pub guards_config: Option<PathBuf>,
    pub operating_context: OperatingContext,
}

impl ProxyConfig {
    pub fn from_mode(mode: &Mode) -> Self {
        let (listen_addr, upstream_url, trust_server, guards_config) = match mode {
            Mode::Generic {
                listen,
                upstream,
                trust_server,
                guards_config,
            } => (*listen, upstream.clone(), trust_server.clone(), guards_config.clone()),
            Mode::Openclaw {
                listen,
                upstream,
                trust_server,
                guards_config,
            } => (*listen, upstream.clone(), trust_server.clone(), guards_config.clone()),
            Mode::Ironclaw {
                listen,
                upstream,
                trust_server,
                guards_config,
            } => (*listen, upstream.clone(), trust_server.clone(), guards_config.clone()),
        };
        Self {
            listen_addr,
            upstream_url,
            trust_server_url: trust_server,
            guards_config,
            operating_context: OperatingContext::default(),
        }
    }
}
