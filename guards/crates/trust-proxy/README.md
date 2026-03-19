# trust-proxy

A sidecar reverse proxy that enforces trust framework guard evaluation on all traffic between an AI agent and its external endpoints. Analogous to Istio/Envoy for service meshes, but purpose-built for AI agent security.

## How It Works

```
                    trust-proxy (sidecar)
                    ┌──────────────────────────────┐
User/Channel ──▶   │  Inbound  ──▶  InputGuards    │
                    │                               │
Agent ──HTTP/WS──▶ │  Outbound ──▶  OutputGuards   │ ──▶  Real API / Tool Endpoints
                    │                               │
                    │  Deny   → 403 + reason        │
                    │  Quarantine → 202 + tickets   │
                    │  Modify → forward modified    │
                    │  Permit → forward as-is       │
                    └──────────────────────────────┘
```

The agent sees the proxy as its upstream API. The proxy:

1. Receives outbound requests from the agent (tool calls, LLM API calls)
2. Evaluates through **OutputGuards** — is the agent allowed to make this call?
3. Forwards permitted requests to the real upstream
4. Evaluates the response through **InputGuards** — is this response safe to return?
5. Returns the response (or blocks it)

The agent **cannot bypass or modify** the proxy because it runs as a separate process at a network boundary.

## Three Modes

### `generic` — Any Tool-Using Agent

Protocol-agnostic HTTP/WebSocket reverse proxy. Treats every request body as opaque JSON, evaluates it through guards, and forwards to the upstream. No domain-specific parsing.

Best for: Python agents, custom agents, LangChain/LlamaIndex pipelines, or any agent that makes HTTP calls to LLM APIs and tools.

```bash
trust-proxy generic --listen 127.0.0.1:8080 --upstream https://api.openai.com
```

Then configure the agent to use `http://127.0.0.1:8080` instead of `https://api.openai.com`:

```bash
# Python agent using OpenAI SDK
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
python my_agent.py

# Or any HTTP client
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}'
```

WebSocket connections are also proxied — the proxy upgrades the connection and evaluates each frame through guards.

### `openclaw` — OpenClaw (TypeScript)

Understands [OpenClaw](https://github.com/openclaw/openclaw)'s WebSocket protocol and provides richer guard payloads with OpenClaw-specific fields.

OpenClaw uses a WebSocket-based control plane with three message types:
- **Requests**: `{type:"req", id, method, params}` — agent actions
- **Responses**: `{type:"res", id, ok, payload|error}` — gateway replies
- **Events**: `{type:"event", event, payload}` — async notifications

The proxy classifies messages by type and method:

| Message | Direction | Guard Layer | Fields Extracted |
|---------|-----------|-------------|------------------|
| `req` with `tools/invoke` | Agent → Gateway | OutputGuards | `tool_name`, `tool_type`, `session_id` |
| `req` with `sessions_send` | Agent → Gateway | OutputGuards | `session_id`, content |
| `res` (any) | Gateway → Agent | InputGuards | Full response payload |
| `event` (any) | Gateway → Agent | InputGuards | `event_type`, `session_id` |
| Connect frame | Agent → Gateway | Pass-through | — |

```bash
# Start the proxy in front of the OpenClaw gateway
trust-proxy openclaw --listen 127.0.0.1:8080 --upstream ws://localhost:18789

# Then point OpenClaw clients at the proxy instead of the gateway
# e.g., in client config: gateway_url = "ws://127.0.0.1:8080"
```

The method names mirror OpenClaw's [PRISM security hooks](https://arxiv.org/html/2603.11853v1):
- `message_ingress` — user messages entering the system (InputGuards)
- `before_tool_call` — tool invocations leaving the system (OutputGuards)
- `message_egress` — assistant responses leaving the system (OutputGuards)

### `ironclaw` — IronClaw (Rust)

Understands [IronClaw](https://github.com/nearai/ironclaw)'s HTTP tool execution API and classifies requests by URL path.

IronClaw's tool execution pipeline is: Allowlist → Leak Scan → Credential Inject → Execute → Response Leak Scan. The trust-proxy sits **before** this pipeline, adding guard evaluation as an additional layer.

| URL Pattern | Direction | Guard Layer | Fields Extracted |
|-------------|-----------|-------------|------------------|
| `POST /tools/*` | Agent → Tool | OutputGuards | `tool_name`, `arguments`, `execution_id` |
| `POST /sandbox/*` | Agent → Sandbox | OutputGuards | `tool_name`, `sandbox=true` |
| `POST /channels/*/send` | Agent → User | OutputGuards | `channel_id`, `content`, `direction=outbound` |
| `POST /channels/*/receive` | User → Agent | InputGuards | `channel_id`, `content`, `direction=inbound` |
| `POST /webhook/*` | External → Agent | InputGuards | `channel_id`, `content` |
| Other paths | — | Generic eval | Full request body |

Tool execution requests are fully round-tripped: OutputGuards evaluate the request, then InputGuards evaluate the tool's response before it reaches the agent.

```bash
# Start the proxy in front of IronClaw's HTTP API
trust-proxy ironclaw --listen 127.0.0.1:8080 --upstream http://localhost:3000

# Configure IronClaw to route tool/channel calls through the proxy
```

## Deployment

### Without Containerization

The simplest deployment: run the proxy as a local process and configure the agent to use it.

**1. Start the proxy:**

```bash
trust-proxy generic --listen 127.0.0.1:8080 --upstream https://api.openai.com
```

**2. Configure the agent to route through the proxy:**

Most AI SDKs support base URL configuration via environment variables:

```bash
# OpenAI SDK (Python/Node)
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1

# Anthropic SDK
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080

# Generic HTTP proxy (for agents that use reqwest/requests/fetch)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

**3. (Optional) Restrict direct network access:**

On macOS, use `pf` (packet filter) to block the agent from bypassing the proxy:

```bash
# Block the agent process from reaching external APIs directly
# (the proxy process itself is not affected)
echo "block out quick proto tcp from any to any port 443 user _agent_user" | sudo pfctl -ef -
```

On Linux, use `iptables`:

```bash
# Only allow outbound HTTPS from the proxy process (by UID)
iptables -A OUTPUT -p tcp --dport 443 -m owner --uid-owner agent_user -j DROP
```

This ensures the agent *must* go through the proxy — it cannot bypass the guards by making direct connections.

### With Docker

Docker provides stronger isolation through network policies.

**docker-compose.yml:**

```yaml
services:
  trust-proxy:
    build: ./guards/crates/trust-proxy
    ports:
      - "8080:8080"
    command: generic --listen 0.0.0.0:8080 --upstream https://api.openai.com
    networks:
      - external   # Can reach the real API
      - internal   # Shared with the agent

  agent:
    build: ./my-agent
    environment:
      - OPENAI_BASE_URL=http://trust-proxy:8080/v1
    networks:
      - internal   # Can ONLY reach trust-proxy, not the external API
    depends_on:
      - trust-proxy

networks:
  external:
    driver: bridge
  internal:
    driver: bridge
    internal: true  # No outbound internet access
```

The `internal: true` network flag ensures the agent container has no direct internet access — all traffic must flow through `trust-proxy`.

**Dockerfile for trust-proxy:**

```dockerfile
FROM rust:1.83 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p trust-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/guards/target/release/trust-proxy /usr/local/bin/
ENTRYPOINT ["trust-proxy"]
```

### With Docker — OpenClaw

```yaml
services:
  trust-proxy:
    image: trust-proxy:latest
    command: openclaw --listen 0.0.0.0:8080 --upstream ws://openclaw-gateway:18789
    networks:
      - external
      - internal

  openclaw-gateway:
    image: openclaw/openclaw:latest
    networks:
      - external  # Needs internet for LLM APIs
      - gateway   # Private network with proxy

  openclaw-client:
    # Your OpenClaw client, pointed at the proxy
    environment:
      - OPENCLAW_GATEWAY_URL=ws://trust-proxy:8080
    networks:
      - internal  # Can only reach the proxy

networks:
  external:
    driver: bridge
  internal:
    driver: bridge
    internal: true
  gateway:
    driver: bridge
    internal: true
```

### With Docker — IronClaw

```yaml
services:
  trust-proxy:
    image: trust-proxy:latest
    command: ironclaw --listen 0.0.0.0:8080 --upstream http://ironclaw:3000
    networks:
      - external
      - internal

  ironclaw:
    image: nearai/ironclaw:latest
    networks:
      - external  # Needs internet for LLM providers
      - backend   # Private network with proxy

  app:
    # Your application calling IronClaw through the proxy
    environment:
      - IRONCLAW_API_URL=http://trust-proxy:8080
    networks:
      - internal

networks:
  external:
    driver: bridge
  internal:
    driver: bridge
    internal: true
  backend:
    driver: bridge
    internal: true
```

### With Kubernetes

Deploy trust-proxy as a sidecar container in the same pod as the agent:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent-with-guard
spec:
  containers:
    - name: trust-proxy
      image: trust-proxy:latest
      args: ["generic", "--listen", "0.0.0.0:8080", "--upstream", "https://api.openai.com"]
      ports:
        - containerPort: 8080

    - name: agent
      image: my-agent:latest
      env:
        - name: OPENAI_BASE_URL
          value: "http://localhost:8080/v1"

  # NetworkPolicy restricts the agent container from direct egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress-only-via-proxy
spec:
  podSelector:
    matchLabels:
      app: agent-with-guard
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector: {}  # Allow intra-pod (localhost) traffic
    - ports:
        - port: 53         # Allow DNS
          protocol: UDP
```

## Verdict Handling

All three modes handle guard verdicts consistently:

| Verdict | HTTP Response | WebSocket Behavior |
|---------|---------------|-------------------|
| **Permit** | Forward request/response as-is | Forward frame |
| **Modify** | Forward with modified payload | Forward modified frame |
| **Escalate** | Forward as-is (logged for review) | Forward frame |
| **Quarantine** | `202 Accepted` with ticket IDs | Drop frame, log warning |
| **Deny** | `403 Forbidden` with reason | Drop frame, log warning |

## Guard Configuration

The proxy supports three evaluation modes, controlled by the `--guards-config` and `--trust-server` flags. Both flags are optional and can be combined.

### Local guards via config file

Use `--guards-config` to load guards from a TOML file. Guards run in-process within the proxy.

**guards.toml:**

```toml
# Input guards — evaluate inbound responses before they reach the agent
[[input_guards]]
name = "prompt-bonk"
priority = 200  # optional, overrides default

[input_guards.config]
threshold = 0.5
fast = true
# binary_path = "/usr/local/bin/prompt-bonk"  # optional

# Output guards — evaluate outbound requests before they leave the agent
[[output_guards]]
name = "file-sharing"
```

```bash
trust-proxy generic \
  --listen 127.0.0.1:8080 \
  --upstream https://api.openai.com \
  --guards-config guards.toml
```

**Available guards:**

| Name | Layer | Config Fields |
|------|-------|---------------|
| `prompt-bonk` | Input or Output | `threshold` (float, default 0.5), `fast` (bool), `binary_path` (string) |
| `file-sharing` | Output | (none) |

### Remote trust server

Use `--trust-server` to delegate evaluation to a centralized trust server. The proxy sends payloads to the server's `/v1/evaluate/input` and `/v1/evaluate/output` endpoints and acts on the returned verdicts.

```bash
trust-proxy generic \
  --listen 127.0.0.1:8080 \
  --upstream https://api.openai.com \
  --trust-server http://trust-server:9090
```

This is the recommended model for centralized deployments: configure guards once on the trust server, and all proxies enforce them automatically.

### Combined: local guards + remote trust server

When both flags are provided, local guards run first, then the remote trust server is called. The **strictest verdict wins** (highest precedence: Deny > Quarantine > Escalate > Modify > Permit).

```bash
trust-proxy generic \
  --listen 127.0.0.1:8080 \
  --upstream https://api.openai.com \
  --guards-config guards.toml \
  --trust-server http://trust-server:9090
```

This is useful for layered defense: fast local guards (e.g. prompt injection scanning) catch obvious threats immediately, while the trust server runs more sophisticated policy evaluation.

### No configuration

Without either flag, the proxy starts with empty guard pipelines — all traffic is permitted. This is useful for testing the proxy as a passthrough.

All three flags work identically across `generic`, `openclaw`, and `ironclaw` modes.
