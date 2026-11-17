# Security Policy & Threat Model

`agent-egress-firewall` (`aegf`) is dedicated security infrastructure designed to inspect outbound application and AI agent HTTP traffic to prevent accidental egress of confidential data, credentials, and personally identifiable information (PII).

---

## 1. Threat Model & Trust Boundaries

```
[ Application / AI Agent ] (Untrusted / Semi-trusted egress source)
            │  HTTP Request (Payload, Headers, Query Params)
            ▼
┌─────────────────────────────────────────────────────────────┐
│ AEGF Egress Security Gateway (Go)                           │
│  - Enforces route boundaries (Anti-Open-Proxy / SSRF)       │
│  - Extracts inspectable JSON/Text/Form content              │
│  - Enforces request body size limits                        │
└──────────────────────────┬──────────────────────────────────┘
                           │ gRPC (Local IPC / Private Network)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ AEGF Inference Engine (Rust)                                │
│  - Local GLiNER ONNX model execution (No SaaS calls)        │
│  - Deterministic regex & algorithmic detectors (Luhn, etc.) │
│  - Unicode-safe span normalization & conflict resolution    │
└──────────────────────────┬──────────────────────────────────┘
                           │ Normalized Findings
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Policy & Vault Enforcement (Go)                             │
│  - Evaluates declarative YAML security policy               │
│  - Encrypts sensitive values into local SQLite vault        │
│    (AES-256-GCM with 96-bit random nonces)                 │
│  - Injects opaque non-deterministic tokens into payload     │
│  - Fails closed on any operational or inference error       │
└──────────────────────────┬──────────────────────────────────┘
                           │ Approved / Redacted HTTP Request
                           ▼
           [ Upstream AI / External API ]
```

### Core Security Principles

1. **Local Self-Hosted Isolation:**
   Sensitive outbound traffic is inspected entirely on local compute using local ONNX Runtime inference and deterministic algorithms. No text or credentials are ever sent to an external SaaS or third-party cloud classification API.

2. **Go Owns Enforcement; Rust Owns Detection:**
   The Rust engine only identifies and scores sensitive spans; it has no network access to upstream services and can never authorize forwarding. Only the Go policy engine can authorize egress.

3. **Fail-Closed by Default:**
   If the Rust inference engine is unreachable, inference times out, the payload is malformed or oversized, or vault encryption fails, strict policies reject the outbound request immediately and never forward uninspected content.

4. **Zero-Plaintext Vault Storage:**
   All sensitive values captured for reversible redaction are encrypted with AES-256-GCM before write to SQLite. Nonces are cryptographically random per record. Plaintext sensitive content is never stored in SQLite or written to logs.

5. **Anti-Open-Proxy & Anti-SSRF:**
   The proxy strictly matches requests against pre-configured routes. Clients cannot pass arbitrary upstream destination URLs via request headers or query parameters.

---

## 2. Supported Interception Modes & Current Limitations

- **Reverse Proxy Architecture:**
  Applications configure their API client base URLs to route through the firewall (e.g. `http://firewall:8080/openai`).
- **No TLS MITM Interception:**
  Transparent forward HTTPS proxying with certificate re-signing is intentionally not implemented. Traffic must arrive as HTTP to the firewall reverse proxy.
- **Pre-Execution Request Inspection vs. Streaming Response Passthrough:**
  Outbound request bodies are fully buffered and inspected before forwarding. Upstream responses (e.g., SSE event streams) are streamed immediately to the client with unbuffered flushing.

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability in `agent-egress-firewall`, please report it responsibly:

- **Email:** `security@ranajahanzaib.com`
- **GitHub Security Advisory:** You may also report vulnerabilities privately through GitHub's Security Advisories feature.
- Please provide a detailed description of the issue, reproduction steps, affected versions, and potential exploit vectors.
- Please allow up to 48 hours for an acknowledgment before any public disclosure.
