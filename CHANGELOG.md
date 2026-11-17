# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-17

### Added
- **Go Egress Gateway**: Reverse proxy engine based on `net/http` and `httputil.ReverseProxy` with path-prefix routing and prefix stripping.
- **Content Extractors**: Structured extraction and traversal for `application/json` (with `json.Number` numeric precision), `application/x-www-form-urlencoded`, `text/plain`, and configured HTTP request headers.
- **Rust ML Inference Engine**: Dedicated gRPC service running quantized zero-shot GLiNER ONNX models (`nexuswho/gliner-onnx-small`) via ONNX Runtime (`ort`).
- **Dynamic Entity Taxonomy**: Runtime entity conditioning without model retraining.
- **Deterministic Detectors**: High-precision regular expressions for API keys (OpenAI, Anthropic, GitHub, AWS, Slack), PEM private keys, JWTs, IPv4/IPv6, email, phone numbers, and Luhn Mod-10 credit card validation.
- **Span Conflict Resolution**: Deterministic Unicode character offset normalization, boundary alignment, and confidence-priority deduplication.
- **Policy Engine**: Declarative YAML security policies supporting `allow`, `redact`, and `block` actions with strict precedence and destination-scoped exceptions.
- **Encrypted Redaction Vault**: AES-256-GCM authenticated encryption with 96-bit random nonces, in-memory/file key management, and SQLite storage for reversible token replacement.
- **Durable Audit Trail**: WAL-mode SQLite store capturing request metadata, decisions, latency, and entity categories with a zero-secret logging invariant.
- **CLI Management Tool (`aegf`)**: Unified operator interface supporting `serve`, `doctor`, `scan`, `policy test`, `vault`, `audit`, and `models` subcommands.
- **Streaming Response Passthrough**: Real-time flushing (`FlushInterval = -1`) for Server-Sent Events (`text/event-stream`) and chunked responses.
- **Deployment Infrastructure**: Multi-stage `Dockerfile` and `docker-compose.yml` for isolated containerized environments.
- **Continuous Integration**: GitHub Actions workflow covering Go/Rust lints, unit tests, integration tests, benchmark evaluation, and Docker builds.
