# AEGF Architecture

`agent-egress-firewall` (`aegf`) is split into two cleanly separated services communicating over gRPC with Protocol Buffers:

```mermaid
graph TD
    Client[Application / AI Agent] -->|Outbound HTTP Request| Proxy[Go Gateway Proxy]
    Proxy -->|Match Route| Router[Routing Engine]
    Router -->|Extract JSON/Form/Text| Extractor[Content Extractor]
    Extractor -->|gRPC ScanRequest| RustEngine[Rust Detection Engine]

    subgraph Rust Detection Engine
        RustEngine --> Tokenizer[Tokenizer / Word Segmenter]
        Tokenizer --> ONNX[ONNX Runtime / GLiNER]
        RustEngine --> Patterns[Deterministic Regex & Luhn Detectors]
        ONNX --> Resolver[Conflict & Span Resolver]
        Patterns --> Resolver
    end

    Resolver -->|gRPC ScanResponse| Proxy
    Proxy -->|Evaluate Findings| Policy[Go Policy Engine]

    Policy -->|Decision: ALLOW| Upstream[Upstream Destination API]
    Policy -->|Decision: BLOCK| Reject[403 Forbidden Response]
    Policy -->|Decision: REDACT| Vault[SQLite Encrypted Vault (AES-GCM)]
    Vault -->|Mutated Payload| Upstream

    Proxy -->|Audit Event| AuditDB[(SQLite Audit Store)]
    Upstream -->|Streaming SSE / Chunks| Client
```

## Service Boundaries

| Component            | Language | Responsibilities                                                                                                                                                                  |
| -------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Egress Gateway**   | Go       | HTTP reverse proxy, routing, route prefix stripping, body extraction & limits, policy enforcement, encrypted vault storage, audit trails, operational metrics, CLI administration |
| **Inference Engine** | Rust     | GLiNER ONNX zero-shot inference, dynamic label conditioning, word segmentation, deterministic pattern detection (Regex, Luhn, JWT), Unicode-safe span normalization               |

## Protocol Buffer Contract

Communication between Go and Rust is strictly specified in `proto/inference.proto`:

- `Scan`: Analyzes text fields, evaluating dynamic entity taxonomies and regex patterns.
- `CheckHealth`: Evaluates engine operational state.
- `GetModelStatus`: Reports model load state, active device, and metadata.
