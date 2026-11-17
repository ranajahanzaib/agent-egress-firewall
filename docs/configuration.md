# Configuration Guide

AEGF is configured through YAML files and environment variable overrides.

## Example Configuration

```yaml
server:
  listen: "127.0.0.1:8080"
  read_timeout: 30s
  write_timeout: 60s
  idle_timeout: 90s
  shutdown_timeout: 15s
  max_body_size_bytes: 10485760 # 10MB
  max_concurrency: 500
  inference_timeout: 5s

inference:
  address: "127.0.0.1:50051"
  timeout: 5s
  enable_ml: true
  enable_patterns: true
  min_confidence: 0.60
  max_spans_per_field: 100

vault:
  enabled: true
  db_path: "vault.db"
  master_key: "" # Or provide via AEGF_VAULT_KEY env var
  key_file: "vault.key"
  retention: "30d"

audit:
  enabled: true
  db_path: "audit.db"
  retention: "90d"

routes:
  - id: openai
    match:
      path_prefix: /openai
    upstream: https://api.openai.com
    strip_prefix: true
    policy: strict-ai-egress
    inspect_headers:
      - X-User-Identity
```

## Environment Variable Overrides

| Variable                 | Target Config Field | Description                                       |
| ------------------------ | ------------------- | ------------------------------------------------- |
| `AEGF_SERVER_LISTEN`     | `server.listen`     | Host and port to bind proxy HTTP server           |
| `AEGF_INFERENCE_ADDRESS` | `inference.address` | Host and port of the Rust gRPC engine             |
| `AEGF_VAULT_KEY`         | `vault.master_key`  | Hex-encoded 32-byte AES-256 master encryption key |
| `AEGF_VAULT_DB`          | `vault.db_path`     | Filepath for vault SQLite database                |
| `AEGF_AUDIT_DB`          | `audit.db_path`     | Filepath for audit SQLite database                |
