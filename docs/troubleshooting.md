# Troubleshooting Guide

## Diagnostic Tool: `aegf doctor`

Run `aegf doctor` to diagnose configuration, inference connectivity, and storage permissions:

```bash
aegf doctor --config configs/config.example.yaml
```

Output checks:

1. Configuration YAML syntax and semantic validation
2. Go runtime availability
3. SQLite directory write permissions
4. Vault master key configuration
5. GLiNER ONNX model files existence
6. Rust gRPC connectivity and model status
7. Policy engine preflight
8. Open-proxy protection status

## Common Issues & Resolutions

### 1. `Inference Service: OFFLINE (context deadline exceeded)`

- Ensure `aegf-inference` is running on the address configured in `inference.address` (default `127.0.0.1:50051`).
- Verify model files exist in `models/gliner-small/`.

### 2. `HTTP 403 Egress Blocked by Policy`

- Check `audit.db` via `aegf audit list` to inspect which sensitive category triggered the block.
- For legitimate credentials intended for a specific provider, configure a destination-scoped exception in `policies[].exceptions`.

### 3. `HTTP 502 Security Inference Unavailable`

- Strict policies fail closed when the inference service is offline.
- Inspect inference logs: `RUST_LOG=info ./bin/aegf-inference`.
