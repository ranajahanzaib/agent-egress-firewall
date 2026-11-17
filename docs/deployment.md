# Deployment Guide

AEGF is packaged for local execution and production Docker environments.

## 1. Local Development / Bare Metal

```bash
# Build both Go and Rust binaries
make build

# Start the Rust Inference Service
./bin/aegf-inference --listen 127.0.0.1:50051 --model-dir models/gliner-small &

# Start the Go Gateway Proxy
./bin/aegf serve --config configs/config.example.yaml
```

## 2. Docker & Docker Compose

Deploy with Docker Compose:

```bash
docker compose up -d
```

Compose manages two isolated services on an internal bridge network:

- `inference`: Private gRPC service (never exposed to host network)
- `gateway`: Egress proxy exposed on `8080`

Persistent volumes:

- `./data`: Stores `vault.db` and `audit.db`
- `./models`: Read-only mount for ONNX model weights
