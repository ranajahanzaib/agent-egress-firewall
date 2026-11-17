# Multi-Stage Build for Agent Egress Firewall (AEGF)

# -------------------------------------------------------------
# Stage 1: Rust Inference Engine Builder (Ubuntu 24.04 with glibc >= 2.38)
# -------------------------------------------------------------
FROM rust:latest AS rust-toolchain

FROM ubuntu:24.04 AS rust-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    protobuf-compiler \
    libprotobuf-dev \
    cmake \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
ENV PATH="/usr/local/cargo/bin:${PATH}"
ENV RUSTUP_HOME="/usr/local/rustup"
ENV CARGO_HOME="/usr/local/cargo"

WORKDIR /build/inference
COPY proto /build/proto
COPY inference /build/inference

RUN cargo build --release

# -------------------------------------------------------------
# Stage 2: Go Gateway Builder
# -------------------------------------------------------------
FROM golang:1.24-bookworm AS go-builder

ENV GOTOOLCHAIN=auto

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY proto ./proto
COPY internal ./internal
COPY cmd ./cmd

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /build/bin/aegf ./cmd/aegf

# -------------------------------------------------------------
# Stage 3: Minimal Production Runtime
# -------------------------------------------------------------
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Run as dedicated non-root user
RUN groupadd -g 10001 aegf && useradd -u 10001 -g aegf -m -s /bin/bash aegf

WORKDIR /app
RUN mkdir -p /app/data /app/models /app/configs && chown -R aegf:aegf /app

COPY --from=go-builder --chown=aegf:aegf /build/bin/aegf /app/aegf
COPY --from=rust-builder --chown=aegf:aegf /build/inference/target/release/aegf-inference /app/aegf-inference
COPY --chown=aegf:aegf configs/ /app/configs/

USER aegf

EXPOSE 8080
VOLUME ["/app/data", "/app/models"]

ENTRYPOINT ["/app/aegf"]
CMD ["serve", "--config", "/app/configs/config.example.yaml"]
