.PHONY: all build build-go build-rust test test-go test-rust test-integration lint fmt proto models run docker-build docker-up docker-down clean eval

all: build test

build: build-go build-rust

build-go:
	@echo "Building Go gateway binary (bin/aegf)..."
	@mkdir -p bin
	go build -o bin/aegf ./cmd/aegf

build-rust:
	@echo "Building Rust inference binary (bin/aegf-inference)..."
	@mkdir -p bin
	cd inference && cargo build --release && cp target/release/aegf-inference ../bin/

proto:
	@echo "Compiling Protocol Buffer bindings for Go and Rust..."
	@mkdir -p internal/inspection/pb inference/proto
	cp proto/inference.proto inference/proto/inference.proto
	export PATH="$$HOME/go/bin:$$PATH" && protoc --proto_path=proto \
		--go_out=internal/inspection/pb --go_opt=paths=source_relative \
		--go-grpc_out=internal/inspection/pb --go-grpc_opt=paths=source_relative \
		proto/inference.proto

test: test-go test-rust test-integration

test-go:
	@echo "Running Go unit tests..."
	go test -v ./internal/...

test-rust:
	@echo "Running Rust unit tests..."
	cd inference && cargo test

test-integration:
	@echo "Running End-to-End integration test suite..."
	go test -v -race ./tests/integration/...

eval:
	@echo "Running Detection & Quality evaluation benchmark..."
	go run scripts/evaluate.go

models:
	@echo "Downloading default GLiNER ONNX model assets..."
	python3 scripts/download_model.py

lint:
	@echo "Running static analysis..."
	go vet ./...
	cd inference && cargo clippy -- -D warnings

fmt:
	@echo "Formatting Go and Rust codebases..."
	go fmt ./...
	cd inference && cargo fmt

run: build
	@echo "Running AEGF demonstration..."
	./scripts/demo.sh

docker-build:
	@echo "Building Docker images..."
	docker compose build

docker-up:
	@echo "Starting containerized stack..."
	docker compose up -d

docker-down:
	@echo "Stopping containerized stack..."
	docker compose down

clean:
	@echo "Cleaning build artifacts and temporary databases..."
	rm -rf bin/ target/ inference/target/ *.db *.db-shm *.db-wal run/
