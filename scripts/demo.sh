#!/usr/bin/env bash
set -euo pipefail

echo "======================================================================"
echo "    AGENT EGRESS FIREWALL (AEGF) — END-TO-END DEMONSTRATION"
echo "======================================================================"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p bin run
rm -f run/demo_*.db run/demo_*.sock

echo "[+] 1. Building binaries..."
go build -o bin/aegf ./cmd/aegf
if [ ! -f bin/aegf-inference ]; then
  cd inference && cargo build --release && cp target/release/aegf-inference ../bin/ && cd ..
fi

echo "[+] 2. Starting Rust Inference Engine (GLiNER ONNX + Patterns)..."
./bin/aegf-inference --listen 127.0.0.1:50051 --model-dir models/gliner-small &
INF_PID=$!
trap "kill $INF_PID 2>/dev/null || true; kill \${GATEWAY_PID:-0} 2>/dev/null || true" EXIT

sleep 2

echo "[+] 3. Running preflight diagnostics with aegf doctor..."
./bin/aegf doctor --config configs/config.example.yaml

echo "[+] 4. Starting Gateway Proxy on 127.0.0.1:8080..."
./bin/aegf serve --config configs/config.example.yaml &
GATEWAY_PID=$!
sleep 2

echo ""
echo "======================================================================"
echo " SCENARIO A: Allowed Request"
echo "======================================================================"
echo "Sending benign query to /openai/v1/chat..."
cat examples/requests/allowed.json
echo ""
curl -s -X POST http://127.0.0.1:8080/openai/v1/chat \
  -H "Content-Type: application/json" \
  -d @examples/requests/allowed.json || true
echo ""
echo "-> Allowed request processed."

echo ""
echo "======================================================================"
echo " SCENARIO B: Redacted Personal Information"
echo "======================================================================"
echo "Sending payload with PII (customer name, email, account number)..."
cat examples/requests/customer.json
echo ""
curl -s -X POST http://127.0.0.1:8080/openai/v1/customer \
  -H "Content-Type: application/json" \
  -d @examples/requests/customer.json || true
echo ""
echo "-> Redacted payload processed and saved to encrypted vault."

echo ""
echo "======================================================================"
echo " SCENARIO C: Blocked API Credential"
echo "======================================================================"
echo "Sending prohibited API key..."
cat examples/requests/credentials.json
echo ""
curl -s -i -X POST http://127.0.0.1:8080/anthropic/v1/query \
  -H "Content-Type: application/json" \
  -d @examples/requests/credentials.json || true
echo ""
echo "-> Blocked response received (403 Forbidden). Upstream never contacted."

echo ""
echo "======================================================================"
echo " SCENARIO F: Dynamic Custom Category"
echo "======================================================================"
echo "Sending dynamic internal build ID..."
cat examples/requests/dynamic_category.json
echo ""
curl -s -i -X POST http://127.0.0.1:8080/openai/v1/build \
  -H "Content-Type: application/json" \
  -d @examples/requests/dynamic_category.json || true
echo ""

echo ""
echo "======================================================================"
echo " AUDIT TRAIL VERIFICATION"
echo "======================================================================"
./bin/aegf audit list --limit 5

echo ""
echo "======================================================================"
echo " VAULT INSPECTION & RESTORATION"
echo "======================================================================"
./bin/aegf vault list

FIRST_TOKEN=$(./bin/aegf vault list | grep -E '^Token: \[' | head -n 1 | awk '{print $2}')
if [ -n "$FIRST_TOKEN" ]; then
  echo ""
  echo "[+] Inspecting Vault Token: $FIRST_TOKEN"
  ./bin/aegf vault inspect --token "$FIRST_TOKEN"
  echo ""
  echo "[+] Demonstrating In-Place Vault Restoration:"
  echo "Input redacted text: 'Outbound request containing token $FIRST_TOKEN'"
  echo "Restored output:     '$(echo "Outbound request containing token $FIRST_TOKEN" | ./bin/aegf vault restore)'"
fi

echo ""
echo "======================================================================"
echo " DEMONSTRATION COMPLETE"
echo "======================================================================"
