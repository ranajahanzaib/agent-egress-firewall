# Contributing to agent-egress-firewall

We welcome contributions of all kinds to improve `agent-egress-firewall` (`aegf`). Follow these guidelines to get started.

---

## Getting Started

1. **Fork the Repository**: Fork the repository to your personal GitHub account.
2. **Clone Your Fork**:
   ```bash
   git clone https://github.com/ranajahanzaib/agent-egress-firewall.git
   cd agent-egress-firewall
   ```
3. **Set Up the Environment**:
   - Ensure Go 1.24+ and Rust 1.85+ with `cargo` are installed.
   - Install `protobuf-compiler` (`protoc`).
   - Download local test model weights:
     ```bash
     make models
     ```

---

## Development Workflow

1. **Create a Topic Branch**:
   ```bash
   git checkout -b feature/my-feature-name
   ```

2. **Build and Test Locally**:
   ```bash
   make build      # Compiles bin/aegf and bin/aegf-inference
   make test       # Runs Go and Rust unit and integration suites
   make lint       # Runs go vet and cargo clippy
   make fmt        # Formats Go and Rust codebases
   ```

3. **Verify End-to-End**:
   ```bash
   ./scripts/demo.sh
   ```

4. **Commit Your Changes**:
   Write clear, descriptive commit messages adhering to standard conventions:
   ```bash
   git commit -m "feat(policy): add support for cidr network ranges in exceptions"
   ```

5. **Submit a Pull Request**:
   - Push your branch to GitHub:
     ```bash
     git push origin feature/my-feature-name
     ```
   - Open a Pull Request targeting `main`.
   - Provide a clear summary of changes, problem statement, and test coverage.

---

## Code Style & Testing Standards

- **Go**: Code must be formatted with `gofmt` and pass `go vet ./...` without warnings.
- **Rust**: Code must be formatted with `cargo fmt` and pass `cargo clippy -- -D warnings`.
- **Zero Secrets**: Never commit live credentials, API keys, private keys, or personal identifiers. Use synthetic test vectors (`sk-proj-...` dummy tokens, `0000...` IDs).
- **Security Invariant**: Go owns enforcement; Rust owns detection. Rust must never make routing or forwarding decisions.

---

## Community Guidelines

Please note that this project adheres to our [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold these standards.
