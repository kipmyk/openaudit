# Contributing to OpenAudit

Thank you for your interest in contributing to OpenAudit. We are building open-source security infrastructure designed to be reliable, transparent, and secure by default.

To maintain code quality, security rigor, and a clean Git history, please review and follow these guidelines.

---

## 1. Prerequisites and Development Setup

OpenAudit is written in Rust using the standard Cargo workspace toolchain.

- **Rust Version:** Rust stable (defined in `rust-toolchain.toml`). Install via [rustup](https://rustup.rs/):
  ```bash
  rustup show
  ```
- **Required Cargo Components:**
  ```bash
  rustup component add rustfmt clippy
  ```

---

## 2. Engineering Principles & Code Conventions

### Strict Code Quality
- **Zero Warnings:** All code must compile with zero warnings under `cargo clippy --all-targets -- -D warnings`.
- **Formatting:** Code must adhere to `cargo fmt --check`. Run `cargo fmt` before staging any changes.
- **Typed Error Handling:** Production code must avoid `.unwrap()` and `.expect()` unless handling an invariant guaranteed by local code that is explicitly documented. Use typed domain errors via `thiserror`.
- **Minimal Dependencies:** Never introduce a third-party dependency without evaluating its security profile, maintenance status, dependency tree, and whether standard library primitives or simpler alternatives suffice.
- **Data Minimization & Redaction:** Security checks and evidence capture must strictly redact sensitive information (secrets, credentials, private keys, authorization tokens) before returning findings.

### Testing Requirements
- Every new domain model, rule check, or utility must be accompanied by unit tests.
- Run the full test suite locally before pushing:
  ```bash
  cargo test
  cargo clippy --all-targets -- -D warnings
  cargo fmt --check
  ```

---

## 3. Git Conventions & Commit Discipline

We maintain a clean, meaningful, and auditable Git history.

### Commit-Per-File Policy
Whenever practical, **commit each file individually** with a focused, descriptive commit message.

- Do **not** batch unrelated modifications across multiple files into a single commit.
- Inspect the diff before committing:
  ```bash
  git diff <file>
  git add <file>
  git commit -m "<type>: <imperative summary of change>"
  ```
- If a change strictly cannot be committed separately due to tight syntactic coupling across crate boundaries, document the reason in the commit description.

### Conventional Commit Messages
Commit messages should follow standard conventional commit prefixes:

- `feat:` Introduces a new feature or domain capability.
- `fix:` Patches a bug or defect.
- `docs:` Documentation additions or updates.
- `test:` Adds or modifies unit, integration, or regression tests.
- `refactor:` Code restructuring without behavioral changes.
- `build:` Changes to Cargo manifests, toolchain, or dependencies.
- `ci:` Changes to GitHub Actions or CI pipeline configurations.
- `security:` Explicit security hardening, vulnerability mitigations, or sanitizers.
- `chore:` Maintenance tasks, gitignore updates, or housekeeping.

**Examples of good commit messages:**
- `docs: explain agent enrollment security boundaries`
- `security: reject unauthorized scan target addresses`
- `feat: add typed infrastructure asset identifiers`
- `test: verify TLS certificate expiry detection`

**Avoid vague messages:**
- ❌ `update`, `fix bug`, `changes`, `initial commit`, `wip`

---

## 4. Pull Request Workflow

1. Fork the repository and create a feature branch off `main` (e.g., `git checkout -b feature/ssh-audit-rules`).
2. Implement your changes following the one-file-per-commit discipline and code conventions.
3. Verify that all tests pass, formatting matches, and clippy passes with zero warnings.
4. Submit a Pull Request targeting `main`. Include:
   - Clear summary of the problem and proposed solution.
   - Associated issue number (if applicable).
   - Evidence of local test verification.
