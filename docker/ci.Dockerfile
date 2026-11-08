# Shared Ubuntu 24.04 Linux CI environment for OpenAudit
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    CARGO_TERM_COLOR=always

# Install build essentials, SSL libraries, and swtpm for TPM integration tests
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    libssl-dev \
    pkg-config \
    swtpm \
    swtpm-tools \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Install Rust stable with rustfmt and clippy components
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile default \
    --component rustfmt \
    --component clippy

# Install cargo-audit for dependency security audits
RUN cargo install cargo-audit --locked

WORKDIR /workspace

CMD ["/bin/bash"]

