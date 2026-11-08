# Debian 13 (Trixie) verification environment for OpenAudit M3.2
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    CARGO_TERM_COLOR=always

# Install core build dependencies, SSL, swtpm, and utilities
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
    nftables \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Install Rust stable minimal toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile minimal

WORKDIR /workspace

CMD ["/bin/bash"]

