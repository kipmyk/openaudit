# Multi-stage production build for OpenAudit Distributed Agent Daemon
# Milestone 8: Distributed Fleet Deployment

FROM rust:1.85-bookworm AS builder

WORKDIR /src
COPY . .

# Build openaudit-agent release binary
RUN cargo build --release -p openaudit-agent

# Hardened agent runtime stage
FROM debian:12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Run as dedicated openaudit-agent user
RUN groupadd -g 10002 openaudit && \
    useradd -u 10002 -g openaudit -s /bin/false -m openaudit

RUN mkdir -p /var/lib/openaudit-agent && chown -R openaudit:openaudit /var/lib/openaudit-agent

COPY --from=builder /src/target/release/openaudit-agent /usr/local/bin/openaudit-agent

USER openaudit
WORKDIR /var/lib/openaudit-agent

ENTRYPOINT ["openaudit-agent"]
CMD ["daemon", "--state-dir", "/var/lib/openaudit-agent"]

