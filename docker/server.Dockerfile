# Multi-stage production build for OpenAudit Control Plane Server
# Milestone 8: Reproducible Self-Hosted Deployment

FROM rust:1.85-bookworm AS builder

WORKDIR /src
COPY . .

# Build openaudit-server release binary
RUN cargo build --release -p openaudit-server

# Minimal hardened runtime stage
FROM debian:12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-privileged security user
RUN groupadd -g 10001 openaudit && \
    useradd -u 10001 -g openaudit -s /bin/false -m openaudit

# Prepare persistent data directory
RUN mkdir -p /data && chown -R openaudit:openaudit /data

COPY --from=builder /src/target/release/openaudit-server /usr/local/bin/openaudit-server

USER openaudit
WORKDIR /data

ENV DATA_DIR=/data \
    BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=info

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/health/ready || exit 1

ENTRYPOINT ["openaudit-server"]
CMD ["serve", "--bind", "0.0.0.0:8080", "--data-dir", "/data"]

