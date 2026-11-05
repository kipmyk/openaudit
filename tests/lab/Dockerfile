# Disposable Ubuntu 24.04 lab image for OpenAudit detection validation.
#
# This image is ONLY for local, throwaway containers. Scenarios deliberately
# weaken its configuration. Never apply these scenarios to a real host.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server nftables iptables ufw sudo python3 passwd \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged accounts used by scenarios.
RUN useradd -m -s /bin/bash auditor \
    && useradd -m -s /bin/bash alice

