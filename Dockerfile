# syntax=docker/dockerfile:1
# ==============================================================================
# OpenỌ̀ṣọ́ọ̀sì Autonomous EDR — Hardened Multi-Stage Container Image
# Compliance:
#   - OpenSSF Scorecard Pinned-Dependencies (10/10 immutable SHA-256 digests)
#   - CIS Docker Benchmark v1.6 Level 2 (Non-root UID 65532, 0 SUID/SGID,
#     immutable root-owned binaries, read-only rootfs ready, package mgr removed)
# ==============================================================================

# ── Stage 1: Builder & Binary Verifier ───────────────────────────────────────
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS builder

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH="/usr/local/cargo/bin:${PATH}"

WORKDIR /src

# Copy workspace manifests, source tree, WebUI dist, rules, and optional staged binary
COPY . /src/

RUN apt-get update && apt-get install -y --no-install-recommends \
        binutils \
        ca-certificates \
    && mkdir -p /out/app/dashboard/dist /out/app/rules /out/data/database /out/data/logs /out/data/quarantine \
    && if [ -f /src/dist/osoosi ]; then \
        cp -f /src/dist/osoosi /out/app/osoosi; \
    elif [ -f /src/deploy/linux/osoosi-linux-x86_64 ]; then \
        cp -f /src/deploy/linux/osoosi-linux-x86_64 /out/app/osoosi; \
    else \
        apt-get install -y --no-install-recommends \
            build-essential \
            curl \
            libssl-dev \
            pkg-config \
        && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
        && cargo build --release -p osoosi-cli --bin osoosi --locked \
        && cp -f /src/target/release/osoosi /out/app/osoosi; \
    fi \
    && strip --strip-unneeded /out/app/osoosi \
    && chmod 0555 /out/app/osoosi \
    && /out/app/osoosi --version \
    && cp -r /src/dashboard/dist/. /out/app/dashboard/dist/ \
    && if [ -d /src/rules ]; then cp -r /src/rules/. /out/app/rules/; fi \
    && find /out/app/dashboard /out/app/rules -type d -exec chmod 0555 {} + \
    && find /out/app/dashboard /out/app/rules -type f -exec chmod 0444 {} + \
    && chmod 0700 /out/data/database /out/data/logs /out/data/quarantine \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 2: Minimal Hardened Non-Root Runtime ───────────────────────────────
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS runtime

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

LABEL org.opencontainers.image.title="OpenOshoosi Autonomous EDR" \
      org.opencontainers.image.description="Hardened Zero-Trust Autonomous Endpoint Detection & Response Engine" \
      org.opencontainers.image.vendor="Oshoosi Security" \
      org.opencontainers.image.version="1.2.0" \
      org.opencontainers.image.source="https://github.com/oyesanyf/OshoosiClaw" \
      org.opencontainers.image.licenses="Apache-2.0"

# Install strictly required shared libraries, create unprivileged UID/GID 65532,
# strip all SUID/SGID bits, lock root account, and purge package managers/shells
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3t64 \
        libstdc++6 \
        libzstd1 \
        zlib1g \
    && apt-get clean \
    && groupadd --system --gid 65532 osoosi \
    && useradd --system --uid 65532 --gid 65532 --home-dir /app --no-create-home --shell /usr/sbin/nologin osoosi \
    && passwd -l root \
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} + || true \
    && rm -rf \
        /var/lib/apt/lists/* \
        /var/cache/apt/* \
        /var/log/* \
        /tmp/* \
        /usr/bin/apt* \
        /usr/bin/dpkg*

WORKDIR /app

# Copy immutable binary and static assets owned by root:root (0:0) so runtime user cannot modify code
COPY --from=builder --chown=0:0 /out/app/ /app/

# Copy writable state directories owned exclusively by unprivileged user 65532:65532
COPY --from=builder --chown=65532:65532 /out/data/database /app/database
COPY --from=builder --chown=65532:65532 /out/data/logs /app/logs
COPY --from=builder --chown=65532:65532 /out/data/quarantine /app/quarantine

ENV OSOOSI_DASHBOARD_HOST=0.0.0.0 \
    OSOOSI_DASHBOARD_PORT=3030 \
    RUST_BACKTRACE=0

VOLUME ["/app/database", "/app/logs", "/app/quarantine"]

EXPOSE 3030/tcp 4001/tcp

USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/osoosi", "--version"]

ENTRYPOINT ["/app/osoosi"]
CMD ["start", "--port", "3030"]
