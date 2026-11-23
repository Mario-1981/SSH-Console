# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: Build React + TypeScript Frontend (Vite)
# ==============================================================================
FROM node:22-bookworm-slim AS frontend-builder

WORKDIR /app

COPY package.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm install --legacy-peer-deps --no-audit --no-fund

COPY index.html tsconfig.json vite.config.ts ./
COPY src ./src

RUN npm run build

# ==============================================================================
# Stage 2: Build Native Rust Backend (Axum + Tokio + SQLite) for Debian Trixie
# ==============================================================================
FROM debian:trixie-slim AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cargo rustc build-essential pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY rust-app/Cargo.toml ./Cargo.toml
COPY rust-app/.cargo ./.cargo
COPY rust-app/src ./src

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo build --release \
    && strip /build/target/release/ssh-console

# ==============================================================================
# Stage 3: Minimal Hardened Runtime Image (Debian 13 Trixie)
# ==============================================================================
FROM debian:trixie-slim AS runtime

LABEL org.opencontainers.image.title="SSH Console" \
      org.opencontainers.image.description="Self-hosted OpenSSH Certificate, Multi-Tab SSH Shell, Ping & BMC Console" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client iputils-ping curl ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home-dir /var/lib/ssh-console --shell /usr/sbin/nologin ssh-console \
    && mkdir -p /var/lib/ssh-console /opt/ssh-console/dist \
    && chown -R ssh-console:ssh-console /var/lib/ssh-console /opt/ssh-console \
    && chmod 0700 /var/lib/ssh-console

COPY --from=rust-builder --chown=root:root /build/target/release/ssh-console /usr/local/bin/ssh-console
COPY --from=frontend-builder --chown=ssh-console:ssh-console /app/dist /opt/ssh-console/dist

RUN chmod 0755 /usr/local/bin/ssh-console

USER ssh-console
WORKDIR /opt/ssh-console

ENV SSH_CONSOLE_BIND=0.0.0.0:3000 \
    SSH_CONSOLE_DATA_DIR=/var/lib/ssh-console \
    SSH_CONSOLE_STATIC_DIR=/opt/ssh-console/dist \
    RUST_LOG=info

EXPOSE 3000
VOLUME ["/var/lib/ssh-console"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/api/status >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ssh-console"]
