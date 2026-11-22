# syntax=docker/dockerfile:1

# 极简化镜像：bun 构建前端 → rust 构建静态二进制 → alpine 运行时只留一个进程
# 运行时不含 nodejs / python / redis / supervisor

ARG ALPINE_VERSION=3.24
ARG BUN_VERSION=1.4.5
ARG RUST_VERSION=1.100

# ------------------------------------------------ 前端构建（Bun + Next 静态导出）
FROM oven/bun:${BUN_VERSION}-alpine AS web-builder

WORKDIR /build/web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile

COPY web/ ./
ENV NEXT_TELEMETRY_DISABLED=1
# .next/cache 只用于加速重复构建，不进镜像层
RUN --mount=type=cache,target=/build/web/.next/cache bun run build \
 && test -f /build/web/out/index.html

# ------------------------------------------------ 后端构建（musl 静态链接）
FROM rust:${RUST_VERSION}-alpine AS api-builder

# ring 需要 C 编译器；依赖树里没有 openssl / aws-lc-sys，无需 cmake
RUN apk add --no-cache build-base

WORKDIR /build/backend
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/migrations ./migrations

# 依赖预热层：空壳 lib 显式引用所有依赖，cargo 的 unused_dependencies lint
# 不会因空实现误报；源码改动时本层缓存命中不变，只重编本 crate
COPY <<'EOF' src/lib.rs
pub mod placeholder {
    pub use actix_files;
    pub use actix_web;
    pub use apalis;
    pub use apalis_mysql;
    pub use base64;
    pub use chrono;
    pub use dashmap;
    pub use dotenvy;
    pub use fernet;
    pub use hmac;
    pub use lettre;
    pub use pbkdf2;
    pub use rand;
    pub use regex;
    pub use reqwest;
    pub use rustls;
    pub use serde;
    pub use serde_cbor_2;
    pub use serde_json;
    pub use sha2;
    pub use sqlx;
    pub use subtle;
    pub use thiserror;
    pub use tokio;
    pub use tower;
    pub use tracing;
    pub use tracing_subscriber;
    pub use url;
    pub use uuid;
    pub use webauthn_rs_core;
}
EOF
RUN mkdir -p src \
 && printf 'fn main() {}\n' > src/main.rs \
 && cargo build --release --locked

COPY backend/src ./src
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked \
 && strip target/release/qbotmessager \
 && test -x target/release/qbotmessager

# ------------------------------------------------ 运行时
FROM alpine:${ALPINE_VERSION}

# ca-certificates：reqwest 走 rustls-platform-verifier，Linux 下读取系统信任库
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
# 迁移已由 sqlx::migrate! 在编译期嵌入二进制，运行镜像不再需要 migrations 目录
COPY --from=api-builder /build/backend/target/release/qbotmessager /app/qbotmessager
COPY --from=web-builder /build/web/out /app/web

RUN adduser -D -u 10001 -h /app -s /sbin/nologin qbot \
 && chown -R qbot:qbot /app

ENV PORT=3000 \
    STATIC_DIR=/app/web \
    RUST_LOG=info \
    NEXT_TELEMETRY_DISABLED=1 \
    TZ=Asia/Shanghai

USER qbot
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:3000/readyz || exit 1

ENTRYPOINT ["/app/qbotmessager"]
