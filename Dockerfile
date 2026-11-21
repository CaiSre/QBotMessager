# syntax=docker/dockerfile:1

ARG ALPINE_VERSION=3.21

# ------------------------------------------------ 前端构建
FROM alpine:${ALPINE_VERSION} AS web-builder

ARG NPM_MIRROR=https://registry.npmjs.org

RUN apk add --no-cache nodejs npm

WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --registry="${NPM_MIRROR}" --no-audit --no-fund

COPY web/ ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ------------------------------------------------ Python 依赖
FROM alpine:${ALPINE_VERSION} AS py-builder

ARG PYPI_MIRROR=https://pypi.org/simple

RUN apk add --no-cache python3 py3-pip
RUN pip install --no-cache-dir --break-system-packages --index-url "${PYPI_MIRROR}" uv

WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv export --frozen --no-dev --no-hashes --no-emit-project --output-file requirements.txt \
 && uv venv /opt/venv --python python3 \
 && VIRTUAL_ENV=/opt/venv uv pip install --index-url "${PYPI_MIRROR}" -r requirements.txt

# ------------------------------------------------ 运行时
FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache python3 nodejs supervisor tzdata

ENV PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai \
    NEXT_TELEMETRY_DISABLED=1 \
    BACKEND_ORIGIN=http://127.0.0.1:8000 \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

COPY --from=py-builder /opt/venv /opt/venv
COPY server ./server
COPY alembic ./alembic
COPY alembic.ini ./
COPY deploy/supervisord.conf /etc/supervisord.conf
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh

COPY --from=web-builder /build/web/.next/standalone ./
COPY --from=web-builder /build/web/.next/static ./.next/static

RUN chmod +x /usr/local/bin/entrypoint.sh \
 && addgroup -S app \
 && adduser -S -G app app \
 && chown -R app:app /app /opt/venv

USER app

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:3000/login || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
