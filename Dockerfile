# IOC Insight — all-in-one image (backend + built web UI)
# Build:  docker build -t ioc-insight .
# Run:    docker run -p 8000:8000 --env-file .env ioc-insight
# NOTE: written without a local Docker daemon — verify with `docker build` on your machine.

# ---------- stage 1: build web UI ----------
FROM node:22-alpine AS webbuild
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---------- stage 2: python runtime ----------
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml ./
COPY ioc_insight/ ./ioc_insight/
RUN uv venv /opt/venv && \
    VIRTUAL_ENV=/opt/venv uv pip install -e .  # runtime deps only (no dev)

# built web UI → served by FastAPI from web/dist
COPY --from=webbuild /web/dist ./web/dist

# runtime data (cache + history SQLite) lives here — mount a volume to persist
RUN mkdir -p /app/data
VOLUME ["/app/data"]

# config via env: VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY,
# URLSCAN_API_KEY, GREYNOISE_API_KEY, HERMES_CUSTOM_API_VLEEE_NET_API_KEY
# optional: mount your own config.yaml to /app/config.yaml

EXPOSE 8000
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/api/v1/health',timeout=5)"

CMD ["/opt/venv/bin/uvicorn", "ioc_insight.api:app", "--host", "0.0.0.0", "--port", "8000"]
