FROM node:24-bookworm-slim AS frontend
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 RS_HOST=0.0.0.0 RS_DATA_DIR=/app/data RS_FRONTEND_DIR=/app/frontend/dist HOME=/tmp
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends tini ca-certificates && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.lock /tmp/requirements.lock
RUN pip install --require-hashes -r /tmp/requirements.lock
COPY backend/ ./backend/
RUN pip install --no-deps ./backend
COPY scripts/ ./scripts/
COPY sample_projects/ ./sample_projects/
COPY --from=frontend /ui/dist ./frontend/dist
RUN groupadd --gid 10001 scanner && useradd --uid 10001 --gid scanner --no-create-home scanner && mkdir -p /app/data && chown -R scanner:scanner /app/data
USER scanner
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4)"
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["python", "scripts/run_services.py"]
