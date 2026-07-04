# For production, pin the base image by digest, e.g.:
#   FROM python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

# Don't buffer stdout/stderr (so audit/log lines flush promptly)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user. Pre-create the replay-ledger dir and hand it to
# the app user so a mounted named volume inherits non-root ownership.
RUN useradd --system --uid 10001 --user-group --home-dir /app --no-log-init appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Liveness probe against the app's /health endpoint (no curl in slim image).
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else sys.exit(1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
