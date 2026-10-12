# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_ENV=production AUDIT_OUTPUT_DESTINATION=stdout
WORKDIR /app

RUN useradd --create-home --uid 10001 appuser
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir . \
    && python -m spacy download en_core_web_sm

# /app/logs is the only writable path in the documented deployments (emptyDir/PVC in
# Kubernetes, bind mount in Compose). Pre-create it owned by the runtime user so a
# named volume mounted there inherits writable ownership.
RUN mkdir -p /app/logs && chown appuser:appuser /app/logs

USER appuser
VOLUME ["/app/logs"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "secure_rag.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
