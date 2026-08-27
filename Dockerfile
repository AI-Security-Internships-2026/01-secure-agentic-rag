# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_ENV=production
WORKDIR /app

RUN useradd --create-home --uid 10001 appuser
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir . \
    && python -m spacy download en_core_web_sm || true

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "secure_rag.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
