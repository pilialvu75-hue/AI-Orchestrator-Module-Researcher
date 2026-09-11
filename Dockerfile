FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    DRY_RUN=true \
    ALLOW_LIBRARY_WRITE=false \
    DASHBOARD_HOST=0.0.0.0

WORKDIR /app
COPY pyproject.toml README.md ARCHITECTURE.md ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 researcher \
    && mkdir -p /data \
    && chown -R researcher:researcher /data /app

USER researcher
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).read()" || exit 1

ENTRYPOINT ["researcher"]
CMD ["worker"]
