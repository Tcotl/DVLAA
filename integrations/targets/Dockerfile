FROM python:3.11-slim

WORKDIR /app
COPY target_server.py /app/target_server.py
COPY finals_core.py /app/finals_core.py
COPY product_skins /app/product_skins
RUN mkdir -p /app/runtime && chmod 700 /app/runtime

ENV PYTHONUNBUFFERED=1 \
    AWDP_NATIVE_HOST=0.0.0.0 \
    AWDP_NATIVE_PORT=5900 \
    AWDP_NATIVE_CHALLENGE=0 \
    AWDP_NATIVE_RUNTIME_DIR=/app/runtime

EXPOSE 5900
HEALTHCHECK --interval=10s --timeout=3s --start-period=2s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5900/health', timeout=2).read()" || exit 1

CMD ["python", "/app/target_server.py"]
