# DVLAA container image
# Runtime image for the LLM and Agent security range.

FROM python:3.11-slim

WORKDIR /app

# 1. Install runtime OS dependencies.
RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources; \
        sed -i 's/security.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
        sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list; \
        sed -i 's/security.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list; \
    fi; \
    apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# 2. Pin CPU-oriented PyTorch to avoid pulling CUDA runtimes into the image.
RUN pip install --no-cache-dir --default-timeout=600 --retries=10 \
    -i https://pypi.org/simple "torch==2.5.1"

# 3. Install Python dependencies with a public mirror fallback.
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=600 --retries=10 \
    -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt \
    || pip install --no-cache-dir --default-timeout=600 --retries=10 \
    -i https://pypi.org/simple -r requirements.txt

# 4. Runtime defaults.
ENV PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=4 \
    OPENBLAS_NUM_THREADS=4 \
    MKL_NUM_THREADS=4

# 5. Copy application files; mutable model/data directories are excluded by .dockerignore.
COPY . .

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5000/health || exit 1

CMD ["python", "-m", "dvlaa"]
