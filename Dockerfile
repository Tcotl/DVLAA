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
    if ! (apt-get -o Acquire::Retries=5 update && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
        build-essential \
        curl \
        ca-certificates); then \
        sed -i 's/mirrors.ustc.edu.cn/deb.debian.org/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i 's/mirrors.ustc.edu.cn/deb.debian.org/g' /etc/apt/sources.list 2>/dev/null || true; \
        rm -rf /var/lib/apt/lists/*; \
        apt-get -o Acquire::Retries=5 update; \
        apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
            build-essential \
            curl \
            ca-certificates; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# 2. Pin CPU-oriented PyTorch to avoid pulling CUDA runtimes into the image.
#    On x86_64, PyPI's default torch wheel pulls CUDA dependency wheels; use the
#    official CPU wheel index explicitly so cloud servers build quickly.
RUN set -eux; \
    arch="$(python -c 'import platform; print(platform.machine())')"; \
    if [ "$arch" = "x86_64" ]; then \
        pip install --no-cache-dir --default-timeout=600 --retries=10 \
            -i https://pypi.tuna.tsinghua.edu.cn/simple \
            filelock typing-extensions networkx jinja2 fsspec sympy==1.13.1; \
        pip install --no-cache-dir --default-timeout=600 --retries=10 --no-deps \
            "https://download.pytorch.org/whl/cpu/torch-2.5.1%2Bcpu-cp311-cp311-linux_x86_64.whl" \
            "https://download.pytorch.org/whl/cpu/torchvision-0.20.1%2Bcpu-cp311-cp311-linux_x86_64.whl"; \
    else \
        pip install --no-cache-dir --default-timeout=600 --retries=10 \
            -i https://pypi.org/simple "torch==2.5.1"; \
    fi

# 3. Install Python dependencies with a public mirror fallback.
COPY requirements.txt .
RUN set -eux; \
    pip install --no-cache-dir --default-timeout=600 --retries=10 \
        -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt \
    || pip install --no-cache-dir --default-timeout=600 --retries=10 \
        -i https://pypi.org/simple -r requirements.txt; \
    apt-get purge -y --auto-remove build-essential; \
    rm -rf /var/lib/apt/lists/*

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
