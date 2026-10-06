# syntax=docker/dockerfile:1
# CUDA-capable base for every Aetheris application microservice.
# PostgreSQL/Redis/MinIO remain vendor images; API/Celery/report/RAG/OCR services
# all inherit this image and can probe/use the NVIDIA device when admitted by
# the shared adaptive GPU semaphore.
FROM nvidia/cuda:12.6.3-runtime-ubuntu24.04 AS dependencies

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/venv/bin:$PATH \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-dev python3-venv python3-pip \
    build-essential libpq-dev gcc curl pkg-config ca-certificates \
    libewf-dev libtsk-dev \
    fonts-liberation fontconfig ffmpeg \
    && python3 -m venv /opt/venv \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install CUDA-enabled PyTorch first.  Compose can override TORCH_INDEX_URL for
# a driver/toolkit validated wheel channel. Requirements then reuse that torch.
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cu130
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --upgrade pip --retries 20 \
    && python -m pip install --retries 20 --index-url "${TORCH_INDEX_URL}" torch torchvision \
    && python -m pip install --retries 20 -r requirements.txt

# This argument is intentionally below every dependency installation. The
# Windows starter changes it once per launch so only application layers rebuild.
FROM dependencies AS application
ARG AETHERIS_APP_BUILD_ID=source
COPY . .
RUN test -n "$AETHERIS_APP_BUILD_ID" && python -m compileall -q app
LABEL org.aetheris.application-build="$AETHERIS_APP_BUILD_ID"
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
