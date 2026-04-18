# ─── Pyguard Bot – Railway Dockerfile ────────────────────────────────────────
FROM python:3.12-slim

# Build tools cần cho C extensions:
#   gcc          → compile watchdog .so (Stage 5) + pyguard_ext .so (Stage 7)
#   clang        → LLVM IR → ELF .o → .text bytes (Stage 4 real native)
#   python3-dev  → Python.h header cho CPython extension
#   libssl-dev   → Stage 7 links -lssl -lcrypto
#   zlib1g-dev   → Stage 7 links -lz
#   libffi-dev   → cryptography package build dep
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        clang \
        python3-dev \
        libssl-dev \
        zlib1g-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cài Python dependencies trước (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ project
COPY . .

# Không cần expose port – bot là worker (không có HTTP server)
CMD ["python", "bot.py"]
