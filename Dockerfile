# Lightweight Python image
FROM python:3.11-slim AS base

# Disable bytecode + ensure stdout/stderr unbuffered
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_ENV=production

WORKDIR /app

# System deps (if needed later, extend here)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose app port
EXPOSE 5000

# Default command: gunicorn with increased timeout for long-running streaming requests
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--timeout", "360", "--keep-alive", "5", "app:app"]

