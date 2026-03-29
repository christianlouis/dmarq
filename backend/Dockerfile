FROM python:3.13-slim

WORKDIR /app

  # Install required system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Remove Tailwind & DaisyUI build; using CDN links instead

# Copy Python requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code including templates and static assets
COPY . .

# Make the entrypoint executable and create the default data directory so
# SQLite has a place to write its file even without an explicit volume mount.
RUN chmod +x /app/entrypoint.sh && mkdir -p /app/data

# Expose application port
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]