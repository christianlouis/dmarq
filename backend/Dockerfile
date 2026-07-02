FROM python:3.13-slim

WORKDIR /app

ARG DMARQ_BUILD_SHA=""
ARG DMARQ_BUILD_REF=""
ARG DMARQ_BUILD_IMAGE=""
ARG DMARQ_BUILD_DATE=""

ENV DMARQ_BUILD_SHA="${DMARQ_BUILD_SHA}" \
    DMARQ_BUILD_REF="${DMARQ_BUILD_REF}" \
    DMARQ_BUILD_IMAGE="${DMARQ_BUILD_IMAGE}" \
    DMARQ_BUILD_DATE="${DMARQ_BUILD_DATE}"

# Install required system dependencies.
# The backend does not need privileged mount helpers. Debian 13 currently has
# no fixed util-linux package for the reported Snyk mount(8) CVEs, so remove
# the SUID entry points from the runtime image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    ca-certificates \
    && chmod u-s /usr/bin/mount /usr/bin/umount \
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
