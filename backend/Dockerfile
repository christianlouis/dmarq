FROM node:22-slim AS frontend

WORKDIR /app

COPY package.json package-lock.json* tailwind.config.cjs ./
RUN npm ci

COPY app/templates ./app/templates
COPY app/static/js ./app/static/js
COPY app/static/css/styles.css ./app/static/css/styles.css
RUN npm run build:css

FROM python:3.13-slim AS sqlite-builder

ARG SQLITE_FIX_COMMIT=c597ed79d1bd03f57198d10d1f431adda293cf2e
ARG SQLITE_FIX_SHA256=61586c1331d519381d4e636512fc13bda678beaf7e3354a083c770c7fdd8e6ba

WORKDIR /tmp/sqlite

# Debian Trixie does not yet ship these two SQLite session-extension fixes.
# Build the upstream fixed tree and package only the shared runtime library so
# Python's sqlite3 module keeps using the normal libsqlite3 ABI.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    dpkg-dev \
    && curl -fsSL "https://github.com/sqlite/sqlite/archive/${SQLITE_FIX_COMMIT}.tar.gz" \
      -o /tmp/sqlite.tar.gz \
    && echo "${SQLITE_FIX_SHA256}  /tmp/sqlite.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/sqlite.tar.gz --strip-components=1 \
    && ./configure --prefix=/opt/sqlite --disable-static --fts5 --session \
    && make -j"$(nproc)" \
    && make install \
    && mkdir -p "/tmp/sqlite-package/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)" \
    && cp -a /opt/sqlite/lib/libsqlite3.so* \
      "/tmp/sqlite-package/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/" \
    && mkdir -p /tmp/sqlite-package/DEBIAN \
    && printf '%s\n' \
      'Package: libsqlite3-0' \
      'Version: 3.54.0-0dmarq1' \
      "Architecture: $(dpkg --print-architecture)" \
      'Multi-Arch: same' \
      'Maintainer: DMARQ maintainers <maintainers@dmarq.org>' \
      'Description: SQLite runtime with DMARQ security fixes' \
      ' This package contains the SQLite runtime built from the upstream' \
      ' session-extension security-fix tree used by the DMARQ image.' \
      > /tmp/sqlite-package/DEBIAN/control \
    && dpkg-deb --build --root-owner-group /tmp/sqlite-package /tmp/libsqlite3-0.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/sqlite /tmp/sqlite-package /tmp/sqlite.tar.gz

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
# Temporary inherited-package decisions are tracked in
# docs/deployment/security-risk-acceptances.md and reviewed on a deadline.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    ca-certificates \
    && chmod u-s /usr/bin/mount /usr/bin/umount \
    && rm -rf /var/lib/apt/lists/*

COPY --from=sqlite-builder /tmp/libsqlite3-0.deb /tmp/libsqlite3-0.deb
RUN dpkg -i /tmp/libsqlite3-0.deb \
    && ldconfig \
    && rm /tmp/libsqlite3-0.deb

# Copy Python requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code including templates and static assets
COPY . .
COPY --from=frontend /app/app/static/css/app.css /app/app/static/css/app.css

# Make the entrypoint executable and create the default data directory so
# SQLite has a place to write its file even without an explicit volume mount.
RUN chmod +x /app/entrypoint.sh && mkdir -p /app/data

# Expose application port
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
