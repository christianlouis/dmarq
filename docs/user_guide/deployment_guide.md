# DMARQ Deployment Guide

This guide provides step-by-step instructions for deploying DMARQ in various environments.

## Table of Contents

1. [Docker Deployment (Recommended)](#docker-deployment-recommended)
2. [Manual Installation](#manual-installation)
3. [Environment Configuration](#environment-configuration)
4. [Database Setup](#database-setup)
5. [Production Best Practices](#production-best-practices)
6. [Upgrading](#upgrading)

For day-to-day production operation, use the [Operator Runbook](../deployment/operations.md). For failure recovery, use [Troubleshooting Playbooks](../deployment/troubleshooting.md).

## Docker Deployment (Recommended)

The canonical, tested Docker instructions live in
[Docker Setup](../deployment/docker.md). The short version is:

### Prerequisites

- Docker Engine 24 or later
- Docker Compose v2.20 or later
- OpenSSL
- 2GB RAM minimum (4GB recommended)
- 20GB storage space

### Deployment Steps

```bash
git clone https://github.com/christianlouis/dmarq.git
cd dmarq
./scripts/bootstrap-docker-env.sh
docker compose pull
docker compose up -d --wait
curl -fsS http://localhost:8080/healthz
```

Open `http://localhost:8080`. PostgreSQL is not published to the host. The
application is bound to `127.0.0.1` and uses auth-disabled single-user mode by
default. Follow the canonical guide before changing that bind address or
exposing the instance.

### Updating the Deployment

To update to a newer version:

```bash
git pull
docker compose pull
docker compose up -d --wait
curl -fsS http://localhost:8080/healthz
```

## Manual Installation

For environments where Docker isn't available, you can install DMARQ manually.

### Prerequisites

- Python 3.13 or higher
- pip and virtualenv
- Node.js 16+ (if modifying frontend assets)

### Installation Steps

1. **Set up virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**

   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Configure environment variables**

   Create a `.env` file in the backend directory with the same variables as in the Docker deployment.

4. **Initialize the database**

   ```bash
   cd app
   python -m alembic upgrade head
   ```

5. **Start the application**

   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8080
   ```

6. **Set up a production server**

   For production, use a proper ASGI server like Uvicorn behind Nginx:

   ```bash
   # Example systemd service
   [Unit]
   Description=DMARQ Application
   After=network.target

   [Service]
   User=dmarq
   WorkingDirectory=/path/to/dmarq/backend
   ExecStart=/path/to/dmarq/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

## Environment Configuration

DMARQ can be configured through environment variables:

### Core Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Secret key for session security | Required |
| `ADMIN_API_KEY` | Stable admin API key for automation | Generated in memory |
| `ENVIRONMENT` | Apply production startup checks when set to `production` | `development` |
| `PUBLIC_BASE_URL` | Public browser and OAuth origin | Auto-detected |
| `BACKEND_CORS_ORIGINS` | Explicit browser origins allowed to call the API | Local development origins |

### Database Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | SQLAlchemy SQLite or PostgreSQL URL | `sqlite:///./data/dmarq.db` |

### IMAP Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `IMAP_SERVER` | IMAP server address | - |
| `IMAP_PORT` | IMAP server port | `993` |
| `IMAP_USERNAME` | IMAP username | - |
| `IMAP_PASSWORD` | IMAP password | - |
| `IMAP_FOLDER` | Initial mailbox folder | `INBOX` |
| `DELETE_IMPORTED_EMAILS` | Delete successfully imported email | `false` |

The `IMAP_*` variables are only a legacy one-time source bootstrap. Prefer the
Mail Sources UI for SSL, polling interval, connection testing, and history.

## Database Setup

DMARQ supports SQLite (default) and PostgreSQL databases.

### SQLite (Default)

SQLite is suitable for smaller deployments with fewer domains and reports. No additional configuration is required as it works out of the box.

### PostgreSQL (Recommended for Production)

1. **Create a PostgreSQL database and user**

   ```sql
   CREATE USER dmarq WITH PASSWORD 'secure_password';
   CREATE DATABASE dmarq OWNER dmarq;
   ```

2. **Update environment variables**

   ```
   DATABASE_URL=postgresql://dmarq:secure_password@your_postgres_host:5432/dmarq
   ```

3. **Run database migrations**

   ```bash
   cd backend
   alembic upgrade head
   ```

## Production Best Practices

For production deployments, consider the following:

1. **Use HTTPS**
   
   Set up SSL/TLS with a valid certificate using a reverse proxy like Nginx:

   ```nginx
   server {
     listen 80;
     server_name dmarq.example.com;
     return 301 https://$server_name$request_uri;
   }

   server {
     listen 443 ssl;
     server_name dmarq.example.com;

     ssl_certificate /path/to/cert.pem;
     ssl_certificate_key /path/to/key.pem;

     location / {
       proxy_pass http://127.0.0.1:8080;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
     }
   }
   ```

2. **Regular Backups**
   
   Set up regular database backups:

   ```bash
   # For PostgreSQL
   pg_dump -U dmarq dmarq > dmarq_backup_$(date +%Y%m%d).sql

   # For SQLite
   sqlite3 data/dmarq.db .dump > dmarq_backup_$(date +%Y%m%d).sql
   ```

3. **Monitoring**
   
   Monitor the application using tools like Prometheus and Grafana.

4. **Secure Credentials**
   
   Store sensitive credentials in a secure vault rather than environment variables for production environments.

## Upgrading

### Major Version Upgrades

1. **Backup your data**
   
   ```bash
   # For PostgreSQL
   pg_dump -U dmarq dmarq > dmarq_backup_before_upgrade.sql
   
   # For SQLite
   sqlite3 data/dmarq.db .dump > dmarq_backup_before_upgrade.sql
   ```

2. **Update the repository**
   
   ```bash
   git fetch --tags
   git checkout v2.0.0  # Replace with your target version
   ```

3. **Update dependencies**
   
   ```bash
   pip install -r requirements.txt
   ```

4. **Run database migrations**
   
   ```bash
   cd backend
   alembic upgrade head
   ```

5. **Restart the application**
   
   ```bash
   # For Docker
   docker compose pull
   docker compose up -d --wait
   
   # For manual installations
   sudo systemctl restart dmarq
   ```

### Minor Version Upgrades

For minor version upgrades (e.g., 1.1.0 to 1.2.0), the process is similar but generally has less risk of breaking changes:

```bash
git fetch --tags
git checkout v1.2.0  # Replace with your target version
docker compose pull
docker compose up -d --wait
```

Always check the release notes for any specific upgrade instructions or breaking changes.
