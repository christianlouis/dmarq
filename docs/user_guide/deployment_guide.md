# DMARQ Deployment Guide

This guide provides step-by-step instructions for deploying DMARQ in various environments.

## Table of Contents

1. [Docker Deployment (Recommended)](#docker-deployment-recommended)
2. [Manual Installation](#manual-installation)
3. [Environment Configuration](#environment-configuration)
4. [Database Setup](#database-setup)
5. [Production Best Practices](#production-best-practices)
6. [Upgrading](#upgrading)

## Docker Deployment (Recommended)

The easiest way to deploy DMARQ is using Docker and Docker Compose. This approach packages all dependencies and provides a consistent environment.

### Prerequisites

- Docker Engine 20.10.0 or later
- Docker Compose v2.0.0 or later
- 2GB RAM minimum (4GB recommended)
- 20GB storage space

### Deployment Steps

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/dmarq.git
   cd dmarq
   ```

2. **Configure environment variables**

   Create a `.env` file in the project root:

   ```
   # Database Configuration
   DB_TYPE=sqlite  # or postgres for production
   DB_PATH=./data/dmarq.db  # for SQLite
   # For PostgreSQL:
   # DB_HOST=postgres
   # DB_PORT=5432
   # DB_USER=dmarq
   # DB_PASS=secure_password
   # DB_NAME=dmarq

   # IMAP Configuration (optional)
   IMAP_ENABLED=false
   # IMAP_SERVER=mail.example.com
   # IMAP_PORT=993
   # IMAP_USERNAME=dmarc@example.com
   # IMAP_PASSWORD=your_secure_password
   # IMAP_USE_SSL=true
   # IMAP_POLLING_INTERVAL=60

   # Security Settings
   SECRET_KEY=generate_a_secure_random_key
   ALLOWED_HOSTS=localhost,127.0.0.1
   ```

   Generate a secure random key for `SECRET_KEY`:

   ```bash
   openssl rand -hex 32
   ```

3. **Start the containers**

   ```bash
   docker-compose up -d
   ```

4. **Access the application**

   Open your browser and navigate to `http://localhost:8000`

5. **Check container status**

   ```bash
   docker-compose ps
   ```

### Updating the Deployment

To update to a newer version:

```bash
git pull
docker-compose down
docker-compose build
docker-compose up -d
```

## Manual Installation

For environments where Docker isn't available, you can install DMARQ manually.

### Prerequisites

- Python 3.9 or higher
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
   uvicorn main:app --host 0.0.0.0 --port 8000
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
   WorkingDirectory=/path/to/dmarq/backend/app
   ExecStart=/path/to/dmarq/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

## Environment Configuration

DMARQ can be configured through environment variables:

### Core Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `false` |
| `SECRET_KEY` | Secret key for session security | Required |
| `ALLOWED_HOSTS` | Comma-separated list of allowed hosts | `localhost,127.0.0.1` |

### Database Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_TYPE` | Database type (sqlite, postgres) | `sqlite` |
| `DB_PATH` | Path to SQLite database file | `./data/dmarq.db` |
| `DB_HOST` | PostgreSQL host | - |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | PostgreSQL username | - |
| `DB_PASS` | PostgreSQL password | - |
| `DB_NAME` | PostgreSQL database name | - |

### IMAP Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `IMAP_ENABLED` | Enable IMAP report fetching | `false` |
| `IMAP_SERVER` | IMAP server address | - |
| `IMAP_PORT` | IMAP server port | `993` |
| `IMAP_USERNAME` | IMAP username | - |
| `IMAP_PASSWORD` | IMAP password | - |
| `IMAP_USE_SSL` | Use SSL for IMAP connection | `true` |
| `IMAP_POLLING_INTERVAL` | Minutes between polling | `60` |

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
   DB_TYPE=postgres
   DB_HOST=your_postgres_host
   DB_PORT=5432
   DB_USER=dmarq
   DB_PASS=secure_password
   DB_NAME=dmarq
   ```

3. **Run database migrations**

   ```bash
   cd backend/app
   python -m alembic upgrade head
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
       proxy_pass http://127.0.0.1:8000;
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
   cd backend/app
   python -m alembic upgrade head
   ```

5. **Restart the application**
   
   ```bash
   # For Docker
   docker-compose down
   docker-compose up -d
   
   # For manual installations
   sudo systemctl restart dmarq
   ```

### Minor Version Upgrades

For minor version upgrades (e.g., 1.1.0 to 1.2.0), the process is similar but generally has less risk of breaking changes:

```bash
git fetch --tags
git checkout v1.2.0  # Replace with your target version
docker-compose down
docker-compose up -d
```

Always check the release notes for any specific upgrade instructions or breaking changes.