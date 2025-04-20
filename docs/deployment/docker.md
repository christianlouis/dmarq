# Docker Setup

This guide covers how to deploy DMARQ using Docker, which is the recommended deployment method.

## Prerequisites

Before deploying DMARQ with Docker, ensure you have:

- Docker Engine 20.10.0 or later
- Docker Compose v2.0.0 or later
- 2GB RAM minimum (4GB recommended)
- 20GB storage space

## Quick Start

The fastest way to get DMARQ running is to use Docker Compose:

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

## Understanding the Docker Setup

The `docker-compose.yml` file defines the following services:

- **backend**: The FastAPI application that handles API requests, processes reports, and serves the web interface
- **db**: A PostgreSQL database container (when using Postgres instead of SQLite)

### Docker Compose File Structure

The `docker-compose.yml` file looks like this:

```yaml
version: '3.8'

services:
  backend:
    build: 
      context: ./backend
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      - DB_TYPE=${DB_TYPE:-sqlite}
      - DB_PATH=${DB_PATH:-./data/dmarq.db}
      - DB_HOST=${DB_HOST:-postgres}
      - DB_PORT=${DB_PORT:-5432}
      - DB_USER=${DB_USER:-dmarq}
      - DB_PASS=${DB_PASS:-dmarqpassword}
      - DB_NAME=${DB_NAME:-dmarq}
      - IMAP_ENABLED=${IMAP_ENABLED:-false}
      - IMAP_SERVER=${IMAP_SERVER:-}
      - IMAP_PORT=${IMAP_PORT:-993}
      - IMAP_USERNAME=${IMAP_USERNAME:-}
      - IMAP_PASSWORD=${IMAP_PASSWORD:-}
      - IMAP_USE_SSL=${IMAP_USE_SSL:-true}
      - IMAP_POLLING_INTERVAL=${IMAP_POLLING_INTERVAL:-60}
      - SECRET_KEY=${SECRET_KEY:-insecure_key_change_me_in_production}
      - ALLOWED_HOSTS=${ALLOWED_HOSTS:-localhost,127.0.0.1}
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:14-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=${DB_USER:-dmarq}
      - POSTGRES_PASSWORD=${DB_PASS:-dmarqpassword}
      - POSTGRES_DB=${DB_NAME:-dmarq}
    restart: unless-stopped

volumes:
  postgres_data:
```

## Configuration Options

### Environment Variables

All configuration in the Docker setup is done via environment variables, either directly in the `docker-compose.yml` file or through a separate `.env` file. See the [Configuration](configuration.md) page for detailed information about all available variables.

### Volumes

The Docker Compose setup uses these volumes:

- **./data**: Local directory mapped to `/app/data` in the container, stores SQLite database (if used) and other persistent data
- **postgres_data**: Docker volume for PostgreSQL data (when using Postgres)

## Production Deployment

For production deployments, consider these additional steps:

### Using a Reverse Proxy

In production, it's recommended to use a reverse proxy like Nginx or Traefik in front of DMARQ:

```yaml
version: '3.8'

services:
  # ...existing services...
  
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - backend
    restart: unless-stopped
```

Example Nginx configuration:

```nginx
server {
    listen 80;
    server_name dmarq.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name dmarq.example.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    location / {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Docker Compose Profiles

For more complex deployments, you can use Docker Compose profiles:

```yaml
version: '3.8'

services:
  backend:
    # ...existing config...
    profiles: [app, all]
  
  db:
    # ...existing config...
    profiles: [app, all]
  
  nginx:
    # ...nginx config...
    profiles: [production, all]
```

Then start only specific profiles:

```bash
docker-compose --profile production up -d
```

## Updating DMARQ

To update to a newer version:

```bash
# Pull the latest code
git pull

# Stop the containers
docker-compose down

# Rebuild and start
docker-compose up -d --build
```

## Monitoring and Maintenance

### Viewing Logs

To view logs from the containers:

```bash
# All logs
docker-compose logs

# Just backend logs
docker-compose logs backend

# Follow logs in real-time
docker-compose logs -f
```

### Container Health Checks

Monitor the health of your containers:

```bash
docker-compose ps
```

### Database Backups

For PostgreSQL backups:

```bash
# Create a backup
docker-compose exec db pg_dump -U dmarq dmarq > backup_$(date +%Y%m%d).sql

# Restore from a backup
cat backup_file.sql | docker-compose exec -T db psql -U dmarq dmarq
```

## Troubleshooting

### Container Won't Start

If containers fail to start:

1. Check logs: `docker-compose logs backend`
2. Verify environment variables: `docker-compose config`
3. Check disk space: `df -h`
4. Ensure ports aren't already in use: `netstat -tuln | grep 8000`

### Database Connection Issues

If the application can't connect to the database:

1. Check the DB environment variables in `.env`
2. For Postgres, ensure the `db` service is running: `docker-compose ps db`
3. Try connecting manually: `docker-compose exec db psql -U dmarq dmarq`

### Mounting Issues

If you encounter volume mounting problems:

1. Check file permissions on the host
2. Use absolute paths in your volume mappings
3. On Windows, ensure you've enabled Docker file sharing for the relevant drives