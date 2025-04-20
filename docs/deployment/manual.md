# Manual Installation

This guide covers how to deploy DMARQ without Docker, using a traditional installation method.

## Prerequisites

Before proceeding with a manual installation, ensure you have:

- Python 3.9 or higher
- pip and virtualenv
- Node.js 16+ (if modifying frontend assets)
- PostgreSQL (recommended for production) or SQLite
- A web server like Nginx (for production)

## Installation Steps

### 1. Set Up the Environment

First, clone the repository and set up a virtual environment:

```bash
# Clone the repository
git clone https://github.com/yourusername/dmarq.git
cd dmarq

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

Install the required Python packages:

```bash
cd backend
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the backend directory with your configuration:

```
# Database Configuration
DB_TYPE=sqlite  # or postgres for production
DB_PATH=./data/dmarq.db  # for SQLite
# For PostgreSQL:
# DB_HOST=localhost
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

### 4. Initialize the Database

For SQLite:

```bash
# Create the data directory
mkdir -p data

# Initialize the database
cd app
python -m alembic upgrade head
```

For PostgreSQL:

```bash
# Create the database and user in PostgreSQL
sudo -u postgres psql -c "CREATE USER dmarq WITH PASSWORD 'secure_password';"
sudo -u postgres psql -c "CREATE DATABASE dmarq OWNER dmarq;"

# Initialize the database
cd app
python -m alembic upgrade head
```

### 5. Start the Application (Development)

For development or testing, you can run the application directly with Uvicorn:

```bash
cd app
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Production Deployment with Systemd

For a production environment, it's recommended to use a process manager like systemd:

1. Create a systemd service file:

```bash
sudo nano /etc/systemd/system/dmarq.service
```

2. Add the following configuration:

```
[Unit]
Description=DMARQ Application
After=network.target

[Service]
User=dmarq
WorkingDirectory=/path/to/dmarq/backend/app
ExecStart=/path/to/dmarq/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
Restart=always
Environment="PATH=/path/to/dmarq/venv/bin"
EnvironmentFile=/path/to/dmarq/backend/.env

[Install]
WantedBy=multi-user.target
```

3. Start and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl start dmarq
sudo systemctl enable dmarq
```

### 7. Set Up Nginx as a Reverse Proxy

For production, it's recommended to use Nginx as a reverse proxy:

1. Install Nginx:

```bash
sudo apt install nginx
```

2. Create a Nginx configuration file:

```bash
sudo nano /etc/nginx/sites-available/dmarq
```

3. Add the following configuration:

```nginx
server {
    listen 80;
    server_name dmarq.example.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

4. Enable the site and reload Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/dmarq /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 8. Set Up HTTPS with Let's Encrypt

For production, you should secure your site with HTTPS:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d dmarq.example.com
```

## Background Tasks

DMARQ requires background tasks for IMAP polling and report processing. For simple deployments, the built-in background task system in FastAPI is sufficient. 

For more complex deployments, you might want to set up Celery:

1. Install Celery:

```bash
pip install celery redis
```

2. Create a Celery service file:

```bash
sudo nano /etc/systemd/system/dmarq-celery.service
```

3. Add the following configuration:

```
[Unit]
Description=DMARQ Celery Worker
After=network.target

[Service]
User=dmarq
WorkingDirectory=/path/to/dmarq/backend/app
ExecStart=/path/to/dmarq/venv/bin/celery -A worker worker --loglevel=info
Restart=always
Environment="PATH=/path/to/dmarq/venv/bin"
EnvironmentFile=/path/to/dmarq/backend/.env

[Install]
WantedBy=multi-user.target
```

4. Start and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl start dmarq-celery
sudo systemctl enable dmarq-celery
```

## Updating DMARQ

To update to a newer version:

```bash
# Pull the latest code
cd /path/to/dmarq
git pull

# Activate the virtual environment
source venv/bin/activate

# Update dependencies
cd backend
pip install -r requirements.txt

# Apply any database migrations
cd app
python -m alembic upgrade head

# Restart the service
sudo systemctl restart dmarq
```

## Troubleshooting

### Application Won't Start

If the application fails to start:

1. Check the systemd logs: `sudo journalctl -u dmarq`
2. Verify the environment variables in your `.env` file
3. Check that all Python dependencies are installed: `pip list | grep -E 'fastapi|uvicorn'`

### Database Connection Issues

If the application can't connect to the database:

1. Check the DB environment variables in `.env`
2. For PostgreSQL, verify the database exists: `sudo -u postgres psql -c "\l" | grep dmarq`
3. Check if you can connect manually: `psql -U dmarq -h localhost dmarq`

### Nginx Configuration Issues

If Nginx isn't serving the application:

1. Check Nginx error logs: `sudo tail -f /var/log/nginx/error.log`
2. Verify the Nginx configuration: `sudo nginx -t`
3. Make sure the application is running: `curl http://localhost:8000`

## Monitoring and Maintenance

### Checking Application Status

Check if the application is running:

```bash
sudo systemctl status dmarq
```

### Viewing Application Logs

View logs from the application:

```bash
# System logs
sudo journalctl -u dmarq

# Application logs (if configured to log to file)
tail -f /path/to/dmarq/logs/dmarq.log
```

### Database Backups

For PostgreSQL backups:

```bash
# Create a backup
pg_dump -U dmarq dmarq > dmarq_backup_$(date +%Y%m%d).sql

# Restore from a backup
psql -U dmarq dmarq < dmarq_backup_file.sql
```

For SQLite backups:

```bash
# Create a backup
sqlite3 /path/to/data/dmarq.db .dump > dmarq_backup_$(date +%Y%m%d).sql

# Restore from a backup
cat dmarq_backup_file.sql | sqlite3 /path/to/data/dmarq.db
```