# Architecture

This document outlines the architecture of the DMARQ system, explaining its components, data flow, and design decisions.

## Overview

DMARQ is designed as a modern web application with a clear separation between the backend (API server) and frontend (web interface). The system is built to be scalable, maintainable, and deployable in various environments from single-server setups to containerized cloud deployments.

## System Components

### Backend Components

![DMARQ Architecture](../assets/images/architecture_diagram.png)

#### API Server

The core of DMARQ is a FastAPI application that provides:

- REST API endpoints for all functionality
- Authentication and authorization
- Business logic for processing DMARC reports
- Database access layer
- Background task processing

**Key Technologies:**
- Python 3.9+
- FastAPI framework
- Pydantic for data validation
- SQLAlchemy ORM for database access
- Alembic for database migrations

#### Database

DMARQ supports two database options:

1. **SQLite** - For small deployments and development
2. **PostgreSQL** - For production deployments with higher load

The database schema is designed to efficiently store:
- Domain information
- DMARC reports (aggregate and forensic)
- User accounts and settings
- System configuration

#### IMAP Client

The IMAP client module connects to an email server to automatically fetch DMARC reports. It:

- Polls the mailbox at configured intervals
- Downloads emails with DMARC report attachments
- Extracts and passes reports to the parser
- Manages the mailbox (marking as read, moving to folders, etc.)

#### DMARC Parser

The parser processes DMARC reports in various formats:
- XML format (direct from email providers)
- Compressed formats (ZIP, GZ)
- Email attachments (EML)

It extracts all relevant data and stores it in the database for analysis.

#### Worker System

Background tasks are handled by an asynchronous worker system that processes:
- Report parsing (which can be time-consuming)
- Scheduled DNS checks
- Email notifications
- Report aggregation and statistics calculation

For simpler deployments, this uses FastAPI's built-in background tasks. For production, it can be configured to use Celery with Redis or RabbitMQ as the message broker.

### Frontend Components

#### Web Interface

The DMARQ web interface is built with modern web technologies:
- HTML5
- CSS (with TailwindCSS/DaisyUI)
- JavaScript
- Jinja2 templates

It provides a responsive dashboard and administrative interface accessible on desktop and mobile devices.

#### Static Assets

Static assets are served directly by the web server or a CDN in production:
- CSS stylesheets
- JavaScript files
- Images and icons
- Fonts

## Data Flow

### Report Processing Flow

1. Reports are received via:
   - Email (IMAP fetcher)
   - Manual upload (web UI)
   - API endpoint

2. The report is queued for processing

3. The DMARC parser:
   - Validates the report format
   - Extracts metadata (date range, reporting organization)
   - Extracts authentication results
   - Processes individual records

4. Processed data is stored in the database

5. Statistics are updated:
   - Domain compliance rates
   - Source IP reputation
   - Authentication success/failure trends

6. Notifications are sent if configured thresholds are triggered

### User Request Flow

1. User makes a request to the web interface

2. The request is authenticated:
   - Session cookie for web UI
   - API key for API requests

3. The relevant API endpoint processes the request:
   - Validates inputs
   - Queries the database
   - Applies business logic
   - Prepares response

4. The response is returned:
   - JSON for API requests
   - HTML for web UI requests

## Deployment Architecture

### Docker Deployment

The recommended deployment method uses Docker Compose with these containers:
- **backend**: The FastAPI application
- **db**: PostgreSQL database (when not using SQLite)
- **nginx**: Web server/reverse proxy (for production)

### Traditional Deployment

For traditional deployments:
- FastAPI application served by Uvicorn/Gunicorn
- Nginx or Apache as reverse proxy
- PostgreSQL database
- Systemd services for process management

## Security Considerations

DMARQ implements several security measures:

### Authentication

- Password-based authentication for web UI
- API keys for programmatic access
- OAuth/OIDC integration (optional)

### Authorization

- Role-based access control (Admin, Analyst, Viewer)
- Domain-based permissions
- API key scoping

### Data Protection

- TLS for all connections
- Encrypted storage of sensitive data
- Secure password hashing
- API rate limiting

## Monitoring and Logging

The system includes comprehensive logging:

- Application logs (API requests, errors)
- Audit logs (user actions)
- Performance metrics
- Health checks

These can be integrated with external monitoring systems through:
- Prometheus metrics endpoint
- Structured JSON logs
- Health check API

## Scalability Considerations

DMARQ is designed to scale in several ways:

### Horizontal Scaling

- Stateless API servers can be deployed behind a load balancer
- Database can be scaled separately
- Background workers can be scaled independently

### Vertical Scaling

- Database connection pooling
- Caching of frequently accessed data
- Efficient query optimization

### Data Volume Handling

- Partitioning of report data by date
- Aggregation of historical data
- Configurable retention policies

## Integration Points

DMARQ is designed to integrate with external systems:

### DNS Providers

- Cloudflare API integration
- AWS Route 53 integration
- Generic DNS API support

### Notification Systems

- Email notifications
- Webhook callbacks
- Integration with Slack, Teams, etc.

### Authentication Providers

- LDAP/Active Directory
- OAuth providers (Google, GitHub, etc.)
- SAML for enterprise SSO

## Development Architecture

For development, the architecture supports:

- Fast reload for code changes
- SQLite database for simplicity
- Mock data generators
- Comprehensive test suite
- CI/CD pipeline integration