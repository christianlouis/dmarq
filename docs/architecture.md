# DMARQ Architecture

## System Overview

DMARQ is designed as a self-contained application that processes DMARC reports, stores relevant data, and presents insights through a web interface. The architecture follows a layered approach with clear separation of concerns between components.

## Core Components

### Web Application (FastAPI)
- Serves the web interface
- Handles API requests
- Manages user authentication
- Coordinates background tasks
- Renders templates with Jinja2

### DMARC Processing Engine
- Parses DMARC XML reports
- Extracts meaningful data from reports
- Validates report structure
- Identifies sending sources
- Calculates compliance metrics

### Data Storage
- **MVP Phase**: In-memory storage
- **Later Phases**: SQLite or PostgreSQL database
- Stores domain configurations
- Maintains report history
- Tracks sender statistics

### Report Acquisition
- **MVP Phase**: Manual file upload
- **Later Phases**: IMAP client for automatic retrieval
- Handles compression formats (ZIP, GZ)
- Deduplicates reports

### Background Processing
- Scheduled report fetching
- Periodic DNS checks
- Alert evaluation
- Data aggregation for dashboards

## Data Flow

1. **Report Ingestion**
   - Reports arrive via upload or IMAP
   - System extracts and validates XML content
   - Parser processes report data
   - Data is stored in appropriate format

2. **Data Processing**
   - Raw report data is transformed into metrics
   - System calculates compliance rates
   - Identifies new or problematic senders
   - Updates historical records

3. **Presentation Layer**
   - Dashboard displays key metrics
   - Domain details show specific report data
   - Charts visualize trends
   - Alerts highlight issues requiring attention

## Architectural Evolution

The DMARQ architecture is designed to evolve across milestones:

### Milestone 1: Minimal Architecture
- Single FastAPI service
- In-memory data storage
- Manual file upload
- Basic template rendering

```
┌─────────────────────────┐
│      Web Browser        │
└───────────┬─────────────┘
            │
┌───────────┼─────────────┐
│  FastAPI Application    │
├───────────┼─────────────┤
│ DMARC Parser │ Templates │
├─────────────┬───────────┤
│      In-Memory Store    │
└─────────────────────────┘
```

### Milestone 2-3: Enhanced Architecture
- FastAPI with background tasks
- Database persistence layer
- IMAP integration
- Expanded web interface

```
┌─────────────────────────┐
│      Web Browser        │
└───────────┬─────────────┘
            │
┌───────────┼─────────────┐
│  FastAPI Application    │
├─────────┬───────┬───────┤
│Templates│Parser │IMAP   │
├─────────┴───────┴───────┤
│    Background Tasks     │
├─────────────────────────┤
│      Database Layer     │
└───────────┬─────────────┘
            │
┌───────────┼─────────────┐
│  SQLite/PostgreSQL DB   │
└─────────────────────────┘
```

### Milestone 5+: Full Architecture
- Authentication layer
- DNS integration
- Alert system
- Visualization enhancements

```
┌───────────────────────────────────────────────┐
│                 Web Browser                   │
└───────────────────┬───────────────────────────┘
                    │
┌───────────────────┼───────────────────────────┐
│             FastAPI Application               │
├────────┬──────────┬──────────┬────────┬───────┤
│Auth    │Templates │Parser    │IMAP    │Apprise│
├────────┴──────────┴──────────┴────────┴───────┤
│             Background Tasks                  │
├───────────────────────────────────────────────┤
│                Database Layer                 │
└───────────────────┬───────────────────────────┘
                    │
┌───────────────────┼───────────────────────────┐
│            SQLite/PostgreSQL DB               │
└───────────────────────────────────────────────┘
    │                │                 │
┌───┴───┐      ┌─────┴────┐      ┌─────┴────┐
│DNS API│      │Notif. API│      │Email     │
└───────┘      └──────────┘      └──────────┘
```

## Technology Stack Details

### Backend Framework
- **FastAPI**: Modern, high-performance web framework
- **Pydantic**: Data validation and settings management
- **SQLAlchemy**: ORM for database interactions
- **APScheduler**: Task scheduling for background jobs

### Frontend
- **Jinja2**: Template engine for rendering HTML
- **Tailwind CSS**: Utility-first CSS framework
- **ShadCN/UI**: Reusable UI component system
- **Chart.js**: Lightweight charting library

### External Libraries
- **parsedmarc**: DMARC report parsing
- **Apprise**: Unified notification system
- **Cloudflare API** (optional): DNS integration
- **FastAPI Users**: Authentication management

### Deployment
- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration
- **SQLite/PostgreSQL**: Database options

## Security Considerations

- Sensitive credentials are stored securely
- Authentication protects access to report data
- HTTPS recommended for production deployment
- No external APIs required for core functionality
- Self-hosted approach keeps data private