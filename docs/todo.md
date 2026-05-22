# DMARQ Implementation Todo List

This file tracks the specific implementation tasks for each milestone of the DMARQ project.

## Milestone 1: Minimal Viable Product (MVP)

### Infrastructure Setup
- [x] Set up FastAPI project structure
- [x] Configure Tailwind CSS
- [x] Create Docker and Docker Compose files
- [ ] Set up CI/CD pipeline (optional for MVP)

### Core DMARC Parser
- [x] Integrate parsedmarc library
- [x] Create parsing service for DMARC XML reports
- [x] Add support for ZIP/GZ compression extraction
- [x] Implement validation for uploaded reports

### Data Models
- [x] Create Domain model
- [x] Create AggregateReport model
- [x] Create ReportRecord model for individual sending sources
- [x] Design in-memory storage for MVP phase

### API Endpoints
- [x] Create domain registration endpoint
- [x] Create report upload endpoint
- [x] Create domain summary endpoints
- [x] Create detailed report view endpoints

### Frontend
- [x] Create base layout template
- [x] Implement dashboard overview page
- [x] Create domain list component
- [x] Build report upload interface
- [x] Implement domain detail view
- [x] Create report detail view
- [x] Add basic visualization components for report statistics

### Testing
- [x] Create unit tests for parser
- [x] Create API tests
- [x] Collect sample DMARC reports for testing
- [x] Manual UI testing

### Documentation
- [x] Create user guide for MVP
- [x] Document deployment instructions
- [x] Add sample screenshots

## Milestone 2: IMAP Integration

### IMAP Client
- [x] Create IMAP connection service
- [x] Implement mailbox search functionality for DMARC reports
- [x] Add attachment extraction capabilities
- [x] Create email filtering logic (by sender, subject)
- [x] Add processed email tracking

### Scheduler
- [x] Implement background task system
- [x] Create scheduler for periodic mailbox checking
- [x] Add timestamp tracking for fetched reports
- [x] Create logging for background processes

### Configuration
- [x] Create configuration model for IMAP settings
- [x] Build configuration UI
- [x] Implement secure credential storage
- [x] Add connection testing functionality

### Frontend Updates
- [x] Add IMAP configuration page
- [x] Create last sync indicator
- [x] Implement manual sync trigger button
- [x] Add status indicators for background processes

## Milestone 2A: Gmail and Mail Import Reliability

### Gmail API Import
- [x] Create Gmail OAuth mail source flow
- [x] Search Gmail for likely DMARC aggregate report messages
- [x] Match Google DMARC subjects like `Report domain: example.com Submitter: google.com`
- [x] Parse Google-style ZIP attachments such as `google.com!example.com!begin!end.zip`
- [x] Use the shared DMARC parser for Gmail imports
- [x] Track ingested Gmail message IDs

### Duplicate and Error Handling
- [x] Skip duplicate domain/report IDs during Gmail imports
- [x] Skip duplicate domain/report IDs during IMAP imports
- [x] Persist sanitized import errors for API/UI review
- [x] Count duplicate skips separately from parse failures
- [x] Show recent import history in the Mail Sources UI
- [x] Add manual import trigger per mail source
- [x] Add per-import result details for duplicates, parse failures, unsupported attachments, and imported report IDs
- [x] Add retry/backfill controls per mail source

## Milestone 3: Database Integration

### Database Setup
- [x] Set up SQLAlchemy ORM
- [x] Create SQLite database (for initial version)
- [x] Design database schema with migrations
- [x] Implement data access layer

### Model Migration
- [x] Convert report ingestion and dashboard reads from in-memory storage to database-backed storage
- [x] Create Domain table
- [x] Create AggregateReport table
- [x] Create ReportRecord table for sender details
- [x] Implement relationships between models
- [x] Persist parsed upload reports to `dmarc_reports` and `report_records`
- [x] Persist parsed Gmail/IMAP reports to `dmarc_reports` and `report_records`
- [x] Load/query persisted reports after app restart

### Domain Management
- [x] Create UI for adding/editing domains
- [x] Implement domain validation
- [x] Add domain deletion with data cleanup
- [x] Create domain filtering/search for larger sets

### Query Optimization
- [x] Add pagination for large report sets
- [x] Implement efficient queries for dashboard stats
- [x] Create data summarization for performance
- [x] Add database indexes for common queries

## Milestone 4: Dashboard Enhancements

### Data Visualization
- [x] Integrate Chart.js library
- [x] Create time-series charts for DMARC compliance
- [x] Add volume charts for email traffic
- [x] Implement sender breakdown visualizations
- [ ] Create policy distribution charts

### Dashboard Widgets
- [ ] Create compliance rate summary widget
- [ ] Add enforcement rate widget
- [x] Implement email volume trends widget
- [x] Create top sender sources widget
- [ ] Add alert status summary (for later integration)

### Historical Data
- [x] Implement date range filtering
- [ ] Create historical trend analysis
- [ ] Add data aggregation for different time periods
- [ ] Implement data comparison features

### Meaningful Reports
- [x] Add per-domain daily rollups
- [x] Add sender/source pass/fail totals
- [x] Add newly observed source detection
- [x] Add exportable domain reports
- [x] Add actionable recommendations for common DMARC failure patterns

## Future Milestones
- [x] Production secret handling guide using 1Password injection
- [ ] Apprise notifications and alert rules
- [ ] DNS health guidance and Cloudflare read-only inspection
- [ ] Guided setup and operator health pages
- [ ] Forensic/RUF report support
