# Changelog

All notable changes to DMARQ will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-04-15

### Added
- Initial release of DMARQ
- Domain management with basic health checks
- DMARC report processing (aggregate and forensic)
- Dashboard with compliance rate visualization
- IMAP integration for automatic report collection
- User authentication and management
- SQLite and PostgreSQL database support
- Docker deployment option
- Basic alert system for compliance issues
- API for third-party integration
- Documentation site

### Security
- Secure password storage with bcrypt
- JWT-based authentication for API
- Rate limiting for API endpoints
- Input validation for all user inputs

## [0.9.0] - 2025-03-01

### Added
- Beta release for early testing
- All core functionality implemented
- Limited to SQLite database only

### Fixed
- Multiple parser bugs for different report formats
- UI responsiveness issues on mobile devices

## [0.8.0] - 2025-02-15

### Added
- Alpha release for internal testing
- Basic DMARC report parsing
- Simple domain management
- Initial dashboard design

### Known Issues
- Limited support for forensic reports
- Missing authentication features
- No alerting capabilities