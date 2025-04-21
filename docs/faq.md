# Frequently Asked Questions

## General

### What is DMARQ?

DMARQ is a DMARC (Domain-based Message Authentication, Reporting, and Conformance) reporting and analysis tool. It helps organizations monitor their email authentication status, analyze DMARC reports, and improve email deliverability and security.

### Who should use DMARQ?

DMARQ is useful for:
- IT administrators who manage email systems
- Security professionals concerned with email security
- Organizations that want to monitor their DMARC compliance
- Email marketing teams who want to improve deliverability

### Is DMARQ open source?

Yes, DMARQ is open source software licensed under the MIT License. You can freely use, modify, and distribute it according to the terms of the license.

### How much does DMARQ cost?

DMARQ is free to use. As an open source project, there's no license fee. You only need to cover the costs of hosting the application on your own infrastructure.

## Setup and Installation

### What are the system requirements for DMARQ?

The minimum requirements are:
- 1 CPU core (2+ recommended for production)
- 2GB RAM (4GB+ recommended for production)
- 20GB storage
- Docker Engine 20.10.0+ (for Docker installation)
- Python 3.9+ (for manual installation)

### How do I install DMARQ?

There are two main ways to install DMARQ:
1. **Docker**: The recommended method using Docker Compose
2. **Manual Installation**: Traditional installation on a server

See our [Docker Setup](deployment/docker.md) or [Manual Installation](deployment/manual.md) guides for detailed instructions.

### Can I run DMARQ on shared hosting?

DMARQ requires the ability to run Docker containers or a Python application server. Most shared hosting environments don't provide this level of access, so you'll likely need a VPS or dedicated server.

### How do I update DMARQ to a new version?

For Docker installations:
```bash
git pull
docker-compose down
docker-compose up -d --build
```

For manual installations:
```bash
git pull
cd backend
pip install -r requirements.txt
cd app
alembic upgrade head
# Restart your application server
```

## DMARC Reports

### What are DMARC reports?

DMARC reports are feedback reports that email providers send to domain owners about emails they receive that claim to be from your domain. There are two types:

1. **Aggregate Reports (RUA)**: XML files with statistical data about email authentication results
2. **Forensic Reports (RUF)**: Detailed reports about specific authentication failures

### How do I receive DMARC reports?

You need to publish a DMARC record in your domain's DNS that includes your reporting email address. For example:
```
v=DMARC1; p=none; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com
```

### How does DMARQ collect DMARC reports?

DMARQ can collect reports in three ways:
1. **IMAP Integration**: Automatically fetching from your email inbox
2. **Manual Upload**: Uploading reports through the web interface
3. **API Upload**: Sending reports via the API

### How far back can I see DMARC data?

DMARQ stores all the data you import, so you can see historical data from the point you started collecting reports. There's no built-in limit to how far back data can be stored.

## Using DMARQ

### How do I add a domain to monitor?

1. Log in to DMARQ
2. Navigate to the Domains section
3. Click "Add Domain"
4. Enter your domain name and click "Add"

### Can I monitor multiple domains?

Yes, DMARQ supports monitoring an unlimited number of domains. You can add all the domains you want to track in the Domains section.

### How often are reports processed?

If you're using IMAP integration, reports are processed according to your configured polling interval (default is every 60 minutes). Manually uploaded reports are processed immediately.

### What should my DMARC policy be?

DMARQ can help you make this decision by showing your current compliance rate, but typically:
- Start with `p=none` to monitor without affecting delivery
- Move to `p=quarantine` when you reach 90%+ compliance
- Move to `p=reject` when you reach 95%+ compliance

## Technical Questions

### Can I use an external database?

Yes, DMARQ supports both SQLite (for smaller deployments) and PostgreSQL (for production). You can configure an external PostgreSQL database in your environment variables.

### How do I back up DMARQ data?

For SQLite:
```bash
cp data/dmarq.db backup-$(date +%Y%m%d).db
```

For PostgreSQL:
```bash
docker-compose exec db pg_dump -U dmarq dmarq > backup-$(date +%Y%m%d).sql
```

### Can I run DMARQ behind a reverse proxy?

Yes, DMARQ works well behind a reverse proxy like Nginx or Apache. This is recommended for production deployments. See our [Docker Setup](deployment/docker.md) guide for an example Nginx configuration.

### What API endpoints are available?

DMARQ provides a comprehensive REST API. See the [API Reference](reference/api.md) for detailed documentation of all available endpoints.

## Troubleshooting

### Why am I not seeing any reports?

Check the following:
1. Verify your DMARC record is correctly published in DNS
2. Ensure your reporting email is correctly set up
3. Check IMAP settings if using IMAP integration
4. Confirm that enough time has passed (can take 24-48 hours to start receiving reports)

### IMAP integration isn't working. What should I check?

1. Verify your IMAP server and port are correct
2. Check that your username and password are correct
3. Ensure IMAP access is enabled for your email account
4. If using Gmail, you may need to create an app-specific password
5. Check if your email provider requires special settings

### How do I report a bug?

You can report bugs on our [GitHub Issues](https://github.com/yourusername/dmarq/issues) page. Please include:
1. Steps to reproduce the issue
2. Expected behavior
3. Actual behavior
4. DMARQ version
5. Any relevant error messages

### I'm getting database errors. How do I fix them?

For SQLite:
1. Create a backup of your database file
2. Run the database integrity check: `sqlite3 data/dmarq.db "PRAGMA integrity_check;"`

For PostgreSQL:
1. Check database connection parameters
2. Verify the database server is running
3. Check for disk space issues

## Contributing

### How can I contribute to DMARQ?

There are many ways to contribute:
1. Code contributions (features, bug fixes)
2. Documentation improvements
3. Testing and bug reporting
4. Translations
5. Feature suggestions

See our [Contributing Guide](development/contributing.md) for more information.

### Where do I find the source code?

The source code is available on GitHub: [https://github.com/yourusername/dmarq](https://github.com/yourusername/dmarq)

### Is there a community forum?

We're building a community around DMARQ. For now, you can:
1. Join discussions in the GitHub repository
2. Ask questions in the issue tracker
3. Connect with other users in the #dmarq channel on the Email Security Discord