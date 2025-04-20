# DMARQ Documentation

<div class="grid cards" markdown>

- ![Dashboard Icon](assets/imgs/dashboard-icon.svg){ .lg .middle } **Dashboard**
  
  Visualize your DMARC compliance with intuitive charts and metrics.

  [:octicons-arrow-right-24: View Dashboard Docs](user_guide/dashboard.md)

- ![Domains Icon](assets/imgs/domains-icon.svg){ .lg .middle } **Domain Management**
  
  Add, configure, and monitor email domains with ease.

  [:octicons-arrow-right-24: Domain Documentation](user_guide/domains.md)

- ![Reports Icon](assets/imgs/reports-icon.svg){ .lg .middle } **DMARC Reports**
  
  Receive, parse, and analyze DMARC aggregate reports.

  [:octicons-arrow-right-24: Report Docs](user_guide/reports.md)

- ![IMAP Icon](assets/imgs/imap-icon.svg){ .lg .middle } **IMAP Integration**
  
  Automatically fetch reports from your email inbox.

  [:octicons-arrow-right-24: IMAP Setup](user_guide/imap.md)

</div>

## What is DMARQ?

DMARQ is a modern, user-friendly tool designed to make DMARC (Domain-based Message Authentication, Reporting, and Conformance) implementation accessible for everyone. With a focus on clarity, automation, and actionable insights, DMARQ enables organizations to safeguard their email domains, prevent phishing attacks, and ensure compliance with industry best practices.

## Quick Start Guide

Get started with DMARQ in minutes:

1. [Install DMARQ](deployment/docker.md) using Docker or manual installation
2. [Add your domain](user_guide/domains.md#adding-a-domain) to the system
3. [Configure IMAP](user_guide/imap.md) to automatically fetch reports (optional)
4. [View your dashboard](user_guide/dashboard.md) to monitor compliance

## Features

- **Intuitive Dashboard**: Get a clear overview of your email authentication status
- **Automatic Report Processing**: Parse and analyze DMARC reports with ease
- **Multi-domain Support**: Monitor multiple domains from a single interface
- **IMAP Integration**: Automatically fetch reports from your inbox
- **Detailed Analytics**: Dive deep into authentication results and trends
- **Policy Management**: Safely transition to stricter DMARC policies

## About DMARC

DMARC (Domain-based Message Authentication, Reporting, and Conformance) is an email authentication protocol that helps organizations protect their domain from unauthorized use, commonly known as email spoofing. It builds upon two existing mechanisms:

- **SPF (Sender Policy Framework)**: Specifies which mail servers are authorized to send email on behalf of your domain
- **DKIM (DomainKeys Identified Mail)**: Adds a digital signature to emails, allowing receiving servers to verify the email wasn't altered in transit

By implementing DMARC, domain owners can tell receiving mail servers what to do with messages that don't pass SPF or DKIM authentication checks, while also receiving reports about these authentication failures.

## Get Support

Need help with DMARQ? We're here to assist:

- [Frequently Asked Questions](faq.md)
- [GitHub Issues](https://github.com/yourusername/dmarq/issues)
- Email support: support@example.com