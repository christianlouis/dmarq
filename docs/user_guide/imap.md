# IMAP Integration

DMARQ can automatically retrieve DMARC reports from your email inbox using IMAP. This guide explains how to set up and manage IMAP integration.

## Overview

DMARC reports are typically sent to a dedicated email address that you specify in your DMARC record. DMARQ can connect to this mailbox using IMAP to fetch and process these reports automatically.

## Prerequisites

Before configuring IMAP integration, you need:

1. An email account dedicated to receiving DMARC reports
2. IMAP access enabled for this email account
3. Your DMARC record configured to send reports to this email address

## Configuration Steps

### 1. Enable IMAP Integration

1. Navigate to **Settings** > **IMAP Integration**
2. Toggle **Enable IMAP** to ON

### 2. Enter IMAP Server Details

Fill in the following information:
- **IMAP Server**: The hostname of your IMAP server (e.g., `imap.gmail.com`)
- **IMAP Port**: The port number (typically 993 for SSL)
- **Use SSL/TLS**: Toggle ON for secure connections (recommended)

### 3. Enter Authentication Details

- **Username**: Your email address
- **Password**: Your email password or app password
  - For Gmail and other providers with 2FA, you'll need to create an app-specific password

### 4. Configure Mailbox Settings

- **Folder**: The mailbox folder to check for reports (usually "INBOX")
- **Polling Interval**: How frequently DMARQ should check for new reports (e.g., every 60 minutes)
- **Report Processing**: Choose what to do after processing:
  - Mark as read
  - Move to a specific folder
  - Delete after processing

### 5. Test Connection

1. Click **Test Connection** to verify your IMAP settings
2. DMARQ will attempt to connect and report success or failure
3. If successful, you'll see the number of unread messages in the specified folder

## Advanced IMAP Settings

### Email Filtering

You can configure DMARQ to only process certain emails:

- **Subject Filter**: Only process emails with subjects containing specific text
- **Sender Filter**: Only process emails from specific senders
- **Age Filter**: Only process emails newer than a specific age

### Attachment Handling

Configure how DMARQ handles report attachments:

- **Supported Formats**: XML, ZIP, GZ, EML
- **Size Limit**: Maximum attachment size to process (default: 10MB)
- **Processing Priority**: Which attachments to process first

### Troubleshooting IMAP Connections

If you're having trouble with IMAP integration:

1. **Check Credentials**: Verify username and password are correct
2. **Verify Server Settings**: Confirm IMAP server address and port
3. **Check IMAP Access**: Ensure IMAP is enabled for your email account
4. **App Passwords**: If using 2FA, verify you're using an app-specific password
5. **Firewall Issues**: Ensure your DMARQ instance can connect to your IMAP server
6. **View IMAP Logs**: Check the IMAP connection logs in **Settings** > **Logs**

## Managing IMAP Integration

### Monitoring Activity

You can monitor IMAP integration activity:

1. Navigate to **Settings** > **IMAP Integration**
2. View the **Activity Log** section
3. Check when reports were last fetched and how many were processed

### Pausing Integration

To temporarily disable IMAP fetching:

1. Navigate to **Settings** > **IMAP Integration**
2. Toggle **Enable IMAP** to OFF
3. Click **Save Changes**

DMARQ will stop checking for new reports until you re-enable the integration.