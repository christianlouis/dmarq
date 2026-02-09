# XSS Vulnerability Fixes - Quick Reference

This document provides specific code fixes for the XSS vulnerabilities identified in the code quality audit.

## Issue 1: dashboard.js - Line 234

### ❌ VULNERABLE CODE
```javascript
row.innerHTML = `
    <td>${domainName}</td>
    <td>${formattedDate}</td>
    <td>${report.is_compliant ? 
        '<span style="color: green;">Compliant</span>' : 
        '<span style="color: red;">Non-compliant</span>'
    }</td>
`;
```

### ✅ SECURE FIX
```javascript
// Create row
const row = document.createElement('tr');

// Domain cell - safe text content
const domainCell = document.createElement('td');
domainCell.textContent = domainName;
row.appendChild(domainCell);

// Date cell - safe text content
const dateCell = document.createElement('td');
dateCell.textContent = formattedDate;
row.appendChild(dateCell);

// Compliance status cell
const statusCell = document.createElement('td');
const statusSpan = document.createElement('span');
statusSpan.textContent = report.is_compliant ? 'Compliant' : 'Non-compliant';
// Use CSS classes instead of inline styles
statusSpan.className = report.is_compliant ? 'text-success' : 'text-error';
row.appendChild(statusCell.appendChild(statusSpan));
```

### Alternative using DaisyUI classes
```javascript
statusSpan.className = report.is_compliant ? 'badge badge-success' : 'badge badge-error';
```

## Issue 2: dashboard.js - Line 15

### ❌ VULNERABLE CODE
```javascript
alertDiv.innerHTML = message;
```

### ✅ SECURE FIX
```javascript
alertDiv.textContent = message;
```

## Issue 3: login.js - Line 9

### ❌ VULNERABLE CODE
```javascript
errorDiv.innerHTML = `<div class="alert alert-error">${message}</div>`;
```

### ✅ SECURE FIX
```javascript
// Clear existing content
errorDiv.innerHTML = '';

// Create alert div
const alertDiv = document.createElement('div');
alertDiv.className = 'alert alert-error';
alertDiv.textContent = message;

// Append to error div
errorDiv.appendChild(alertDiv);
```

### Even Safer Alternative
```javascript
function showError(message) {
    const errorDiv = document.getElementById('error-div');
    errorDiv.innerHTML = ''; // Clear previous errors
    
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-error';
    
    const icon = document.createElement('svg');
    icon.innerHTML = '<path d="..."/>'; // Safe - controlled SVG path
    icon.className = 'stroke-current shrink-0 h-6 w-6';
    
    const span = document.createElement('span');
    span.textContent = message; // User input here - safe
    
    alertDiv.appendChild(icon);
    alertDiv.appendChild(span);
    errorDiv.appendChild(alertDiv);
}
```

## Issue 4: setup.js - Line 9

### ❌ VULNERABLE CODE
```javascript
alertDiv.innerHTML = message;
```

### ✅ SECURE FIX
```javascript
alertDiv.textContent = message;
```

## Issue 5: Credentials in localStorage (setup.js Lines 188-189)

### ❌ INSECURE CODE
```javascript
localStorage.setItem('setup_cloudflare_token', cloudflareToken);
localStorage.setItem('setup_cloudflare_zone', cloudflareZone);
```

### ✅ SECURE FIX

**Step 1: Remove client-side storage**
```javascript
// DELETE these lines completely
// localStorage.setItem('setup_cloudflare_token', cloudflareToken);
// localStorage.setItem('setup_cloudflare_zone', cloudflareZone);
```

**Step 2: Send to backend immediately**
```javascript
async function saveCloudflareCredentials(token, zone) {
    const response = await fetch('/api/v1/settings/cloudflare', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${getAuthToken()}`,
        },
        body: JSON.stringify({
            cloudflare_api_token: token,
            cloudflare_zone_id: zone
        })
    });
    
    if (!response.ok) {
        throw new Error('Failed to save Cloudflare credentials');
    }
    
    // Don't store the actual credentials - just a success flag
    sessionStorage.setItem('cloudflare_configured', 'true');
}
```

**Step 3: Backend endpoint (Python)**
```python
from app.core.security import encrypt_credential

@router.post("/api/v1/settings/cloudflare")
async def save_cloudflare_credentials(
    credentials: CloudflareCredentials,
    current_user: User = Depends(get_current_user)
):
    """Save Cloudflare credentials securely"""
    # Encrypt before storing
    encrypted_token = encrypt_credential(credentials.cloudflare_api_token)
    encrypted_zone = encrypt_credential(credentials.cloudflare_zone_id)
    
    # Store in database with encryption
    db.store_setting("cloudflare_token", encrypted_token, user_id=current_user.id)
    db.store_setting("cloudflare_zone", encrypted_zone, user_id=current_user.id)
    
    return {"success": True, "message": "Credentials saved securely"}
```

## Testing Your Fixes

### Manual XSS Test Cases

**Test 1: Malicious Domain Name**
```javascript
// Try injecting this as a domain name
const maliciousDomain = '<img src=x onerror=alert("XSS")>';

// With vulnerable code: XSS executes
// With fixed code: Displays as text (safe)
```

**Test 2: Script Injection**
```javascript
// Try injecting this as a message
const maliciousMessage = '<script>alert("XSS")</script>';

// With vulnerable code: Script executes
// With fixed code: Displays as text (safe)
```

**Test 3: Event Handler Injection**
```javascript
// Try injecting this
const maliciousData = '<div onmouseover="alert(\'XSS\')">Hover me</div>';

// With vulnerable code: XSS on hover
// With fixed code: Displays as text (safe)
```

### Automated Testing

```javascript
// Add to your test suite
describe('XSS Prevention Tests', () => {
    const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        'javascript:alert("XSS")',
    ];
    
    xssPayloads.forEach(payload => {
        it(`should safely handle XSS payload: ${payload}`, () => {
            const element = renderDomainRow(payload, new Date(), {is_compliant: true});
            
            // Check that payload is not executed
            expect(element.innerHTML).not.toContain('<script>');
            expect(element.innerHTML).not.toContain('onerror=');
            
            // Check that it's displayed as text
            expect(element.textContent).toContain(payload);
        });
    });
});
```

## CSP Header Update

After fixing the XSS issues, update your CSP header in `backend/app/middleware/security.py`:

### Current (Insecure)
```python
"script-src 'self' 'unsafe-inline' 'unsafe-eval'",
"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
```

### Target (Secure)
```python
"script-src 'self'",  # No unsafe-inline needed
"style-src 'self' https://fonts.googleapis.com",  # No unsafe-inline needed
```

## Verification Checklist

- [ ] All `innerHTML` usage replaced with safe DOM methods
- [ ] All user input uses `textContent` not `innerHTML`
- [ ] No credentials stored in localStorage
- [ ] Inline styles replaced with CSS classes
- [ ] CSP headers updated to remove 'unsafe-inline'
- [ ] Manual XSS testing completed
- [ ] Automated tests added
- [ ] Code review completed

## Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN: Element.textContent](https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent)
- [MDN: Document.createElement](https://developer.mozilla.org/en-US/docs/Web/API/Document/createElement)
- [Content Security Policy Reference](https://content-security-policy.com/)
