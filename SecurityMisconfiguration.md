# CS-003 — Security Misconfiguration
### OWASP Juice Shop · Verbose Error Handling & Directory Listing

---

## Overview

| Field | Detail |
|-------|--------|
| **Target** | OWASP Juice Shop (`localhost:3000`) |
| **Category** | Security Misconfiguration (OWASP A05:2021) |
| **Severity** | 🟠 High (Error Handling) · 🟠 High (Directory Listing) |
| **Techniques** | Error Provocation, Directory Traversal via robots.txt |
| **Tools** | Burp Suite, Browser (Kali Linux) |
| **Environment** | Node.js / Express.js backend, SQLite database |

---

## Objective

Identify and exploit security misconfiguration vulnerabilities in OWASP Juice Shop:
1. Provoke unhandled errors that leak database schema, file paths, and query structure
2. Discover and access an open FTP directory exposing confidential business documents without authentication

---

## Background — What is Security Misconfiguration?

Security Misconfiguration occurs when a system is set up incorrectly, not due to a bug in the code logic, but because of poor configuration choices. According to OWASP data, it ranked **#2 in 2025** (up from #5 in 2021), reflecting how common configuration mistakes are across production environments.

**Common examples:**
- Verbose error messages exposing stack traces and internal paths
- Directory listing enabled on web servers
- Default credentials not changed after installation
- Debug mode left enabled in production
- Missing HTTP security headers (CSP, HSTS, X-Frame-Options)
- Cloud storage buckets publicly accessible

---

## Reconnaissance

### Manual Application Browsing
- Mapped all visible endpoints using Burp Suite HTTP History
- Noted the search bar sends `GET /rest/products/search?q=<term>` requests
- Checked `robots.txt` for disallowed paths — standard reconnaissance step

**`robots.txt` Discovery:**
```
GET http://localhost:3000/robots.txt

User-agent: *
Disallow: /ftp
```

> The `robots.txt` file is intended to instruct search engine crawlers — but it also **advertises sensitive paths to attackers**. The `/ftp` path was immediately flagged for investigation.

---

## Exploitation

### Finding 1 — Verbose Error Handling (Stack Trace Disclosure)

**Severity:** 🟠 High  
**Root Cause:** No global error handler; `NODE_ENV` not set to production; raw SQL queries used without parameterization

**Steps:**
1. Open Burp Suite, browse Juice Shop, capture `GET /rest/products/search?q=apple`

<img width="600" height="222" alt="image" src="https://github.com/user-attachments/assets/26441f0f-9c78-43ef-9f4b-2f3f1d42ee10" />

3. Send to Repeater
4. Modify the `q` parameter to an invalid SQL fragment: `q=',1,1,1--`

<img width="600" height="501" alt="image" src="https://github.com/user-attachments/assets/4c8710b1-e2d0-432d-b61f-cd5ad64b294c" />

**Modified Request:**
```http
GET /rest/products/search?q=',1,1,1-- HTTP/1.1
Host: localhost:3000
Authorization: Bearer <token>
```

**Server Response (500 Error):**
```json
{
  "error": {
    "message": "SQLITE_ERROR: incomplete input",
    "stack": "Error: SQLITE_ERROR: incomplete input",
    "errno": 1,
    "code": "SQLITE_ERROR",
    "sql": "SELECT * FROM Products WHERE (name LIKE '%',1,1,1--%'
            OR description LIKE '%',1,1,1--%')
            AND deletedAt IS NULL ORDER BY name"
  }
}
```

**Sensitive Information Exposed:**
| Type | Leaked Data |
|------|-------------|
| Database Engine | SQLite (confirms attack surface) |
| Table Name | `Products` |
| Column Names | `name`, `description`, `deletedAt` |
| SQL Query Logic | Full WHERE clause revealed |
| Error Layer | Database-level (confirms raw queries, not ORM) |

<img width="600" height="427" alt="image" src="https://github.com/user-attachments/assets/c2567172-3564-4d24-b05f-a7d8e202bdd2" />

> ✅ **Challenge Completed:** "Error Handling" — Provoke an error that is neither very gracefully nor consistently handled.

---

### Finding 2 — Open FTP Directory (Confidential Document Exposure)

**Severity:** 🟠 High  
**Root Cause:** Directory listing enabled without authentication; sensitive files stored in publicly accessible path

**Steps:**
1. After discovering `/ftp` in `robots.txt`, navigate to `http://localhost:3000/ftp`

<img width="600" height="246" alt="image" src="https://github.com/user-attachments/assets/e1b3aee7-7a8d-4fe1-bcf9-8282055f89ef" />

3. Full directory listing rendered in browser — no authentication required

<img width="600" height="292" alt="image" src="https://github.com/user-attachments/assets/73f41656-1d62-4f6b-a986-ac25c288ae5e" />

**Directory Contents (`/ftp`):**
```
~/ftp
├── 📁 quarantine/
├── 📄 acquisitions.md          ← Planned acquisition targets (CONFIDENTIAL)
├── 📄 announcement_encrypted.md
├── 📄 coupons_2013.md.bak
├── 📄 eastere.gg
├── 📄 encrypt.pyc
├── 📄 incident-support.kdbx
├── 📄 legal.md                  ← Legal/Terms document
├── 📄 package-lock.json.bak
├── 📄 package.json.bak
└── 📄 suspicious_errors.yml
```

**Contents of `acquisitions.md`:**
```markdown
# Planned Acquisitions

> This document is confidential! Do not distribute!

Our company plans to acquire several competitors within the next year.
This will have a significant stock market impact...

Our shareholders will be excited. It's true. No fake news.
```

> This document is flagged as **confidential** yet is freely downloadable with zero authentication. In a real organization, this would constitute a serious data leak with regulatory and legal implications.

<img width="600" height="538" alt="image" src="https://github.com/user-attachments/assets/e058e63a-16a6-4150-bcff-8774e902d951" />
<img width="600" height="390" alt="image" src="https://github.com/user-attachments/assets/e7241f5b-7d9d-4400-9380-00f3e94e317f" />

> ✅ **Challenge Completed:** "Confidential Document" — Access a confidential document.
> ✅ **Challenge Completed:** "Score Board" — Find the carefully hidden Score Board page.

---

## Root Cause Analysis

### Finding 1 — Verbose Error Handling
```
Root Causes:
  1. No global error handling middleware — default Express error handler
     sends full error object to the client
  2. NODE_ENV not set to 'production' — disables automatic error sanitization
  3. Raw SQL queries (not ORM) — error messages include full SQL text
  4. No input validation on search parameter before database query
```

### Finding 2 — Directory Listing
```
Root Causes:
  1. express.static() serving /ftp with no index:false config
  2. No authentication middleware on /ftp route
  3. Sensitive business documents stored in a web-accessible directory
  4. robots.txt advertising the path (security through obscurity ≠ security)
```

---

## Remediation

### Fix 1 — Global Error Handler (Express.js)

```javascript
// Secure global error handler — add as LAST middleware
app.use((err, req, res, next) => {
  // Log full details SERVER-SIDE only
  console.error('[ERROR]', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  const isProd = process.env.NODE_ENV === 'production';

  res.status(err.status || 500).json({
    // In production: generic message only, no internal details
    error: isProd ? 'An unexpected error occurred.' : err.message
  });
});
```

**Set environment variable:**
```bash
NODE_ENV=production node server.js
```

### Fix 2 — Disable FTP Directory Access

**Option A — Block entirely:**
```javascript
// Block all access to /ftp
app.use('/ftp', (req, res) => {
  res.status(403).json({ error: 'Access denied.' });
});
```

**Option B — Require authentication + disable directory listing:**
```javascript
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token || !verifyToken(token)) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  next();
};

app.use('/ftp', requireAuth, express.static(path.join(__dirname, 'ftp'), {
  index: false,      // Disables directory listing
  dotfiles: 'deny'
}));
```

---

## Production Configuration Checklist

Based on findings, all production deployments should verify:

| Setting | Required Value | Risk if Not Set |
|---------|---------------|-----------------|
| `NODE_ENV` | `production` | Stack traces exposed to users |
| Debug Mode | Disabled | Internal paths and configs exposed |
| Global Error Handler | Implemented | Raw errors reach client |
| Directory Listing | Disabled | File structure enumeration |
| HTTP Security Headers | CSP, HSTS, X-Frame-Options | Multiple client-side attack vectors |
| Sensitive Files | Behind authentication | Confidential data exposure |
| `robots.txt` | Reviewed for sensitive paths | Advertises attack surface |

---

## Impact Assessment

| Finding | Business Impact |
|---------|----------------|
| Stack Trace Disclosure | Accelerates SQLi attacks; reveals tech stack for targeted exploits |
| Schema Exposure | Attacker can craft precise UNION queries without blind enumeration |
| Confidential Documents | M&A plans exposed — insider trading risk, legal liability |
| Backup Files (`.bak`) | May contain old credentials, configs, source code |

---

## Conclutions

1. **`robots.txt` is not a security control.** It tells attackers exactly where to look. Sensitive paths must be protected by authentication, not obscured by crawler hints.
2. **Default error handlers are dangerous in production.** Express.js (and most frameworks) will return detailed error objects by default. A global error handler is mandatory before going live.
3. **Web-accessible directories should never contain sensitive files.** Business documents, legal files, and database backups must live outside the web root or behind strict authentication.
4. **`NODE_ENV=production` matters.** Many frameworks (including Express) automatically change behavior based on this flag — error verbosity, caching, and security defaults all improve in production mode.

---

