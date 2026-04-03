# CS-007 — Identification & Authentication Security
### Policy Design · OWASP ASVS · NIST SP 800-63B

---

## 📋 Overview

| Field | Detail |
|-------|--------|
| **Category** | Identification and Authentication Failures (OWASP A07:2021) |
| **Type** | Defensive Policy & Architecture Design |
| **Standards** | OWASP ASVS V2 Authentication, NIST SP 800-63B |
| **Deliverable** | Secure Authentication Policy for Web Applications |

---

## 🎯 Objective

Design a comprehensive, standards-compliant authentication security policy for web applications, covering:
- Secure password requirements and storage
- Login protection mechanisms
- Multi-factor authentication (MFA) strategy
- Session security controls
- Analysis of common authentication failure patterns

---

## 📖 Background

**Identification** is the process of claiming an identity — typically via username or email.  
**Authentication** is the process of *proving* that identity — typically via password, token, biometric, or a combination.

Authentication failures rank **#7 in OWASP Top 10** (2021) — indicating these vulnerabilities remain widespread despite being well-understood. The two root causes are:

1. **User factors** — Weak password choices, susceptibility to phishing/social engineering
2. **Application factors** — Failure to enforce strong authentication policies server-side

---

## 🔓 Common Vulnerabilities

### Vulnerability 1 — Weak Password Policy

Applications that allow common or short passwords expose users to:

```
Attack Type : Credential Stuffing (using leaked password lists)
Attack Type : Brute Force (systematic password guessing)
Attack Type : Dictionary Attack (common word combinations)

Example weak passwords accepted by misconfigured apps:
  - "password", "123456", "admin", "qwerty"
  - User's name or date of birth
  - Passwords under 8 characters
```

### Vulnerability 2 — No Login Rate Limiting

Without attempt limiting, automated tools can test thousands of passwords per second:

```
Tool       : Hydra, Burp Intruder, custom scripts
Attack     : Brute force / credential stuffing
Speed      : 1,000–100,000 attempts/second (depending on app response time)
Mitigation : Account lockout, CAPTCHA, progressive delays, IP rate limiting
```

### Vulnerability 3 — Plaintext Password Storage

```sql
-- What attackers find in a leaked database dump
SELECT username, password FROM users;

username  | password
admin     | admin123
john.doe  | Summer2024!
```

**Impact:** Immediate access to all accounts. Credentials likely reused on other platforms.

### Vulnerability 4 — Missing Session Security

```
Risk Scenario: Session ID not regenerated after login
  → Attacker fixes session ID before login
  → Victim authenticates → Attacker's session ID is now authenticated
  → Session fixation attack succeeds

Risk Scenario: Session never expires
  → Attacker captures session cookie via XSS or network sniff
  → Cookie remains valid indefinitely
  → No time limit on attacker's access window
```

### Vulnerability 5 — Single-Factor Only

```
If password is breached (phishing, data breach, reuse):
  → Without MFA: Attacker has immediate, complete access
  → With MFA: Attacker is blocked at second factor
  → MFA reduces account takeover risk by ~99.9% (Microsoft telemetry)
```

---

## 📐 Authentication Security Policy

### Policy 1 — Password Requirements

Based on **OWASP ASVS V2** and **NIST SP 800-63B**:

```
Minimum length    : 12 characters (NIST recommends up to 64)
Maximum length    : 128 characters (bcrypt truncates at 72 — hash pre-process if longer)
Complexity        : At least one: uppercase, lowercase, number, special character
Prohibited values :
  - Top 10,000 common passwords (check against blocklist)
  - Username or email address as password
  - Sequential or repeated characters (aaaaaa, 123456)
  - Context-specific words (company name, service name)
Expiry policy     : Do NOT force periodic rotation (NIST 800-63B §5.1.1.2)
                    Only require change on evidence of compromise
```

> **NIST Note:** Mandatory password rotation without evidence of compromise leads to predictable patterns (`Password1!` → `Password2!`) and reduces overall security. NIST SP 800-63B explicitly recommends against it.

### Policy 2 — Login Attempt Limiting

```
Max failed attempts  : 5 per account within 15 minutes
Lockout response     : Progressive delay (2s → 10s → 60s → temporary lock)
Account lock period  : 15 minutes (auto-unlock) OR manual unlock via email
IP rate limiting     : 20 attempts per IP per minute across all accounts
CAPTCHA trigger      : After 3 failed attempts from same session
Notification         : Alert account owner of failed login attempts via email
```

**Implementation (Express.js with rate-limiter-flexible):**
```javascript
const { RateLimiterMemory } = require('rate-limiter-flexible');

const loginLimiter = new RateLimiterMemory({
  points: 5,              // 5 attempts
  duration: 15 * 60,      // per 15 minutes
  blockDuration: 15 * 60  // lock for 15 minutes
});

app.post('/login', async (req, res) => {
  try {
    await loginLimiter.consume(req.ip);
    // Proceed with authentication
  } catch (e) {
    res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }
});
```

### Policy 3 — Password Storage

```
Algorithm      : bcrypt (rounds = 12) or Argon2id (recommended for new systems)
Never use      : MD5, SHA-1, SHA-256 alone (not designed for passwords)
Salt           : Automatic (bcrypt/Argon2 handle this internally)
Pepper         : Optional — server-side secret added before hashing (stored separately from DB)
```

```python
# Python implementation
import bcrypt

# Registration
def store_password(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode()

# Login verification
def verify_login(plaintext: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(plaintext.encode('utf-8'), stored_hash.encode('utf-8'))
```

### Policy 4 — Multi-Factor Authentication (MFA)

```
Required for       : Admin accounts, privileged roles, first login from new device
Recommended for    : All user accounts
Accepted factors   :
  - TOTP (Time-based OTP): Google Authenticator, Authy, Microsoft Authenticator
  - SMS OTP              : Acceptable but vulnerable to SIM swapping (use as fallback)
  - Email OTP            : Acceptable; 15-minute expiry
  - Hardware keys        : FIDO2/WebAuthn (highest assurance — recommended for admins)

Recovery codes     : Generate 8–10 single-use backup codes on MFA setup
Re-authentication  : Require current password before changing email, password, or MFA
```

### Policy 5 — CAPTCHA

```
When to apply  : After 3 failed login attempts from same session
                 On all registration forms
                 On password reset forms
Type           : hCaptcha or reCAPTCHA v3 (invisible, score-based)
Purpose        : Prevent automated brute force and credential stuffing bots
```

### Policy 6 — Session Security

```
Session ID         : Generate new ID after successful login (prevent session fixation)
ID entropy         : Minimum 128 bits of randomness
ID storage         : Cookie only (not URL parameter)
Idle timeout       : 15–30 minutes for sensitive applications
Absolute timeout   : 8–24 hours (force re-login regardless of activity)
Logout             : Invalidate server-side session record immediately

Cookie flags:
  Secure   : true  — HTTPS only
  HttpOnly : true  — Block JavaScript access
  SameSite : Strict — Prevent cross-site submission
```

---

## 🏗️ Secure Authentication Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Browser                         │
│  HTTPS (TLS 1.2+)  │  Secure Cookies  │  HSTS enforced     │
└─────────────────────┬───────────────────────────────────────┘
                      │ Encrypted channel
┌─────────────────────▼───────────────────────────────────────┐
│                    Application Server                        │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Rate Limiter│  │ Input         │  │ CAPTCHA Validator │  │
│  │ (5 attempts)│  │ Validation    │  │ (after 3 fails)   │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
│                          │                                  │
│  ┌────────────────────────▼────────────────────────────┐    │
│  │              Authentication Logic                   │    │
│  │  1. Validate credentials against hashed DB value    │    │
│  │  2. Check MFA token if enabled                      │    │
│  │  3. Generate new session ID on success              │    │
│  │  4. Set secure session cookie                       │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                       Database                               │
│  Passwords: bcrypt hashed (never plaintext)                 │
│  Sessions:  ID + UserId + expiry timestamp                  │
│  Audit log: IP, timestamp, success/fail per login attempt   │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ Implementation Checklist

### Developers
- [ ] Password minimum 12 characters enforced server-side
- [ ] Common password blocklist integrated
- [ ] bcrypt (rounds ≥ 12) or Argon2id used for all password storage
- [ ] Login attempt rate limiting implemented
- [ ] CAPTCHA on login after threshold
- [ ] Session ID regenerated after login
- [ ] Session expiry (idle + absolute) configured
- [ ] All session cookies have `HttpOnly`, `Secure`, `SameSite=Strict`
- [ ] MFA available for all accounts
- [ ] MFA required for admin/privileged roles
- [ ] Secure password reset (expiring token via email, not security questions)
- [ ] Failed login notification sent to account owner

### Operations
- [ ] TLS 1.2 minimum configured (prefer TLS 1.3)
- [ ] HSTS header enabled with long max-age
- [ ] Authentication events logged with IP, timestamp, outcome
- [ ] Alerts configured for brute force patterns
- [ ] Breach password list updated regularly

---

## 🧠 Key Takeaways

1. **Authentication security is a shared responsibility.** Applications must enforce strong policies server-side — relying on users to choose strong passwords without technical enforcement always fails.
2. **MFA is the single highest-ROI security control for account protection.** Implementing TOTP-based MFA blocks the vast majority of credential-stuffing and phishing attacks.
3. **NIST's guidance on password rotation is counterintuitive but correct.** Forcing regular rotation leads to weak, predictable passwords. Only change on compromise.
4. **Every authentication event is a security event.** Log IP, timestamp, and outcome for every login attempt — this data is essential for detecting brute force and responding to incidents.
5. **Session management is authentication's second half.** A perfectly secure login is worthless if the resulting session can be stolen, fixed, or kept indefinitely.

---

## 📚 References

1. OWASP Application Security Verification Standard (ASVS) — [V2: Authentication](https://owasp.org/www-project-application-security-verification-standard/)
2. NIST Special Publication 800-63B — [Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
3. OWASP Top 10 — [A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
4. OWASP Cheat Sheet — [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
5. OWASP Cheat Sheet — [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

*This document represents policy design and analysis based on industry standards. No systems were tested or attacked in the creation of this document.*
