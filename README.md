# Cybersecurity Portfolio

Cybersecurity portfolio consist of application penetration testing, offensive security simulations, and malware analysis. All research documented here was conducted exclusively in authorized lab environments, intentionally vulnerable applications (OWASP Juice Shop), and sandbox platforms.

## Content

| File | Topic | Category | Severity |
|------|-------|----------|----------|
| [BrokenAccessControl.md](./BrokenAccessControl.md) | IDOR, Admin Bypass, Review Impersonation | Web App Pentest | 🔴 Critical |
| [SqlInjection.md](./SqlInjection.md) | Login Bypass, UNION Dump, SQLMap | Injection Attacks | 🔴 Critical |
| [SecurityMisconfiguration.md](./SecurityMisconfiguration.md) | Error Handling, Directory Listing | Web App Pentest | 🟠 High |
| [CryptographicFailures.md](./CryptographicFailures.md) | MD5 vs Bcrypt, HTTP Sniffing | Cryptography | 🟠 High |
| [SessionHijacking.md](./SessionHijacking.md) | Cookie Hijacking, ARP Spoofing | Network Attack | 🟠 High |
| [njRATMalware.md](./njRATMalware.md) | Sandbox Analysis, IOC Extraction | Malware Analysis | 🔴 Critical (10/10) |
| [AuthenticationSecurity.md](./AuthenticationSecurity.md) | Auth Policy Design, MFA, NIST | Defensive / Policy | 🟡 Informational |

---

## Tools & Environment

```
Offensive       : Burp Suite, SQLMap, BetterCap v2.41, Kali Linux
Sandbox         : Triage (tria.ge), VirusTotal, Any.Run
Target Apps     : OWASP Juice Shop, Custom PHP/MySQL Lab App
Frameworks Ref  : OWASP Top 10, MITRE ATT&CK v16, NIST SP 800-63B
Languages       : PHP, Python, JavaScript (Node.js / Express.js), SQL
```

---

## Summary Stats

| Metric | Value |
|--------|-------|
| Total Engagements | 7 |
| Critical Findings | 3 |
| High Findings | 6 |
| Exploits Documented | 12+ |
| Malware Samples Analyzed | 1 |
| Environment | Authorized Lab / CTF Only |

---

## Ethical Disclosure

> All security research in this portfolio was performed exclusively within **authorized environments**:
> - OWASP Juice Shop (intentionally vulnerable by design)
> - Custom local lab applications built for testing purposes
> - Public sandbox platforms (Triage, VirusTotal, Any.Run)
> - Target: `testphp.vulnweb.com` (public vulnerable test site)
> No unauthorized or production systems were accessed at any point. All sensitive data (real IPs outside CTF context, credentials) has been sanitized per responsible disclosure principles.

