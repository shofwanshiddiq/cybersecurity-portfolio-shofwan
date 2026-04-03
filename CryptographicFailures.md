# CS-004 — Cryptographic Failures
### Password Storage · Hash Cracking · Protocol Sniffing Comparison

---

## 📋 Overview

| Field | Detail |
|-------|--------|
| **Category** | Cryptographic Failures (OWASP A02:2021) |
| **Severity** | 🟠 High |
| **Focus Areas** | Password Hashing (Plaintext vs MD5 vs Bcrypt) · HTTP vs HTTPS Sniffing |
| **Tools** | Python 3, MariaDB, BetterCap v2.41, CrackStation, Kali Linux |
| **Standards Referenced** | OWASP ASVS, NIST SP 800-63B |

---

## 🎯 Objective

Demonstrate the practical consequences of cryptographic failures in two areas:
1. **Password Storage** — Compare plaintext, MD5, and bcrypt storage; attempt to crack each
2. **Protocol Security** — Show credential exposure over HTTP vs encrypted HTTPS traffic

---

## 📖 Background

Cryptographic Failures occur when a system fails to adequately protect sensitive data in transit or at rest. This is OWASP **A02:2021** — the second most critical web security risk.

**Common causes:**
- Storing passwords in plaintext or with weak hashing (MD5, SHA-1)
- Transmitting sensitive data over unencrypted protocols (HTTP instead of HTTPS)
- Using outdated or broken cryptographic algorithms
- Missing or misconfigured TLS certificates

---

## 🔬 Part 1 — Password Hashing Comparison

### Lab Setup
```
OS        : Kali Linux
Database  : MariaDB
Language  : Python 3
Libraries : hashlib (MD5), bcrypt
```

### Step 1 — Database and Table Creation

```sql
CREATE TABLE users (
  id                 INT AUTO_INCREMENT PRIMARY KEY,
  username           VARCHAR(100),
  password_plaintext VARCHAR(255),
  password_md5       VARCHAR(255),
  password_bcrypt    VARCHAR(255)
);
```

### Step 2 — Insert Plaintext Password

```sql
INSERT INTO users (username, password_plaintext)
VALUES ('shofwan_shiddiq', 'Password123!');
```

**Stored in DB:**
```
username        | password_plaintext | password_md5 | password_bcrypt
shofwan_shiddiq | Password123!       | NULL         | NULL
```

> ⚠️ Anyone with database read access — via SQLi, backup leak, or insider threat — sees credentials immediately.

---

### Step 3 — MD5 Hashing

**Using MySQL built-in:**
```sql
INSERT INTO users (username, password_md5)
VALUES ('user_md5', MD5('Password123!'));
```

**Using Python script (`md5_hash.py`):**
```python
import hashlib

password = "Password123!"
md5_hash = hashlib.md5(password.encode()).hexdigest()

print("Password:", password)
print("MD5:", md5_hash)
```

**Output:**
```
Password: Password123!
MD5: 2c103f2c4ed1e59c0b4e2e01821770fa
```

---

### Step 4 — Bcrypt Hashing

**Python script (`bcrypt_hash.py`):**
```python
import bcrypt

password = b"Password123!"

# Generate salt + hash with work factor 12
salt   = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)

print("Password:", password.decode())
print("Salt:", salt)
print("bcrypt hash:", hashed.decode())
```

**Output:**
```
Password: Password123!
Salt: b'$2b$12$lZWxAlFkVhAu7MbVzg05de'
bcrypt hash: $2b$12$lZWxAlFkVhAu7MbVzg05deTmot.PUjs2WjxOoF/gir/l5mAhxrwEi
```

> Note: Running the script again produces a **different hash** for the same password — bcrypt's automatic salt prevents rainbow table attacks.

---

### Step 5 — Cracking Attempt

Both hashes tested against **CrackStation** (online hash cracker with 15+ billion word list):

| Hash Type | Hash Value | Result |
|-----------|-----------|--------|
| MD5 | `2c103f2c4ed1e59c0b4e2e01821770fa` | ✅ **CRACKED** → `Password123!` |
| Bcrypt | `$2b$12$lZWxAlFk...` | ❌ **Not Found** — Algorithm not identified |

**MD5 cracking time:** Near-instant (entry in precomputed rainbow table)

---

### Cryptographic Comparison

| Property | Plaintext | MD5 | Bcrypt |
|----------|-----------|-----|--------|
| Reversible | ✅ (trivially) | 🟡 (rainbow tables) | ❌ No |
| Salt | ❌ | ❌ | ✅ Automatic per-hash |
| Work Factor | N/A | Fixed (fast) | ✅ Configurable (rounds) |
| Crack Speed | Instant | Very fast (GPU accelerated) | Very slow (by design) |
| Collision Risk | N/A | ✅ Known collisions | ❌ No known collisions |
| Recommended | ❌ Never | ❌ Deprecated | ✅ Yes |
| Alternative | — | — | Argon2, scrypt |

**Why bcrypt resists cracking:**
- **Automatic salt:** Same password produces different hash every time → rainbow tables useless
- **Work factor (rounds):** `rounds=12` means 2^12 = 4096 iterations → each guess takes ~300ms vs microseconds for MD5
- **Designed to be slow:** Unlike MD5/SHA which are optimized for speed, bcrypt is intentionally computationally expensive

---

## 🔬 Part 2 — HTTP vs HTTPS Protocol Sniffing

### Setup

```
Attacker : Kali Linux (BetterCap v2.41.5) — bridged adapter, same LAN
Victim   : Windows machine on same local network
Target 1 : http://testphp.vulnweb.com  (HTTP — no encryption)
Target 2 : https://dribbble.com         (HTTPS — TLS encrypted)
```

### HTTP Sniffing

**BetterCap setup:**
```bash
sudo bettercap

# Enable ARP spoofing toward victim
set arp.spoof.targets 192.168.0.11
arp.spoof on

# Enable HTTP proxy for traffic capture
http.proxy on
```

**Victim logs into `testphp.vulnweb.com`**

**Captured by BetterCap:**
```
[net.sniff.http.request] http 192.168.0.11 POST testphp.vulnweb.com/userinfo.php

Server: nginx/1.19.0
Set-Cookie: login=test%2Ftest

POST /userinfo.php HTTP/1.1
Host: testphp.vulnweb.com
Cookie: login=test%2Ftest
Content-Type: application/x-www-form-urlencoded
...

uname=test&pass=test
```

**Data extracted:**
```
Cookie   : login=test%2Ftest
Username : test
Password : test
```

> Full session takeover possible by replaying the captured cookie.

---

### HTTPS Sniffing — No Data Captured

**Victim logs into `https://dribbble.com`**

**BetterCap output:**
```
[INFO] arp.spoof started, probing 1 targets.
[INFO] endpoint 192.168.0.3 detected
[INFO] endpoint 192.168.0.7 detected
...
(No request body captured — all data encrypted via TLS)
```

**Result: Zero credential or cookie data extracted.** ARP Spoofing still succeeds (traffic routes through attacker) but TLS encryption makes the payload unreadable.

---

### Protocol Comparison

| Property | HTTP | HTTPS (TLS 1.2+) |
|----------|------|-----------------|
| Encryption | ❌ Plaintext | ✅ AES-256 (or similar) |
| Cookie Visibility | ✅ Fully visible | ❌ Encrypted |
| Password Visibility | ✅ Fully visible | ❌ Encrypted |
| MITM Readable | ✅ Yes | ❌ No |
| Certificate Required | ❌ | ✅ CA-signed cert |
| Performance | Slightly faster | Negligible difference (TLS 1.3) |

---

## 🔧 Recommendations

### Password Storage

```python
# Use bcrypt (or Argon2) — never MD5 or SHA-1 for passwords
import bcrypt

# Hashing on registration
def hash_password(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()

# Verification on login
def verify_password(plaintext: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(plaintext.encode(), stored_hash.encode())
```

### Protocol Security Checklist

| Control | Action |
|---------|--------|
| **HTTPS** | Obtain SSL cert from trusted CA (Let's Encrypt is free); redirect all HTTP → HTTPS |
| **TLS Version** | Enforce TLS 1.2 minimum; prefer TLS 1.3 |
| **HSTS** | Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header |
| **Cookie Flags** | Set `Secure; HttpOnly; SameSite=Strict` on all session cookies |
| **Certificate Pinning** | For mobile apps: pin certificate to prevent rogue CA attacks |

### Business-Level Password Policy (NIST SP 800-63B Aligned)

```
Minimum length    : 12 characters
Complexity        : Mix of uppercase, lowercase, numbers, symbols
Prohibited        : Common passwords, dictionary words, sequential numbers
Storage           : bcrypt (rounds ≥ 12) or Argon2id
Reset mechanism   : Secure token via email with short expiry (15 min)
MFA               : Required for privileged accounts; recommended for all
Rotation policy   : Only force change on evidence of compromise (NIST guidance)
```

---

## 📊 Impact of Cryptographic Failures

| Failure | Consequence |
|---------|-------------|
| Plaintext passwords in DB | Any DB breach = instant full credential exposure |
| MD5-hashed passwords | Cracked in seconds via rainbow tables; GPU cracking ~billions/sec |
| HTTP protocol | All sessions, cookies, passwords visible to anyone on the network path |
| Missing cookie flags | Cookies stealable via XSS (no HttpOnly), HTTP downgrade (no Secure), CSRF (no SameSite) |
| Weak TLS config (TLS 1.0/1.1) | Vulnerable to POODLE, BEAST, CRIME attacks |
| Self-signed certs | Browser warnings; susceptible to MITM with no chain of trust |

---

## 🧠 Lessons Learned

1. **MD5 is dead for password storage.** It was never designed for passwords — it's optimized for speed, which means GPU-accelerated cracking is trivially fast. Over 15 billion MD5 hashes are in publicly available rainbow tables.
2. **The cost of bcrypt is a feature.** Its intentional slowness (configurable via rounds) means brute-forcing is economically infeasible even for short passwords at high work factors.
3. **HTTP sniffing requires no special skill.** BetterCap + ARP Spoofing is a 3-command setup. Any user on the same LAN segment can execute this attack. There is no justification for HTTP on any login or authenticated page.
4. **Encryption in transit and at rest are separate requirements.** HTTPS protects data while moving; bcrypt protects data at rest. Both are needed — one doesn't substitute for the other.

---

*Environment: Kali Linux lab with MariaDB for hashing experiments. BetterCap used on an isolated bridged network. testphp.vulnweb.com is a publicly available intentionally vulnerable test site.*
