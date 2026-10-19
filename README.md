# MedShield Health Portal — Full-Stack Web Security Project (Part 2)

**Information Security Practical Assignment 2 | Total Marks for Part 2: 100**

---

## 1. Project Overview & Use Case
**MedShield Health Portal** is an electronic hospital management and clinical registry platform designed for healthcare professionals and patients. It allows patients to search specialists, review medical staff, view laboratory diagnoses, manage patient security profiles, and authenticate medical personnel.

The project implements a **Dual-Mode Security Architecture** allowing instantaneous side-by-side comparison between an intentionally insecure implementation (**Vulnerable Mode**) and an enterprise-hardened defense (**Safe Mode**).

---

## 2. Technology Stack
- **Backend Environment:** Node.js (v24.x)
- **Web Framework:** Express.js (v4.21.x)
- **Database Engine:** SQLite3 (Serverless embedded SQL with `better-sqlite3`/`sqlite3` bindings)
- **Session & State Management:** Cookie-based sessions with HTTP-only tokens
- **Frontend Architecture:** Vanilla HTML5, Modern Responsive CSS3 (Glassmorphism design tokens), and Asynchronous JavaScript (Fetch API)
- **Security Defenses:** Context-aware HTML entity encoding, cryptographic anti-CSRF token verification, and parameterized SQL prepared statements.

---

## 3. How to Run the Application

### Prerequisites
- Node.js installed (`node -v` $\ge$ 18.x)
- npm installed (`npm -v`)

### Installation & Launch
```bash
# 1. Navigate to the project directory
cd part2-webproject

# 2. Install dependencies
npm install

# 3. Seed the SQLite database with realistic clinical data
npm run seed

# 4. Launch the local web server
npm start
```
The server will start at: **`http://localhost:3000`**

### Running the Automated Security Test Suite
To automatically run every payload against both modes and print execution results with timestamps:
```bash
npm run test-payloads
```

---

## 4. Switching Between Vulnerable and Safe Versions
The application provides three convenient ways to toggle modes:
1. **Interactive UI Navbar Switch:** Click the **`Switch Mode`** button in the top-right header to toggle between `🔴 VULNERABLE MODE` and `🟢 SAFE (HARDENED) MODE`.
2. **Query Parameter:** Append `?mode=safe` or `?mode=vulnerable` to any URL.
3. **Session Cookie:** The `app_mode` cookie preserves state across navigation.

---

## 5. Vulnerability & Defense Implementation Matrix

### 1. Cross-Site Scripting (XSS) — All Three Types (25 Marks)

#### A. Reflected XSS
- **Target Endpoint:** `GET /api/search?q=<payload>` (Doctor & Specialist Search)
- **Vulnerability:** Unsanitized user query is directly interpolated into the server's HTML response template.
- **Working Payload:**
  ```html
  <script>alert('Reflected XSS by Group Member!')</script>
  ```
- **Defense Implementation:** Input is parsed and passed through `escapeHtml()` converting special characters (`<`, `>`, `&`, `"`, `'`) into harmless HTML entities (`&lt;`, `&gt;`).

#### B. Stored XSS
- **Target Endpoint:** `POST /api/reviews` & `GET /api/reviews` (Patient Testimonials)
- **Vulnerability:** Raw comment text is persisted into the SQLite database and rendered on the client.
- **Working Payload:**
  ```html
  <img src=x onerror="alert('Stored XSS from Database!')">
  ```
- **Defense Implementation:** Inputs are sanitized before database insertion and safely encoded on output.

#### C. DOM-based XSS
- **Target Location:** `department.html#dept=<payload>` (Department Selector)
- **Vulnerability:** Client-side JavaScript parses `window.location.hash` and writes untrusted user input directly to the DOM using the execution sink `element.innerHTML`.
- **Working Payload:**
  ```html
  #dept=<img src=1 onerror="alert('DOM XSS Triggered!')">
  ```
- **Defense Implementation:** Replaced the dangerous `innerHTML` sink with `element.textContent`, ensuring user input is strictly treated as text.

---

### 2. Cross-Site Request Forgery (CSRF) (15 Marks)
- **Target Action:** `POST /api/profile/email` (Primary Patient Contact Email Update)
- **Vulnerability:** The endpoint relies exclusively on ambient session cookies (`user_session`) without validating request origin or requiring anti-forgery tokens.
- **Attacker Exploit:** Standalone malicious webpage [attacker_csrf_exploit.html](file:///D:/Study%20Material/Semester%208/IS/Assignment/Assignment02/part2-webproject/public/attacker_csrf_exploit.html) automatically submits a hidden POST request changing the victim's email to `attacker_hijacked@evilcorp.com`.
- **Defense Implementation:** The server requires a cryptographic `X-CSRF-Token` header. Cross-origin forged requests lacking this token fail immediately with `HTTP 403 Forbidden`.

---

### 3. SQL Injection (SQLi) — Three Complexity Levels (30 Marks)

#### Level 1: Easy (Authentication Bypass)
- **Target Endpoint:** `POST /api/login`
- **Vulnerability:** SQL statement assembled via direct string concatenation:
  ```sql
  SELECT * FROM users WHERE username = '${username}' AND password = '${password}'
  ```
- **Working Payload:**
  ```sql
  ' OR '1'='1' --
  ```
- **Result:** Successfully authenticates as Administrator (Chief Medical Officer Dr. Sarah Jenkins) without knowing the password.
- **Defense:** Parameterized prepared statement (`WHERE username = ? AND password = ?`).

#### Level 2: Intermediate (Blind Boolean-Based Injection)
- **Target Endpoint:** `GET /api/doctors?specialty=<payload>`
- **Vulnerability:** Specialty filter concatenated into SQL query.
- **Working Payload:**
  ```sql
  Cardiology' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='A' --
  ```
- **Result:** Returns 1 doctor if True; returns 0 doctors if False, allowing character-by-character password reconstruction.
- **Defense:** Parameterized query binding specialty strictly to parameter `?`.

#### Level 3: Advanced (Structured 4-Stage UNION Data Exfiltration)
- **Target Endpoint:** `GET /api/records?search=<payload>`
- **Full Attack Chain:**
  1. **Stage 1 (Determine Columns):**
     ```sql
     %' UNION SELECT 1, 2, 3, 4, 5, 6 --
     ```
  2. **Stage 2 (Enumerate Tables & Schema):**
     ```sql
     %' UNION SELECT 1, tbl_name, sql, 'SCHEMA', 5, 6 FROM sqlite_master WHERE type='table' --
     ```
  3. **Stage 3 (Enumerate Columns of `users` table):**
     ```sql
     %' UNION SELECT 1, name, type, 'COLUMN_SPEC', 5, 6 FROM pragma_table_info('users') --
     ```
  4. **Stage 4 (Exfiltrate Sensitive Credentials & SSNs):**
     ```sql
     %' UNION SELECT id, username, password, email, role, ssn FROM users --
     ```
- **Result:** Dumps entire patient/admin database including cleartext passwords and Social Security Numbers.
- **Defense:** Parameterized query with bound wildcard parameters (`LIKE ?`).

---

## 6. Directory Structure
```
part2-webproject/
├── package.json
├── server.js                     # Dual-mode backend server
├── seed.js                       # SQLite schema & database seeder
├── test_payloads.js              # Automated payload testing suite
├── medshield.db                  # Local SQLite clinical database
├── public/
│   ├── index.html                # Main portal & Reflected XSS
│   ├── login.html                # Staff login & Easy SQLi bypass
│   ├── records.html              # Medical records & Advanced UNION SQLi
│   ├── reviews.html              # Testimonials & Stored XSS
│   ├── department.html           # Directory & DOM-based XSS
│   ├── profile.html              # Patient settings & CSRF target
│   ├── attacker_csrf_exploit.html# External malicious attacker page
│   ├── style.css                 # Hospital design system
│   └── app.js                    # Shared client-side controller
└── README.md                     # Comprehensive documentation
```
