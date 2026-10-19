/**
 * server.js - MedShield Health Portal Web Application
 * Information Security Practical Assignment 2
 * Dual-Mode Security Architecture: Vulnerable vs Safe (Hardened)
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to SQLite Database
const dbPath = path.join(__dirname, 'medshield.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('[-] Could not connect to database:', err.message);
    } else {
        console.log('[+] Connected to MedShield SQLite database.');
    }
});

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser('medshield_secret_key_2026'));

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// HTML Entity encoding helper for Safe Mode defenses
function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Global Security Mode Determination Middleware
// Mode can be controlled via Cookie, Query Parameter (?mode=safe|vulnerable), or Header
app.use((req, res, next) => {
    let mode = 'vulnerable'; // Default to vulnerable for initial grading/testing

    if (req.query.mode === 'safe' || req.query.mode === 'vulnerable') {
        mode = req.query.mode;
        res.cookie('app_mode', mode, { httpOnly: false });
    } else if (req.cookies.app_mode) {
        mode = req.cookies.app_mode;
    }

    req.isSafeMode = (mode === 'safe');
    req.appMode = mode;
    next();
});

// Authentication / Session Simulator Middleware
app.use((req, res, next) => {
    const sessionUser = req.cookies.user_session;
    if (sessionUser) {
        req.currentUser = sessionUser;
    } else {
        // Default demo session is John Doe (Patient)
        req.currentUser = 'john_doe';
    }
    next();
});

// ============================================================================
// API ROUTES: MODE & STATUS
// ============================================================================

// Get Current Security Mode
app.get('/api/mode', (req, res) => {
    res.json({
        mode: req.appMode,
        isSafeMode: req.isSafeMode,
        currentUser: req.currentUser,
        timestamp: new Date().toISOString()
    });
});

// Toggle Security Mode
app.post('/api/mode/toggle', (req, res) => {
    const newMode = req.body.mode || (req.isSafeMode ? 'vulnerable' : 'safe');
    res.cookie('app_mode', newMode, { httpOnly: false });
    res.json({
        success: true,
        previousMode: req.appMode,
        activeMode: newMode,
        message: `Security mode successfully switched to: ${newMode.toUpperCase()}`
    });
});

// Get Current User Profile & CSRF Token
app.get('/api/profile', (req, res) => {
    db.get('SELECT id, username, email, role, ssn, csrf_token FROM users WHERE username = ?', [req.currentUser], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ error: 'User profile not found' });
        }
        res.json({
            user: row,
            mode: req.appMode
        });
    });
});

// ============================================================================
// 1. CROSS-SITE SCRIPTING (XSS) IMPLEMENTATIONS
// ============================================================================

// A. Reflected XSS: Doctor & Department Search
// Vulnerable: Query string echoed directly into HTML response without escaping
// Safe: Query string HTML-entity encoded before embedding
app.get('/api/search', (req, res) => {
    const query = req.query.q || '';

    if (req.isSafeMode) {
        // --- SAFE DEFENSE: HTML Entity Encoding ---
        const safeQuery = escapeHtml(query);
        const searchSql = 'SELECT * FROM doctors WHERE name LIKE ? OR specialty LIKE ?';
        db.all(searchSql, [`%${query}%`, `%${query}%`], (err, rows) => {
            res.json({
                mode: 'safe',
                query: safeQuery,
                htmlEcho: `<div class="search-feedback">Search results for: <strong>${safeQuery}</strong></div>`,
                results: rows || []
            });
        });
    } else {
        // --- VULNERABLE: Direct string reflection ---
        const searchSql = `SELECT * FROM doctors WHERE name LIKE '%${query}%' OR specialty LIKE '%${query}%'`;
        db.all(searchSql, (err, rows) => {
            res.json({
                mode: 'vulnerable',
                query: query,
                // Raw unescaped reflection enables script execution when rendered in browser
                htmlEcho: `<div class="search-feedback">Search results for: <strong>${query}</strong></div>`,
                results: rows || []
            });
        });
    }
});

// B. Stored XSS: Patient Reviews & Doctor Feedback
// Vulnerable: Saves unescaped input to DB, and sends unescaped HTML to clients
// Safe: Sanitizes input on arrival and sends sanitized text
app.get('/api/reviews', (req, res) => {
    db.all('SELECT * FROM reviews ORDER BY id DESC', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        if (req.isSafeMode) {
            // Safe mode: Encode any legacy stored tags on output
            const safeRows = rows.map(r => ({
                ...r,
                patient_name: escapeHtml(r.patient_name),
                comment: escapeHtml(r.comment)
            }));
            res.json({ mode: 'safe', reviews: safeRows });
        } else {
            // Vulnerable mode: Raw output directly as stored in DB
            res.json({ mode: 'vulnerable', reviews: rows });
        }
    });
});

app.post('/api/reviews', (req, res) => {
    let { patient_name, doctor_name, rating, comment } = req.body;
    patient_name = patient_name || 'Anonymous Patient';
    doctor_name = doctor_name || 'General Staff';
    rating = parseInt(rating) || 5;

    if (req.isSafeMode) {
        // --- SAFE DEFENSE: Sanitize and encode on write ---
        const safeComment = escapeHtml(comment || '');
        const safePatient = escapeHtml(patient_name);
        db.run(
            'INSERT INTO reviews (patient_name, doctor_name, rating, comment) VALUES (?, ?, ?, ?)',
            [safePatient, doctor_name, rating, safeComment],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({
                    success: true,
                    mode: 'safe',
                    message: 'Review saved safely with HTML encoding.',
                    id: this.lastID
                });
            }
        );
    } else {
        // --- VULNERABLE: Store raw unsanitized payload into database ---
        db.run(
            'INSERT INTO reviews (patient_name, doctor_name, rating, comment) VALUES (?, ?, ?, ?)',
            [patient_name, doctor_name, rating, comment],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({
                    success: true,
                    mode: 'vulnerable',
                    message: 'Review stored in raw format (Vulnerable to Stored XSS).',
                    id: this.lastID
                });
            }
        );
    }
});

// C. DOM-Based XSS is implemented on the frontend in /department.html
// In Vulnerable Mode, JS reads location.hash and assigns to innerHTML.
// In Safe Mode, JS reads location.hash and assigns to textContent.

// ============================================================================
// 2. CROSS-SITE REQUEST FORGERY (CSRF) IMPLEMENTATIONS
// ============================================================================

// State-Changing Action: Update Patient Email
// Vulnerable: Relies solely on session cookie; no CSRF token check
// Safe: Requires valid Anti-CSRF Token
app.post('/api/profile/email', (req, res) => {
    const newEmail = req.body.email;
    if (!newEmail) {
        return res.status(400).json({ error: 'Email parameter is required.' });
    }

    if (req.isSafeMode) {
        // --- SAFE DEFENSE: Verify Anti-CSRF Token ---
        const submittedToken = req.headers['x-csrf-token'] || req.body._csrf;
        
        db.get('SELECT csrf_token FROM users WHERE username = ?', [req.currentUser], (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Session unauthorized.' });
            }

            if (!submittedToken || submittedToken !== user.csrf_token) {
                console.log(`[DEFENSE BLOCKED] CSRF Attack detected against user ${req.currentUser}! Invalid token.`);
                return res.status(403).json({
                    success: false,
                    mode: 'safe',
                    error: '403 Forbidden: Invalid or missing Anti-CSRF token! Request blocked by Safe Mode defense.'
                });
            }

            // Valid token -> perform state change safely
            db.run('UPDATE users SET email = ? WHERE username = ?', [escapeHtml(newEmail), req.currentUser], (updateErr) => {
                if (updateErr) return res.status(500).json({ error: updateErr.message });
                res.json({
                    success: true,
                    mode: 'safe',
                    message: `Email updated to ${escapeHtml(newEmail)} with verified CSRF protection!`,
                    user: req.currentUser,
                    updatedEmail: newEmail
                });
            });
        });
    } else {
        // --- VULNERABLE: No CSRF verification! Accepts third-party forged POST ---
        console.log(`[VULNERABLE EXPLOIT] Email updated for user ${req.currentUser} without CSRF token verification!`);
        db.run('UPDATE users SET email = ? WHERE username = ?', [newEmail, req.currentUser], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({
                success: true,
                mode: 'vulnerable',
                message: `[VULNERABLE] Email successfully changed to ${newEmail} without any CSRF validation!`,
                user: req.currentUser,
                updatedEmail: newEmail
            });
        });
    }
});

// ============================================================================
// 3. SQL INJECTION (SQLi) IMPLEMENTATIONS (3 LEVELS)
// ============================================================================

// Level 1: Easy - Login Authentication Bypass
// Vulnerable: Raw string concatenation in SQL statement
// Safe: Parameterized query with '?' placeholders
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (req.isSafeMode) {
        // --- SAFE DEFENSE: Parameterized Prepared Statement ---
        const safeSql = 'SELECT id, username, email, role, ssn FROM users WHERE username = ? AND password = ?';
        db.get(safeSql, [username, password], (err, user) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!user) {
                return res.status(401).json({
                    success: false,
                    mode: 'safe',
                    error: 'Invalid username or password (SQL Injection blocked by parameterized query).'
                });
            }
            res.cookie('user_session', user.username);
            res.json({
                success: true,
                mode: 'safe',
                message: `Authentication successful for ${user.username}`,
                user: user
            });
        });
    } else {
        // --- VULNERABLE: Direct String Concatenation ---
        const vulnerableSql = `SELECT id, username, email, role, ssn FROM users WHERE username = '${username}' AND password = '${password}'`;
        console.log(`[SQL EXEC - Vulnerable]: ${vulnerableSql}`);

        db.get(vulnerableSql, (err, user) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    mode: 'vulnerable',
                    error: `Database SQL Error: ${err.message}`,
                    executedQuery: vulnerableSql
                });
            }
            if (!user) {
                return res.status(401).json({
                    success: false,
                    mode: 'vulnerable',
                    error: 'Invalid credentials.',
                    executedQuery: vulnerableSql
                });
            }
            res.cookie('user_session', user.username);
            res.json({
                success: true,
                mode: 'vulnerable',
                message: `[EXPLOITED] Logged in as ${user.username} (${user.role})!`,
                executedQuery: vulnerableSql,
                user: user
            });
        });
    }
});

// Level 2: Intermediate - Blind Boolean-Based Injection
// Vulnerable: Doctor specialty lookup vulnerable to injected boolean clauses
// Safe: Strict parameter binding
app.get('/api/doctors', (req, res) => {
    const specialty = req.query.specialty;

    if (!specialty) {
        return db.all('SELECT * FROM doctors', [], (err, rows) => {
            res.json({ mode: req.appMode, doctors: rows || [] });
        });
    }

    if (req.isSafeMode) {
        // --- SAFE DEFENSE: Parameterized query ---
        const safeSql = 'SELECT * FROM doctors WHERE specialty = ?';
        db.all(safeSql, [specialty], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({
                mode: 'safe',
                matched: (rows && rows.length > 0),
                count: rows ? rows.length : 0,
                doctors: rows || []
            });
        });
    } else {
        // --- VULNERABLE: Direct concatenation allowing boolean/blind inference ---
        const vulnerableSql = `SELECT * FROM doctors WHERE specialty = '${specialty}'`;
        console.log(`[SQL EXEC - Blind]: ${vulnerableSql}`);

        db.all(vulnerableSql, (err, rows) => {
            if (err) {
                return res.status(500).json({
                    mode: 'vulnerable',
                    error: err.message,
                    executedQuery: vulnerableSql
                });
            }
            res.json({
                mode: 'vulnerable',
                matched: (rows && rows.length > 0),
                count: rows ? rows.length : 0,
                executedQuery: vulnerableSql,
                doctors: rows || []
            });
        });
    }
});

// Level 3: Advanced - Structured 4-Stage UNION Schema & Sensitive Data Dump
// Vulnerable: Patient Medical Records search allows UNION SELECT data exfiltration
// Safe: Parameterized query
app.get('/api/records', (req, res) => {
    const search = req.query.search || '';

    if (req.isSafeMode) {
        // --- SAFE DEFENSE: Parameterized query with wildcards bound safely ---
        const safeSql = `SELECT id, patient_name, doctor_name, diagnosis, treatment, status 
                         FROM records 
                         WHERE patient_name LIKE ? OR diagnosis LIKE ?`;
        db.all(safeSql, [`%${search}%`, `%${search}%`], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({
                mode: 'safe',
                count: rows ? rows.length : 0,
                records: rows || []
            });
        });
    } else {
        // --- VULNERABLE: Concatenation allows multi-stage UNION injections ---
        const vulnerableSql = `SELECT id, patient_name, doctor_name, diagnosis, treatment, status 
                               FROM records 
                               WHERE patient_name LIKE '%${search}%'`;
        console.log(`[SQL EXEC - Advanced UNION]: ${vulnerableSql}`);

        db.all(vulnerableSql, (err, rows) => {
            if (err) {
                return res.status(500).json({
                    mode: 'vulnerable',
                    error: err.message,
                    executedQuery: vulnerableSql
                });
            }
            res.json({
                mode: 'vulnerable',
                count: rows ? rows.length : 0,
                executedQuery: vulnerableSql,
                records: rows || []
            });
        });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log('===========================================================');
    console.log(`  MedShield Health Portal running at http://localhost:${PORT}`);
    console.log(`  Default Mode: VULNERABLE (Use navbar toggle for SAFE mode)`);
    console.log('===========================================================');
});
