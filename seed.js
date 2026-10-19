/**
 * seed.js - Database initialization and seeding for MedShield Health Portal
 */
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, 'medshield.db');

// Remove existing database if any to ensure clean fresh state
if (fs.existsSync(dbPath)) {
    fs.unlinkSync(dbPath);
}

const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    console.log('[*] Creating MedShield SQLite database schema...');

    // 1. Users Table (Contains sensitive credentials, roles, and SSNs)
    db.run(`
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            ssn TEXT NOT NULL,
            csrf_token TEXT NOT NULL
        )
    `);

    // 2. Doctors Directory Table
    db.run(`
        CREATE TABLE doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            specialty TEXT NOT NULL,
            department TEXT NOT NULL,
            experience_years INTEGER NOT NULL,
            rating REAL NOT NULL,
            consultation_fee INTEGER NOT NULL
        )
    `);

    // 3. Medical Records Table (Used for intermediate/advanced SQLi and search)
    db.run(`
        CREATE TABLE records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name TEXT NOT NULL,
            doctor_name TEXT NOT NULL,
            diagnosis TEXT NOT NULL,
            treatment TEXT NOT NULL,
            status TEXT NOT NULL,
            confidential_notes TEXT NOT NULL
        )
    `);

    // 4. Patient Reviews Table (Used for Stored XSS)
    db.run(`
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name TEXT NOT NULL,
            doctor_name TEXT NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    console.log('[*] Inserting realistic healthcare seed data...');

    // Seed Users (Admin CMO, Patients, Staff)
    const userStmt = db.prepare('INSERT INTO users (username, password, email, role, ssn, csrf_token) VALUES (?, ?, ?, ?, ?, ?)');
    userStmt.run('admin', 'Admin@MedShield2026!', 's.jenkins@medshield.org', 'Chief Medical Officer', '987-65-4321', 'csrf_tok_admin_sec99a');
    userStmt.run('john_doe', 'PatientPass123', 'john.doe@email.com', 'Patient', '123-45-6789', 'csrf_tok_john_88bc');
    userStmt.run('jane_smith', 'SecretHeart2026', 'jane.smith@email.com', 'Patient', '321-65-0987', 'csrf_tok_jane_77ab');
    userStmt.run('dr_robert', 'NeuroCure88', 'r.stone@medshield.org', 'Senior Neurologist', '456-78-1234', 'csrf_tok_robert_66cd');
    userStmt.finalize();

    // Seed Doctors
    const docStmt = db.prepare('INSERT INTO doctors (name, specialty, department, experience_years, rating, consultation_fee) VALUES (?, ?, ?, ?, ?, ?)');
    docStmt.run('Dr. Sarah Jenkins', 'Cardiology', 'Cardiovascular Care', 18, 4.9, 150);
    docStmt.run('Dr. Robert Stone', 'Neurology', 'Brain & Spine Institute', 14, 4.8, 175);
    docStmt.run('Dr. Emily Vance', 'Oncology', 'Cancer Care Center', 12, 4.9, 200);
    docStmt.run('Dr. Michael Chen', 'Orthopedics', 'Bone & Joint Surgery', 10, 4.7, 130);
    docStmt.run('Dr. Aisha Patel', 'Pediatrics', 'Children Health Clinic', 8, 5.0, 100);
    docStmt.run('Dr. David Kim', 'Radiology', 'Diagnostic Imaging', 15, 4.8, 140);
    docStmt.finalize();

    // Seed Medical Records
    const recStmt = db.prepare('INSERT INTO records (patient_name, doctor_name, diagnosis, treatment, status, confidential_notes) VALUES (?, ?, ?, ?, ?, ?)');
    recStmt.run('John Doe', 'Dr. Sarah Jenkins', 'Stage 2 Hypertension', 'Lisinopril 20mg daily + Sodium restriction', 'Active', 'Patient experiences occasional palpitations.');
    recStmt.run('Jane Smith', 'Dr. Robert Stone', 'Vestibular Migraine', 'Topiramate 50mg + lifestyle counseling', 'Monitoring', 'Scheduled for follow-up MRI in 3 months.');
    recStmt.run('Alice Walker', 'Dr. Emily Vance', 'Early Stage Lymphoma', 'Chemotherapy cycle 1 completed', 'Under Treatment', 'Family history of oncological disorders.');
    recStmt.run('David Miller', 'Dr. Michael Chen', 'Anterior Cruciate Ligament Tear', 'Arthroscopic ACL reconstruction', 'Post-Op Recovery', 'Physical therapy twice weekly.');
    recStmt.run('Sophia Brown', 'Dr. Aisha Patel', 'Acute Pediatric Bronchitis', 'Amoxicillin oral suspension 250mg', 'Resolved', 'Immunization record is fully up to date.');
    recStmt.finalize();

    // Seed Reviews (Safe initial data)
    const revStmt = db.prepare('INSERT INTO reviews (patient_name, doctor_name, rating, comment) VALUES (?, ?, ?, ?)');
    revStmt.run('John Doe', 'Dr. Sarah Jenkins', 5, 'Dr. Jenkins was extremely attentive and helped stabilize my blood pressure quickly.');
    revStmt.run('Jane Smith', 'Dr. Robert Stone', 5, 'Great neurological consultation! Clear explanations and great bedside manner.');
    revStmt.run('Mark Higgins', 'Dr. Aisha Patel', 5, 'Wonderful pediatric care for our daughter. Very gentle and patient.');
    revStmt.finalize();

    console.log('[+] MedShield database seeded successfully.');
});

db.close();
