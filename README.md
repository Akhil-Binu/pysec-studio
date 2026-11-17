# PySecStudio 🛡️⚡
### Pro Cyber Studio for Custom Python Automation (Vulnerability Scanning & Log Threat Parsing)

[![Live Demo](https://img.shields.io/badge/demo-pysec--studio.vercel.app-06b6d4?logo=vercel&logoColor=white)](https://pysec-studio.vercel.app)
[![Version](https://img.shields.io/badge/version-1.0.0-06b6d4.svg)](https://github.com/Akhil-Binu/pysec-studio/releases)
[![GitHub Packages](https://img.shields.io/badge/pkg-@akhil--binu/pysec--studio-blue?logo=github)](https://github.com/Akhil-Binu/pysec-studio/packages)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Node](https://img.shields.io/badge/Node-18%2B-339933.svg?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Code Style](https://img.shields.io/badge/Code%20Style-PEP%208-emerald.svg)](https://peps.python.org/pep-0008/)

**PySecStudio** is a workbench and interactive code generation studio designed specifically for security engineers, penetration testers, DevSecOps practitioners, and SOC analysts to **author, configure, test, and deploy production-grade Python automation scripts** for:
1. **Network & Web Application Vulnerability Scanning** (TCP port discovery, banner grabbing, SSL/TLS validation, defensive HTTP header auditing, sensitive config fuzzing, and CORS exploitation testing).
2. **High-Throughput Threat Hunting & Log Parsing** (Streaming $O(1)$ memory ingestion, sliding-window brute-force correlation, SQLi/XSS/LFI signature detection, automated firewall IP banning, and MITRE ATT&CK mapping).

---

## 🌟 Key Capabilities & Architecture

### 1. 🎯 Vulnerability Scanning Studio
- **Scope & Port Configuration**: Target hostname, IP, or CIDR. Presets for Top 20 common ports, Top 100 IANA services, custom ranges, or full sweeps.
- **High-Concurrency Engine**: Choose between **AsyncIO Coroutines** (blazingly fast async sockets), **ThreadPoolExecutor**, or **Multiprocessing**, with adjustable worker count (1–200) and socket timeout.
- **Stealth & Rate Limiting**: Interval jitter and custom User-Agent injection to avoid WAF threshold rate bans.
- **Audit Modules**:
  - **TCP Banner Grabbing**: Socket probes to extract daemon version strings.
  - **Defensive HTTP Headers**: Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type, and server token leakages.
  - **SSL/TLS & Cipher Auditor**: Certificate expiration countdowns and deprecated TLS 1.0/1.1 identification.
  - **Sensitive Endpoint Fuzzer**: Discovers leaked `/.env`, `/.git/HEAD`, `wp-config.php.bak`, actuator endpoints, and swagger docs.
  - **CORS Misconfiguration**: Detects arbitrary origin reflection with `Access-Control-Allow-Credentials: true`.
  - **Heuristic Probing**: Safe non-destructive reflection checks for SQLi and XSS.
- **Multi-Format Export**: Generates colorized console output, JSON reports, CSV spreadsheets, and Discord/Slack webhook dispatches.

### 2. 📜 Log Parsing & Threat SIEM Engine
- **$O(1)$ Memory Streaming Generator**: Uses line-by-line generator pipelines (`yield`) capable of processing 50 GB log files using less than 15 MB of RAM.
- **Multi-Source Ingestion**:
  - Web Server Access Logs (Nginx / Apache Combined Format)
  - Linux SSH Auth Logs (`/var/log/auth.log` and `/var/log/secure`)
  - AWS CloudTrail JSON Event Trails
  - Windows Event Log / Sysmon EVTX
  - Custom regex patterns
- **Sliding-Window Brute-Force Correlator**: `collections.defaultdict(deque)` rolling window to detect credential stuffing bursts and calculate hostile source IPs.
- **Web Exploit Signatures**: High-efficiency regex matchers for SQL Injection (`UNION SELECT`, `' OR '1'='1`), XSS (`<script>`, `document.cookie`), Directory Traversal (`../../etc/passwd`), and Webshell execution (`cmd.exe`, `/bin/sh`).
- **Scanner Fingerprint Identification**: Automatically flags automated scanner bots (sqlmap, nikto, masscan, gobuster, nmap).
- **Automated Firewall Mitigation**: Exports ready-to-run auto-ban scripts for `ufw`, `iptables`, or `fail2ban`.
- **MITRE ATT&CK Alignment**: Automatically maps findings to Enterprise Matrix techniques (`T1110`, `T1190`, `T1083`, `T1059`, `T1595`).

### 3. 🧪 Interactive Cyber Sandbox Simulator
- Test generated scripts directly in the browser before deploying them to production.
- Watch simulated real-time terminal output with authentic ANSI color highlighting, phase progression, and summary scorecard.

### 4. 🧩 Log Regex & Grok Tokenizer Workbench
- Live tester with sample datasets (Nginx access logs, Linux SSH logs, AWS CloudTrail JSON).
- Real-time named capture group extraction (`ip`, `time`, `method`, `uri`, `status`, `bytes`, `ref`, `ua`) visualized with token chips.
- One-click copy for `re.compile(r'...')` Python boilerplate.

### 5. 📚 Curated 12-Script Production Library
Includes ready-to-run, documented, battle-tested Python scripts:
1. *AsyncIO TCP Port Scanner* (`asyncio` + banner grabbing)
2. *HTTP Security Headers & SSL Auditor* (`requests` + `cryptography` + A-F posture grading)
3. *Sensitive Config & Secret Fuzzer* (`.env`, `.git`, actuators)
4. *Nginx / Apache Attack Log Forensics Hunter* (SQLi/XSS/LFI detector + top IP statistics)
5. *SSH Auth Log Brute-Force Hunter & Auto-Ban Exporter* (Sliding window + UFW rule builder)
6. *Real-Time `tail -f` Log Watcher Daemon* (Discord/Slack webhook integration)
7. *AWS CloudTrail JSON Privilege Escalation Auditor* (Root activity & IAM tampering)
8. *CORS Misconfiguration & Origin Reflection Tester* (Arbitrary origin reflection)
9. *And more...*

### 6. 🛡️ DevSecOps & Container Deployment
- One-click generation of:
  - **Dockerfile** (Hardened, non-root Alpine container)
  - **requirements.txt**
  - **GitHub Actions Workflow** (`.github/workflows/security-scan.yml` for CI/CD scheduled scans)
  - **systemd Service Unit** for 24/7 background log monitoring daemons

---

## 🚀 Quickstart & Development

### Prerequisites
- Node.js (v18+)
- npm (v9+)
- Python (v3.8+)

### Running Locally
```bash
# 1. Install dependencies
npm install

# 2. Start the local development server
npm run dev
```

Visit **`http://localhost:5173/`** in your browser.

### Building for Production
```bash
npm run build
```
The static, self-contained production bundle is generated in the `dist/` directory.

---

## ⚖️ Ethical & Legal Disclaimer
Automated scanning scripts generated by this tool interact directly with network ports and services. Only scan systems, IP addresses, and applications that you own or have explicit written authorization (Rules of Engagement) to assess. Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA) or international cybersecurity regulations.
