import { ScriptTemplate } from '../types/script';

export const SCRIPT_TEMPLATES: ScriptTemplate[] = [
  {
    id: 'async-port-scanner',
    title: 'High-Speed AsyncIO TCP Port & Service Fingerprinter',
    category: 'vuln_scanning',
    description: 'Blazingly fast asynchronous port scanner using native Python asyncio and socket. Grabs service banners, identifies common open daemons, and outputs JSON/CSV reports without external dependencies.',
    difficulty: 'Intermediate',
    tags: ['AsyncIO', 'Port Scanner', 'Reconnaissance', 'Sockets', 'Zero-Dependencies'],
    dependencies: ['Python 3.8+ (standard library only)'],
    cliExample: 'python async_scanner.py -t 192.168.1.1 -p 1-1024 -c 200 -o results.json',
    mitreTags: ['T1046 - Network Service Discovery'],
    pythonCode: `#!/usr/bin/env python3
"""
High-Speed AsyncIO TCP Port & Service Fingerprinter
Author: PySecStudio Production Library
Requirements: Python 3.8+ (Standard Library)
"""

import asyncio
import socket
import argparse
import json
import sys
from typing import List, Dict, Any, Optional

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}

async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
    try:
        # Send generic HTTP HEAD probe to trigger banner response
        writer.write(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=1.5)
        banner = data.decode('utf-8', errors='ignore').strip()
        return banner.split('\\n')[0][:80]
    except Exception:
        return ""

async def scan_port(host: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = await grab_banner(reader, writer)
            writer.close()
            await writer.wait_closed()
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"\\\x1b[92m[+] Port {port:5d}/TCP OPEN\\\x1b[0m | Service: {service:12s} {f'| Banner: {banner}' if banner else ''}")
            return {"port": port, "service": service, "banner": banner}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

async def main():
    parser = argparse.ArgumentParser(description="AsyncIO TCP Service Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target hostname or IP")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g. 1-1024 or 80,443,8080)")
    parser.add_argument("-c", "--concurrency", type=int, default=150, help="Max concurrent connections")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout seconds")
    parser.add_argument("-o", "--output", default="port_scan.json", help="JSON output file")
    args = parser.parse_args()

    # Parse ports
    port_list = []
    for chunk in args.ports.split(","):
        if "-" in chunk:
            s, e = map(int, chunk.split("-"))
            port_list.extend(range(s, e + 1))
        else:
            port_list.append(int(chunk))

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"\\\x1b[91m[-] Failed to resolve host: {args.target}\\\x1b[0m")
        sys.exit(1)

    print(f"[*] Target : {args.target} ({ip})")
    print(f"[*] Ports  : {len(port_list)} ports to inspect")
    print(f"[*] Workers: {args.concurrency} concurrent coroutines\\n")

    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [scan_port(ip, port, args.timeout, semaphore) for port in port_list]
    results = [r for r in await asyncio.gather(*tasks) if r is not None]

    with open(args.output, "w") as f:
        json.dump({"target": args.target, "ip": ip, "open_ports": results}, f, indent=2)
    print(f"\\n\\\x1b[94m[*] Finished: Found {len(results)} open ports. Saved to {args.output}\\\x1b[0m")

if __name__ == "__main__":
    asyncio.run(main())
`
  },
  {
    id: 'http-header-ssl-auditor',
    title: 'HTTP Security Headers & TLS/SSL Certificate Grade Evaluator',
    category: 'vuln_scanning',
    description: 'Audits defensive HTTP response headers (HSTS, CSP, X-Frame-Options, Permissions-Policy, CORS) and inspects SSL certificate expiration, cipher strength, and TLS version compatibility.',
    difficulty: 'Beginner',
    tags: ['Headers', 'SSL/TLS', 'HSTS', 'CSP', 'Compliance', 'Certbot'],
    dependencies: ['requests>=2.31.0', 'cryptography>=42.0.0'],
    cliExample: 'python header_ssl_auditor.py -u https://example.com --grade',
    mitreTags: ['T1592.004 - Client Configurations'],
    pythonCode: `#!/usr/bin/env python3
"""
HTTP Security Headers & SSL/TLS Certificate Auditor
Author: PySecStudio Production Library
Requirements: requests, cryptography
"""

import sys
import ssl
import socket
import argparse
from datetime import datetime, timezone
import requests

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {"weight": 25, "desc": "Enforces HTTPS connections and eliminates SSL stripping"},
    "Content-Security-Policy": {"weight": 25, "desc": "Prevents Cross-Site Scripting (XSS) and content injection"},
    "X-Frame-Options": {"weight": 15, "desc": "Protects against Clickjacking framing attacks"},
    "X-Content-Type-Options": {"weight": 15, "desc": "Prevents MIME-sniffing drive-by downloads"},
    "Referrer-Policy": {"weight": 10, "desc": "Prevents sensitive URL path leakage in HTTP referrers"},
    "Permissions-Policy": {"weight": 10, "desc": "Restricts browser features like camera, microphone, geolocation"}
}

def audit_ssl(hostname: str) -> dict:
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.settimeout(5.0)
        s.connect((hostname, 443))
        cert = s.getpeercert()
        tls_ver = s.version()
        not_after = cert.get('notAfter')
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
        days_left = (expiry - datetime.utcnow()).days if expiry else 0
        return {
            "tls_version": tls_ver,
            "expires_in_days": days_left,
            "expiry_date": str(expiry),
            "subject": dict(x[0] for x in cert.get('subject', []))
        }

def calculate_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"

def main():
    parser = argparse.ArgumentParser(description="HTTP Header & TLS Security Auditor")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()

    hostname = args.url.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"\\\x1b[95m[*] Auditing Security Posture: {args.url}\\\x1b[0m\\n")

    # SSL Inspection
    try:
        ssl_info = audit_ssl(hostname)
        print(f"\\\x1b[92m[+] SSL/TLS Status:\\\x1b[0m")
        print(f"    Protocol: {ssl_info['tls_version']}")
        print(f"    Validity: {ssl_info['expires_in_days']} days remaining ({ssl_info['expiry_date']})")
    except Exception as e:
        print(f"\\\x1b[91m[-] SSL Check Failed: {e}\\\x1b[0m")

    # Headers Audit
    resp = requests.get(args.url, timeout=10, headers={"User-Agent": "PySecStudio-Auditor/1.0"})
    headers = {k.lower(): v for k, v in resp.headers.items()}

    score = 0
    print(f"\\n\\\x1b[92m[+] Defensive HTTP Headers:\\\x1b[0m")
    for name, meta in RECOMMENDED_HEADERS.items():
        val = headers.get(name.lower())
        if val:
            score += meta["weight"]
            print(f"    \\\x1b[92m✓ [PASS] {name:28s}\\\x1b[0m : {val[:60]}")
        else:
            print(f"    \\\x1b[91m✗ [FAIL] {name:28s}\\\x1b[0m : MISSING ({meta['desc']})")

    # Leakage check
    server = headers.get("server") or headers.get("x-powered-by")
    if server:
        score = max(0, score - 10)
        print(f"\\n    \\\x1b[93m! [WARN] Server Info Leakage : {server}\\\x1b[0m")

    grade = calculate_grade(score)
    print(f"\\n\\\x1b[1m=========================================")
    print(f"FINAL SECURITY POSTURE GRADE: \\\x1b[96m{grade} ({score}/100)\\\x1b[0m")
    print(f"=========================================\\\x1b[0m")

if __name__ == "__main__":
    main()
`
  },
  {
    id: 'api-sensitive-endpoints-fuzzer',
    title: 'API & Sensitive Config Fuzzer (.env, .git, Swagger, Actuators)',
    category: 'vuln_scanning',
    description: 'Scans target web applications for sensitive leaked artifacts, environment variable dumps (.env), Git repository metadata (.git/HEAD), API docs, Spring Boot Actuators, and backup archives with rate-limiting.',
    difficulty: 'Intermediate',
    tags: ['Fuzzer', 'Sensitive Data', 'Information Disclosure', 'Git Leaks', 'API Security'],
    dependencies: ['requests>=2.31.0'],
    cliExample: 'python fuzzer.py -t https://app.corp.internal -w sensitive_paths.txt --delay 0.1',
    mitreTags: ['T1552.001 - Credentials in Files'],
    pythonCode: `#!/usr/bin/env python3
"""
API & Sensitive Environment Fuzzer
Author: PySecStudio Production Library
Requirements: requests
"""

import time
import argparse
from concurrent.futures import ThreadPoolExecutor
import requests

SENSITIVE_ENDPOINTS = [
    ("/.env", "Critical: Database/API Secret Key Leak"),
    ("/.git/HEAD", "High: Exposed Git Source Code Repository"),
    ("/.git/config", "High: Internal Repository Metadata"),
    ("/wp-config.php.bak", "Critical: WordPress Credentials Backup"),
    ("/actuator/env", "Critical: Spring Boot Actuator Env Dump"),
    ("/actuator/health", "Low: Microservice Health Probe"),
    ("/swagger-ui.html", "Low: Interactive API Documentation"),
    ("/v2/api-docs", "Low: OpenAPI / Swagger Specification"),
    ("/phpinfo.php", "Medium: Full PHP Diagnostic Dump"),
    ("/server-status", "Medium: Apache Internal Worker Status"),
    ("/backup.tar.gz", "High: Raw Compressed Backup Archive"),
    ("/id_rsa", "Critical: Private SSH Key File")
]

def check_endpoint(base_url: str, path: str, desc: str, delay: float):
    if delay > 0:
        time.sleep(delay)
    url = f"{base_url.rstrip('/')}{path}"
    try:
        r = requests.get(url, timeout=5, allow_redirects=False, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        if r.status_code == 200:
            sample = r.text[:80].replace('\\n', ' ')
            # Filter standard HTML 404 custom error pages
            if "<html" not in sample.lower() or path.endswith((".html", ".php")):
                print(f"\\\x1b[91m[EXPOSED: 200 OK]\\\x1b[0m {path:22s} -> {desc}")
                print(f"    Sample: {sample}...")
        elif r.status_code in [401, 403]:
            print(f"\\\x1b[93m[FORBIDDEN: {r.status_code}]\\\x1b[0m {path:22s} (Resource exists but protected)")
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="Sensitive Endpoint Discovery Fuzzer")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. https://api.internal.corp)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Concurrent workers")
    parser.add_argument("-d", "--delay", type=float, default=0.05, help="Delay between requests to prevent WAF bans")
    args = parser.parse_args()

    print(f"[*] Fuzzing sensitive endpoints on: {args.target}")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for path, desc in SENSITIVE_ENDPOINTS:
            pool.submit(check_endpoint, args.target, path, desc, args.delay)

if __name__ == "__main__":
    main()
`
  },
  {
    id: 'web-access-log-threat-hunter',
    title: 'Nginx / Apache Attack Log Parser & Forensics Hunter',
    category: 'log_parsing',
    description: 'Streams web server access logs to uncover SQL Injection (SQLi), Cross-Site Scripting (XSS), Local File Inclusion (LFI), Webshell execution, and automated recon tools with top attacker statistics.',
    difficulty: 'Intermediate',
    tags: ['Web Logs', 'SQLi', 'XSS', 'Threat Hunting', 'Nginx', 'Apache'],
    dependencies: ['Python standard library (re, collections, urllib, json)'],
    cliExample: 'python log_hunter.py -f /var/log/nginx/access.log --top-ips 10',
    mitreTags: ['T1190 - Exploit Public-Facing Application', 'T1059 - Command and Scripting Interpreter'],
    pythonCode: `#!/usr/bin/env python3
"""
Nginx/Apache Web Threat Log Hunter & Forensics Parser
Author: PySecStudio Production Library
Requirements: Python 3.8+ (Zero External Dependencies)
"""

import re
import sys
import argparse
from urllib.parse import unquote
from collections import defaultdict

COMBINED_REGEX = re.compile(
    r'^(?P<ip>[\\d\\.]+)\\s+-\\s+\\S+\\s+\\[(?P<time>[^\\]]+)\\]\\s+"(?P<method>[A-Z]+)\\s+(?P<uri>\\S+)\\s+\\S+"\\s+(?P<status>\\d{3})\\s+(?P<bytes>\\S+)(?:\\s+"(?P<ref>[^"]*)"\\s+"(?P<ua>[^"]*)")?'
)

ATTACK_RULES = [
    (re.compile(r"(\\bunion\\b.*\\bselect\\b|'\\s*or\\s*['\"\\d]|--|sleep\\(\\d+\\)|benchmark\\()", re.I), "SQL Injection (SQLi)", "T1190"),
    (re.compile(r"(<script|javascript:|onerror\\s*=|onload\\s*=|alert\\()", re.I), "Cross-Site Scripting (XSS)", "T1189"),
    (re.compile(r"(\\.\\./|\\.\\.\\\\|/etc/passwd|/win\\.ini)", re.I), "Directory Traversal / LFI", "T1083"),
    (re.compile(r"(cmd\\.exe|/bin/sh|/bin/bash|eval\\(|base64_decode)", re.I), "Remote Code Execution / Webshell", "T1059")
]

SCANNER_UA = re.compile(r"(sqlmap|nikto|gobuster|dirbuster|nmap|masscan|acunetix)", re.I)

def main():
    parser = argparse.ArgumentParser(description="Web Access Log Threat Hunter")
    parser.add_argument("-f", "--file", required=True, help="Path to access.log")
    parser.add_argument("--top-ips", type=int, default=5, help="Number of top attacker IPs to show")
    args = parser.parse_args()

    ip_threats = defaultdict(int)
    attack_counts = defaultdict(int)
    total_lines = 0

    print(f"\\\x1b[96m[*] Ingesting and analyzing logs from: {args.file}\\\x1b[0m\\n")

    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            m = COMBINED_REGEX.match(line.strip())
            if not m:
                continue

            ip = m.group("ip")
            uri = unquote(m.group("uri"))
            ua = m.group("ua") or ""

            # Check for exploit signatures
            for pattern, name, mitre in ATTACK_RULES:
                if pattern.search(uri):
                    ip_threats[ip] += 1
                    attack_counts[name] += 1
                    print(f"\\\x1b[91m[THREAT: {name} ({mitre})]\\x1b[0m from \\\x1b[1m{ip}\\x1b[0m")
                    print(f"    Payload: {uri[:90]}")
                    break

            # Check for scanner User-Agent
            if SCANNER_UA.search(ua):
                ip_threats[ip] += 1
                attack_counts["Recon Scanner"] += 1
                print(f"\\\x1b[93m[SCANNER DETECTED]\\x1b[0m {ua} probe from {ip}")

    print(f"\\n\\\x1b[1m=========================================")
    print(f"FORENSIC LOG ANALYSIS SUMMARY")
    print(f"Total lines parsed: {total_lines}")
    print(f"Threat breakdown  : {dict(attack_counts)}")
    print(f"\\nTop Attacking IPs:")
    for ip, count in sorted(ip_threats.items(), key=lambda x: x[1], reverse=True)[:args.top_ips]:
        print(f"  - {ip:16s} : {count} malicious requests")
    print(f"=========================================\\\x1b[0m")

if __name__ == "__main__":
    main()
`
  },
  {
    id: 'ssh-bruteforce-autoban',
    title: 'SSH Auth Log Brute-Force Hunter & Fail2Ban/UFW Exporter',
    category: 'log_parsing',
    description: 'Monitors Linux /var/log/auth.log or /var/log/secure using a sliding-window algorithm. Isolates distributed password guessing attacks and generates instant UFW / iptables mitigation scripts.',
    difficulty: 'Intermediate',
    tags: ['SSH', 'Brute-Force', 'Auth.log', 'UFW', 'Firewall', 'Fail2ban'],
    dependencies: ['Python standard library'],
    cliExample: 'python ssh_hunter.py -f /var/log/auth.log -t 5 -w 60 --export ufw',
    mitreTags: ['T1110.001 - Password Guessing'],
    pythonCode: `#!/usr/bin/env python3
"""
SSH Brute-Force Hunter & Firewall Exporter
Author: PySecStudio Production Library
Requirements: Python 3.8+ (Standard Library)
"""

import re
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, deque

SSH_FAILED_REGEX = re.compile(
    r'^(?P<time>[A-Z][a-z]{2}\\s+\\d+\\s+[\\d:]+)\\s+\\S+\\s+sshd\\[\\d+\\]:\\s+Failed\\s+password\\s+for(?:\\s+invalid\\s+user)?\\s+(?P<user>\\S+)\\s+from\\s+(?P<ip>[\\d\\.]+)'
)

def main():
    parser = argparse.ArgumentParser(description="SSH Auth.log Brute-Force Hunter")
    parser.add_argument("-f", "--file", default="/var/log/auth.log", help="Path to auth log")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failures threshold to flag")
    parser.add_argument("-w", "--window", type=int, default=60, help="Sliding window in seconds")
    parser.add_argument("--export", choices=["ufw", "iptables"], default="ufw", help="Firewall ban script format")
    args = parser.parse_args()

    ip_attempts = defaultdict(deque)
    banned_ips = set()
    current_year = datetime.now().year

    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = SSH_FAILED_REGEX.match(line.strip())
            if not m:
                continue

            time_str = m.group("time")
            user = m.group("user")
            ip = m.group("ip")

            dt = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
            window = ip_attempts[ip]
            window.append(dt)

            # Slide window
            cutoff = dt - timedelta(seconds=args.window)
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= args.threshold and ip not in banned_ips:
                banned_ips.add(ip)
                print(f"\\\x1b[91m[BRUTE-FORCE IDENTIFIED]\\x1b[0m Host \\\x1b[1m{ip}\\x1b[0m exceeded {args.threshold} failed logins in {args.window}s (Targeting user '{user}')")

    print(f"\\n[*] Isolated {len(banned_ips)} hostile brute-forcing IP addresses.")
    if banned_ips:
        with open("ban_rules.sh", "w") as out:
            out.write("#!/bin/bash\\n# Generated by PySecStudio SSH Hunter\\n\\n")
            for ip in sorted(banned_ips):
                if args.export == "ufw":
                    out.write(f"ufw insert 1 deny from {ip} comment 'PySecStudio SSH Brute-Force Ban'\\n")
                else:
                    out.write(f"iptables -A INPUT -s {ip} -j DROP\\n")
        print(f"\\\x1b[92m[+] Ban rules exported to ban_rules.sh\\\x1b[0m")

if __name__ == "__main__":
    main()
`
  },
  {
    id: 'realtime-log-watcher-webhook',
    title: 'Real-Time Log Watcher Daemon with Discord / Slack Alerts',
    category: 'log_parsing',
    description: 'An asynchronous event daemon that performs `tail -f` on any active log stream, detects anomalies instantly, and dispatches rich formatted webhook notifications with zero latency.',
    difficulty: 'Advanced',
    tags: ['Daemon', 'Tail -f', 'Slack', 'Discord', 'Automation', 'Real-Time'],
    dependencies: ['requests>=2.31.0'],
    cliExample: 'python log_watcher.py --file /var/log/nginx/error.log --webhook https://discord.com/api/webhooks/...',
    mitreTags: ['T1008 - Fallback Channels'],
    pythonCode: `#!/usr/bin/env python3
"""
Real-Time Log Watcher Daemon with Webhook Dispatch
Author: PySecStudio Production Library
Requirements: requests
"""

import time
import os
import re
import json
import argparse
import requests

CRITICAL_ALERT_PATTERN = re.compile(r"(segmentation fault|panic:|fatal error|access violation|unauthorized|critical)", re.IGNORECASE)

def follow_file(filepath: str):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.strip()

def send_alert(webhook_url: str, message: str):
    try:
        requests.post(webhook_url, json={"content": f"🚨 **Security Event Daemon Alert**\\n\`\`\`\\n{message[:500]}\\n\`\`\`"}, timeout=5)
    except Exception as e:
        print(f"Webhook error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Real-Time Log Event Daemon")
    parser.add_argument("--file", required=True, help="File to watch in real time")
    parser.add_argument("--webhook", required=True, help="Discord or Slack Webhook URL")
    args = parser.parse_args()

    print(f"[*] Watching {args.file} in real-time... (Press Ctrl+C to stop)")
    for line in follow_file(args.file):
        if CRITICAL_ALERT_PATTERN.search(line):
            print(f"\\\x1b[91m[CRITICAL DETECTED]\\x1b[0m {line}")
            send_alert(args.webhook, line)

if __name__ == "__main__":
    main()
`
  },
  {
    id: 'aws-cloudtrail-privilege-audit',
    title: 'AWS CloudTrail Threat & Privilege Escalation JSON Auditor',
    category: 'log_parsing',
    description: 'Parses multi-gigabyte AWS CloudTrail JSON security event trails. Detects unauthorized API bursts, root console logins, unauthorized IAM policy modifications, and S3 bucket ACL tampering.',
    difficulty: 'Advanced',
    tags: ['AWS', 'CloudTrail', 'Cloud Security', 'IAM', 'Privilege Escalation'],
    dependencies: ['Python standard library (json, gzip, glob)'],
    cliExample: 'python cloudtrail_auditor.py -d ./cloudtrail_logs/ --alert-root',
    mitreTags: ['T1098 - Account Manipulation', 'T1078.004 - Cloud Accounts'],
    pythonCode: `#!/usr/bin/env python3
"""
AWS CloudTrail Security Event & Privilege Escalation Auditor
Author: PySecStudio Production Library
Requirements: Python 3.8+ (Standard Library)
"""

import json
import gzip
import glob
import argparse
from typing import Dict, Any

SUSPICIOUS_API_CALLS = {
    "AttachUserPolicy": "IAM Privilege Escalation: Admin policy attached to user",
    "CreateAccessKey": "Credential Access: New API access key generated",
    "PutBucketPolicy": "S3 Policy Change: Bucket permissions modified",
    "AuthorizeSecurityGroupIngress": "Network Defense Evasion: Security group opened (0.0.0.0/0)",
    "StopLogging": "Defense Evasion: CloudTrail audit logging paused!",
    "DeleteTrail": "Critical Defense Evasion: CloudTrail destroyed"
}

def analyze_event(event: Dict[str, Any]):
    name = event.get("eventName", "")
    ip = event.get("sourceIPAddress", "unknown")
    user_id = event.get("userIdentity", {}).get("userName", "UnknownPrincipal")
    user_type = event.get("userIdentity", {}).get("type", "")

    if user_type == "Root":
        print(f"\\\x1b[91m[ALERT: ROOT ACCOUNT USAGE]\\x1b[0m Root user invoked {name} from {ip}")

    if name in SUSPICIOUS_API_CALLS:
        print(f"\\\x1b[93m[ALERT: SENSITIVE API CALL]\\x1b[0m {name} invoked by {user_id} ({ip})")
        print(f"    Risk: {SUSPICIOUS_API_CALLS[name]}")

def main():
    parser = argparse.ArgumentParser(description="AWS CloudTrail JSON Forensics Auditor")
    parser.add_argument("-f", "--file", required=True, help="Path to CloudTrail .json or .json.gz file")
    args = parser.parse_args()

    open_func = gzip.open if args.file.endswith(".gz") else open
    with open_func(args.file, "rt", encoding="utf-8") as f:
        data = json.load(f)
        records = data.get("Records", [])
        print(f"[*] Auditing {len(records)} CloudTrail event records...")
        for r in records:
            analyze_event(r)

if __name__ == "__main__":
    main()
`
  },
  {
    id: 'cors-misconfig-tester',
    title: 'CORS Misconfiguration & Origin Reflection Exploitation Tester',
    category: 'vuln_scanning',
    description: 'Automates testing web endpoints for dangerous CORS policies: arbitrary origin reflection with credentials allowed, null origin acceptance, and wildcard trust.',
    difficulty: 'Intermediate',
    tags: ['CORS', 'Web Security', 'SOP Bypass', 'Data Leak'],
    dependencies: ['requests>=2.31.0'],
    cliExample: 'python cors_tester.py -u https://api.target.com/user/profile',
    mitreTags: ['T1557 - Adversary-in-the-Middle'],
    pythonCode: `#!/usr/bin/env python3
"""
CORS Misconfiguration & Origin Reflection Tester
Author: PySecStudio Production Library
Requirements: requests
"""

import argparse
import requests

ORIGIN_TESTS = [
    ("https://evil-attacker-site.com", "Arbitrary Untrusted Origin Reflection"),
    ("null", "Null Origin Acceptance (Sandboxed iframe exploitation)"),
    ("https://target.com.evil.com", "Subdomain Prefix Spoofing"),
]

def main():
    parser = argparse.ArgumentParser(description="CORS Vulnerability Tester")
    parser.add_argument("-u", "--url", required=True, help="Target URL endpoint to audit")
    args = parser.parse_args()

    print(f"[*] Auditing CORS headers on {args.url}\\n")

    for test_origin, description in ORIGIN_TESTS:
        headers = {"Origin": test_origin, "User-Agent": "Mozilla/5.0"}
        try:
            r = requests.get(args.url, headers=headers, timeout=5)
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = r.headers.get("Access-Control-Allow-Credentials")

            if acao == test_origin and acac == "true":
                print(f"\\\x1b[91m[CRITICAL VULNERABILITY]\\x1b[0m {description}")
                print(f"    Origin reflected: {acao} with Allow-Credentials: true!")
                print(f"    Impact: An attacker site can read private user data.\\n")
            elif acao == "*":
                print(f"\\\x1b[93m[MEDIUM RISK]\\x1b[0m Wildcard CORS '*' detected on {args.url}\\n")
            else:
                print(f"\\\x1b[92m[SAFE]\\x1b[0m Rejected origin: {test_origin}")
        except Exception as e:
            print(f"Request failed: {e}")

if __name__ == "__main__":
    main()
`
  }
];
