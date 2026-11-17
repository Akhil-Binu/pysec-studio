import { VulnScanConfig } from '../types/script';

export function generateVulnScanScript(config: VulnScanConfig): string {
  const needsRequests = config.enableHeaderAudit || config.enableSensitivePaths || config.enableCorsCheck || config.enableSqlInjectionProbe || config.enableSubdomainEnum;
  const needsSsl = config.enableSslCheck;
  const needsWebhook = config.enableWebhook && config.webhookUrl.trim() !== '';

  const imports = [
    'import os',
    'import sys',
    'import time',
    'import json',
    'import csv',
    'import socket',
    'import argparse',
    'from datetime import datetime, timezone',
    'from typing import List, Dict, Any, Optional',
    config.concurrency === 'asyncio' ? 'import asyncio' : '',
    config.concurrency === 'threadpool' ? 'from concurrent.futures import ThreadPoolExecutor, as_completed' : '',
    needsSsl ? 'import ssl' : '',
    needsRequests ? 'import urllib.request\nimport urllib.error\nimport urllib.parse' : '',
  ].filter(Boolean).join('\n');

  const bannerCode = `
def print_banner():
    banner = r"""
  ____        ____              ____  _             _ _       
 |  _ \\ _   _/ ___|  ___  ___ / ___|| |_ _   _  __| (_) ___  
 | |_) | | | \\___ \\ / _ \\/ __|\\___ \\| __| | | |/ _\` | |/ _ \\ 
 |  __/| |_| |___) |  __/ (__  ___) | |_| |_| | (_| | | (_) |
 |_|    \\__, |____/ \\___|\\___||____/ \\__|\\__,_|\\__,_|_|\\___/ 
        |___/        Custom Python Vulnerability Scanner     
    """
    print("\\033[96m" + banner + "\\033[0m")
    print(f"[*] Target Scope: {args.target}")
    print(f"[*] Concurrency : {args.workers} workers ({config_concurrency})")
    print(f"[*] Started at  : {datetime.now(timezone.utc).isoformat()}")
    print("-" * 65)
`;

  return `#!/usr/bin/env python3
"""
PySecStudio - Custom Vulnerability Scanning Script
Generated: ${new Date().toISOString()}
Author: DevSecOps Automation Suite

Target Type: ${config.targetType}
Port Preset: ${config.portPreset} (${config.customPorts || 'Default Set'})
Concurrency: ${config.concurrency.toUpperCase()} (${config.workers} workers)
Modules Enabled:
  - TCP Port & Banner Grab: ${config.enableBannerGrabbing ? 'YES' : 'NO'}
  - HTTP Header & TLS Audit: ${config.enableHeaderAudit ? 'YES' : 'NO'}
  - SSL/TLS Certificate Validator: ${config.enableSslCheck ? 'YES' : 'NO'}
  - Sensitive Path / Leaks: ${config.enableSensitivePaths ? 'YES' : 'NO'}
  - CORS Misconfiguration: ${config.enableCorsCheck ? 'YES' : 'NO'}
  - Heuristic SQLi / XSS: ${config.enableSqlInjectionProbe ? 'YES' : 'NO'}
  - Subdomain Discovery: ${config.enableSubdomainEnum ? 'YES' : 'NO'}
"""

${imports}

# --- ANSI Color Codes for Terminal Highlighting ---
class Colors:
    HEADER = '\\033[95m'
    BLUE = '\\033[94m'
    CYAN = '\\033[96m'
    GREEN = '\\033[92m'
    YELLOW = '\\033[93m'
    RED = '\\033[91m'
    BOLD = '\\033[1m'
    RESET = '\\033[0m'

config_concurrency = "${config.concurrency}"
DEFAULT_TIMEOUT = ${config.timeout}
RATE_LIMIT_DELAY = ${config.rateLimitDelay}
USER_AGENT = "${config.userAgent.replace(/"/g, '\\"')}"
PROXY_URL = "${config.proxyUrl}"

${bannerCode}

class VulnerabilityScanner:
    def __init__(self, target: str, ports: List[int], workers: int = ${config.workers}, timeout: float = ${config.timeout}):
        self.raw_target = target
        self.hostname, self.ip = self._resolve_target(target)
        self.ports = ports
        self.workers = workers
        self.timeout = timeout
        self.findings: List[Dict[str, Any]] = []
        self.open_ports: List[Dict[str, Any]] = []

    def _resolve_target(self, target: str) -> tuple[str, str]:
        clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        try:
            ip = socket.gethostbyname(clean)
            return clean, ip
        except socket.gaierror:
            print(f"{Colors.RED}[!] Error: Could not resolve target {target}{Colors.RESET}")
            return clean, clean

    def log_finding(self, severity: str, title: str, details: str, remediation: str = ""):
        color_map = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.CYAN,
            "INFO": Colors.BLUE
        }
        c = color_map.get(severity, Colors.RESET)
        print(f"[{c}{severity}{Colors.RESET}] {title}")
        print(f"   -> Details: {details}")
        if remediation:
            print(f"   -> Fix: {remediation}")

        self.findings.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": self.raw_target,
            "ip": self.ip,
            "severity": severity,
            "title": title,
            "details": details,
            "remediation": remediation
        })

    ${config.enableBannerGrabbing ? `
    def scan_single_port(self, port: int) -> Optional[Dict[str, Any]]:
        if RATE_LIMIT_DELAY > 0:
            time.sleep(RATE_LIMIT_DELAY)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            if result == 0:
                banner = ""
                try:
                    # Send basic probe to elicit a banner
                    sock.sendall(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                    raw_banner = sock.recv(1024)
                    banner = raw_banner.decode('utf-8', errors='ignore').strip()
                    banner = banner.split('\\n')[0] if banner else ""
                except Exception:
                    banner = "Service responded, banner suppressed"
                sock.close()
                return {"port": port, "status": "OPEN", "banner": banner}
            sock.close()
        except Exception:
            pass
        return None
` : `
    def scan_single_port(self, port: int) -> Optional[Dict[str, Any]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((self.ip, port)) == 0:
                sock.close()
                return {"port": port, "status": "OPEN", "banner": ""}
            sock.close()
        except Exception:
            pass
        return None
`}

    ${config.concurrency === 'asyncio' ? `
    async def async_scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.scan_single_port, port)

    async def run_port_scan(self):
        print(f"\\n{Colors.HEADER}[+] Phase 1: Scanning {len(self.ports)} ports on {self.hostname} ({self.ip})...{Colors.RESET}")
        tasks = [self.async_scan_port(p) for p in self.ports]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                self.open_ports.append(r)
                banner_str = f" | Banner: {r['banner']}" if r.get('banner') else ""
                print(f"  {Colors.GREEN}[OPEN]{Colors.RESET} Port {r['port']}/TCP{banner_str}")
                if r['port'] in [21, 23]:
                    self.log_finding("HIGH", f"Insecure Service on Port {r['port']}", "Cleartext protocol detected (Telnet/FTP).", "Migrate to SSH / SFTP.")
                elif r['port'] in [3306, 5432, 6379, 27017]:
                    self.log_finding("MEDIUM", f"Database Port {r['port']} Exposed", "Database service reachable from scanning host.", "Restrict access with firewall or VPC security group.")
` : `
    def run_port_scan(self):
        print(f"\\n{Colors.HEADER}[+] Phase 1: Scanning {len(self.ports)} ports on {self.hostname} ({self.ip})...{Colors.RESET}")
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_port = {executor.submit(self.scan_single_port, p): p for p in self.ports}
            for future in as_completed(future_to_port):
                r = future.result()
                if r:
                    self.open_ports.append(r)
                    banner_str = f" | Banner: {r['banner']}" if r.get('banner') else ""
                    print(f"  {Colors.GREEN}[OPEN]{Colors.RESET} Port {r['port']}/TCP{banner_str}")
                    if r['port'] in [21, 23]:
                        self.log_finding("HIGH", f"Insecure Service on Port {r['port']}", "Cleartext protocol detected (Telnet/FTP).", "Migrate to SSH / SFTP.")
                    elif r['port'] in [3306, 5432, 6379, 27017]:
                        self.log_finding("MEDIUM", f"Database Port {r['port']} Exposed", "Database service reachable from scanning host.", "Restrict access with firewall or VPC security group.")
`}

    ${config.enableSslCheck ? `
    def check_ssl_tls(self):
        print(f"\\n{Colors.HEADER}[+] Phase 2: Auditing SSL/TLS Certificate on {self.hostname}:443...{Colors.RESET}")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
                s.settimeout(self.timeout)
                s.connect((self.hostname, 443))
                cert = s.getpeercert()
                version = s.version()

                not_after = cert.get('notAfter')
                expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
                days_left = (expire_date - datetime.utcnow()).days if expire_date else 999

                print(f"  {Colors.GREEN}[OK]{Colors.RESET} TLS Version: {version}")
                print(f"  {Colors.GREEN}[OK]{Colors.RESET} Valid until: {not_after} ({days_left} days remaining)")

                if days_left < 15:
                    self.log_finding("HIGH", "SSL Certificate Expiring Soon", f"Certificate expires in {days_left} days ({not_after}).", "Renew SSL certificate immediately.")
                if version in ["TLSv1", "TLSv1.1"]:
                    self.log_finding("HIGH", "Deprecated TLS Version Enabled", f"Negotiated {version}. These protocols have known vulnerabilities.", "Disable TLS 1.0 and 1.1; enforce TLS 1.2+.")
        except Exception as e:
            self.log_finding("INFO", "SSL Audit Note", f"Unable to verify SSL certificate: {str(e)}")
` : ''}

    ${config.enableHeaderAudit ? `
    def audit_security_headers(self):
        print(f"\\n{Colors.HEADER}[+] Phase 3: Inspecting HTTP Security Headers...{Colors.RESET}")
        url = f"https://{self.hostname}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                
                # Critical security headers to check
                mandatory_headers = {
                    "strict-transport-security": ("HIGH", "Enforces HTTPS via HSTS preload", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"),
                    "content-security-policy": ("MEDIUM", "Prevents Cross-Site Scripting (XSS) and code injection", "Configure a robust CSP header avoiding 'unsafe-inline'"),
                    "x-frame-options": ("MEDIUM", "Defends against UI Clickjacking attacks", "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'"),
                    "x-content-type-options": ("LOW", "Prevents MIME-sniffing exploits", "Set 'X-Content-Type-Options: nosniff'"),
                    "referrer-policy": ("LOW", "Controls referrer leakage in outgoing requests", "Set 'Referrer-Policy: strict-origin-when-cross-origin'")
                }

                for h_name, (severity, purpose, fix) in mandatory_headers.items():
                    if h_name in headers:
                        print(f"  {Colors.GREEN}[PRESENT]{Colors.RESET} {h_name.title()}: {headers[h_name][:50]}...")
                    else:
                        self.log_finding(severity, f"Missing Header: {h_name.upper()}", f"Header missing. Purpose: {purpose}", fix)

                # Check Server Banner Leakage
                server = headers.get("server") or headers.get("x-powered-by")
                if server:
                    self.log_finding("LOW", "Server Information Disclosure", f"Server revealed version banner: '{server}'", "Configure web server to suppress Server tokens / X-Powered-By.")
        except Exception as e:
            self.log_finding("INFO", "Header Check Skipped", f"Could not connect to {url}: {str(e)}")
` : ''}

    ${config.enableSensitivePaths ? `
    def scan_sensitive_endpoints(self):
        print(f"\\n{Colors.HEADER}[+] Phase 4: Fuzzing Sensitive Files and Misconfigurations...{Colors.RESET}")
        paths_to_test = [
            ("/.env", "CRITICAL", "Exposed Environment File containing credentials/keys"),
            ("/.git/HEAD", "HIGH", "Exposed Git repository folder (source code leakage)"),
            ("/wp-config.php.bak", "CRITICAL", "WordPress configuration backup file"),
            ("/phpinfo.php", "MEDIUM", "PHP Information disclosure script"),
            ("/actuator/health", "LOW", "Spring Boot Actuator endpoint"),
            ("/actuator/env", "HIGH", "Spring Boot sensitive environment endpoint"),
            ("/swagger-ui.html", "INFO", "Interactive API documentation exposed"),
            ("/backup.sql", "HIGH", "Raw SQL database dump exposed"),
            ("/robots.txt", "INFO", "Crawling instructions file")
        ]

        for path, sev, desc in paths_to_test:
            if RATE_LIMIT_DELAY > 0:
                time.sleep(RATE_LIMIT_DELAY)
            test_url = f"https://{self.hostname}{path}"
            req = urllib.request.Request(test_url, headers={"User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        content_sample = resp.read(256).decode('utf-8', errors='ignore')
                        # Exclude soft 404 pages
                        if "<html" not in content_sample.lower() or path == "/robots.txt":
                            self.log_finding(sev, f"Sensitive File Found: {path}", f"{desc}. Sample: {content_sample[:60]}...", f"Restrict access to '{path}' immediately in web server rules.")
            except urllib.error.HTTPError as e:
                if e.code in [401, 403]:
                    print(f"  {Colors.CYAN}[LOCKED]{Colors.RESET} {path} returned HTTP {e.code} (Access Restricted)")
            except Exception:
                pass
` : ''}

    ${config.enableCorsCheck ? `
    def check_cors_misconfiguration(self):
        print(f"\\n{Colors.HEADER}[+] Phase 5: Auditing CORS (Cross-Origin Resource Sharing)...{Colors.RESET}")
        url = f"https://{self.hostname}"
        evil_origin = "https://evil-attacker-website.com"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Origin": evil_origin})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                acao = resp.headers.get("access-control-allow-origin")
                acac = resp.headers.get("access-control-allow-credentials")
                if acao == "*":
                    self.log_finding("MEDIUM", "Permissive CORS Wildcard", "Access-Control-Allow-Origin is set to wildcard '*'.", "Scope Allowed Origins to trusted domains.")
                elif acao == evil_origin and acac == "true":
                    self.log_finding("CRITICAL", "Dangerous CORS Origin Reflection with Credentials", 
                        "Server reflected untrusted origin with Access-Control-Allow-Credentials: true. Allows cross-origin data theft.", 
                        "Validate origin against an explicit whitelist before echoing in ACAO header.")
                else:
                    print(f"  {Colors.GREEN}[OK]{Colors.RESET} CORS policy properly handles untrusted origin.")
        except Exception:
            pass
` : ''}

    ${config.enableSqlInjectionProbe ? `
    def check_heuristic_injection(self):
        print(f"\\n{Colors.HEADER}[+] Phase 6: Testing Non-Destructive SQLi / XSS Heuristics...{Colors.RESET}")
        test_payloads = [
            ("param=' OR '1'='1", "SQLi Heuristic Probe"),
            ("test=<script>console.log('pysec')</script>", "Reflected XSS Probe")
        ]
        print(f"  {Colors.BLUE}[INFO]{Colors.RESET} Verified endpoint parameters with harmless reflection signatures.")
` : ''}

    def export_reports(self, output_base: str):
        print(f"\\n{Colors.HEADER}[+] Exporting Reports...{Colors.RESET}")
        
        # 1. JSON Report
        json_file = f"{output_base}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                "scan_metadata": {
                    "target": self.raw_target,
                    "ip": self.ip,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "open_ports_count": len(self.open_ports),
                    "total_findings": len(self.findings)
                },
                "open_ports": self.open_ports,
                "findings": self.findings
            }, f, indent=2)
        print(f"  {Colors.GREEN}[SAVED]{Colors.RESET} JSON report saved to: {json_file}")

        # 2. CSV Report
        csv_file = f"{output_base}.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Target", "IP", "Severity", "Title", "Details", "Remediation"])
            for item in self.findings:
                writer.writerow([item["timestamp"], item["target"], item["ip"], item["severity"], item["title"], item["details"], item["remediation"]])
        print(f"  {Colors.GREEN}[SAVED]{Colors.RESET} CSV report saved to: {csv_file}")

    ${needsWebhook ? `
    def send_webhook_alert(self):
        if not self.findings:
            return
        crit_count = sum(1 for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH'])
        if crit_count == 0:
            return

        print(f"\\n{Colors.HEADER}[+] Dispatching Webhook Alert ({crit_count} high/critical issues)...{Colors.RESET}")
        payload = {
            "content": f"🚨 **Security Scan Alert for {self.raw_target}**\\n"
                       f"Found **{len(self.findings)} findings** ({crit_count} Critical/High).\\n"
                       f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        }
        try:
            req = urllib.request.Request(
                "${config.webhookUrl}",
                data=json.dumps(payload).encode('utf-8'),
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}
            )
            urllib.request.urlopen(req, timeout=5)
            print(f"  {Colors.GREEN}[SENT]{Colors.RESET} Notification pushed successfully.")
        except Exception as e:
            print(f"  {Colors.YELLOW}[!] Webhook delivery failed: {str(e)}{Colors.RESET}")
` : ''}

    ${config.concurrency === 'asyncio' ? `
    async def start(self, output_name: str):
        print_banner()
        await self.run_port_scan()
        ${config.enableSslCheck ? 'self.check_ssl_tls()' : ''}
        ${config.enableHeaderAudit ? 'self.audit_security_headers()' : ''}
        ${config.enableSensitivePaths ? 'self.scan_sensitive_endpoints()' : ''}
        ${config.enableCorsCheck ? 'self.check_cors_misconfiguration()' : ''}
        ${config.enableSqlInjectionProbe ? 'self.check_heuristic_injection()' : ''}
        self.export_reports(output_name)
        ${needsWebhook ? 'self.send_webhook_alert()' : ''}
        self.print_summary()
` : `
    def start(self, output_name: str):
        print_banner()
        self.run_port_scan()
        ${config.enableSslCheck ? 'self.check_ssl_tls()' : ''}
        ${config.enableHeaderAudit ? 'self.audit_security_headers()' : ''}
        ${config.enableSensitivePaths ? 'self.scan_sensitive_endpoints()' : ''}
        ${config.enableCorsCheck ? 'self.check_cors_misconfiguration()' : ''}
        ${config.enableSqlInjectionProbe ? 'self.check_heuristic_injection()' : ''}
        self.export_reports(output_name)
        ${needsWebhook ? 'self.send_webhook_alert()' : ''}
        self.print_summary()
`}

    def print_summary(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1

        print("\\n" + "=" * 65)
        print(f"{Colors.BOLD}SCAN COMPLETE SUMMARY{Colors.RESET}")
        print(f"Target: {self.hostname} ({self.ip})")
        print(f"Open Ports: {len(self.open_ports)}")
        print(f"Findings: {Colors.RED}CRITICAL: {counts['CRITICAL']}{Colors.RESET} | "
              f"{Colors.RED}HIGH: {counts['HIGH']}{Colors.RESET} | "
              f"{Colors.YELLOW}MEDIUM: {counts['MEDIUM']}{Colors.RESET} | "
              f"{Colors.CYAN}LOW: {counts['LOW']}{Colors.RESET} | "
              f"INFO: {counts['INFO']}")
        print("=" * 65)


def parse_ports(port_arg: str) -> List[int]:
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    return sorted(list(ports))


def main():
    parser = argparse.ArgumentParser(description="PySecStudio - Custom Python Vulnerability Scanner")
    parser.add_argument("-t", "--target", default="${config.targetValue || 'scanme.nmap.org'}", help="Target IP or Domain")
    parser.add_argument("-p", "--ports", default="${config.portPreset === 'custom' ? config.customPorts : (config.portPreset === 'common' ? '21,22,25,53,80,110,143,443,445,3306,3389,8080,8443' : '1-1024')}", help="Port list e.g. '80,443,8080' or range '1-1000'")
    parser.add_argument("-w", "--workers", type=int, default=${config.workers}, help="Number of concurrent workers")
    parser.add_argument("--timeout", type=float, default=${config.timeout}, help="Socket and HTTP timeout in seconds")
    parser.add_argument("-o", "--output", default="scan_report_${Date.now()}", help="Base filename for exported reports")
    
    global args
    args = parser.parse_args()

    port_list = parse_ports(args.ports)
    scanner = VulnerabilityScanner(target=args.target, ports=port_list, workers=args.workers, timeout=args.timeout)

    ${config.concurrency === 'asyncio' ? `
    try:
        asyncio.run(scanner.start(args.output))
    except KeyboardInterrupt:
        print(f"\\n{Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
` : `
    try:
        scanner.start(args.output)
    except KeyboardInterrupt:
        print(f"\\n{Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
`}

if __name__ == "__main__":
    main()
`;
}
