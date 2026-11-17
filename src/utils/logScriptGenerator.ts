import { LogParserConfig } from '../types/script';

export function generateLogParserScript(config: LogParserConfig): string {
  const isWebLog = config.logType === 'nginx' || config.logType === 'apache';
  const isSshLog = config.logType === 'ssh';
  const isCloudTrail = config.logType === 'cloudtrail';
  const needsWebhook = config.enableWebhookAlert && config.webhookUrl.trim() !== '';

  const webhookMethod = needsWebhook ? `
    def dispatch_webhook(self, alert_event: Dict[str, Any]):
        try:
            payload = {
                "text": f"SIEM Alert - {alert_event['severity']}\\n"
                        f"Threat: {alert_event['title']}\\n"
                        f"Source IP: {alert_event['ip']}\\n"
                        f"MITRE ATT&CK: {alert_event['mitre_id']}\\n"
                        f"Details: {alert_event['details']}"
            }
            req = urllib.request.Request(
                "${config.webhookUrl}",
                data=json.dumps(payload).encode('utf-8'),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass
` : '';

  let logPatternDefinition = '';
  if (isWebLog) {
    logPatternDefinition = `LOG_PATTERN = re.compile(
    r'^(?P<ip>[\\d\\.:a-fA-F]+)\\s+-\\s+(?P<user>[^\\s]+)\\s+\\[(?P<timestamp>[^\\]]+)\\]\\s+"(?P<method>[A-Z]+)\\s+(?P<path>[^\\s]+)\\s+(?P<proto>[^"]+)"\\s+(?P<status>\\d{3})\\s+(?P<bytes>\\d+|-)(?:\\s+"(?P<referrer>[^"]*)"\\s+"(?P<user_agent>[^"]*)")?'
)`;
  } else if (isSshLog) {
    logPatternDefinition = `LOG_PATTERN = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\\s+\\d+\\s+[\\d:]+)\\s+(?P<host>[^\\s]+)\\s+(?P<daemon>sshd\\[\\d+\\]):\\s+(?P<message>.*)'
)
SSH_FAILED_PATTERN = re.compile(r'Failed\\s+password\\s+for(?:\\s+invalid\\s+user)?\\s+(?P<user>[^\\s]+)\\s+from\\s+(?P<ip>[\\d\\.:a-fA-F]+)')
SSH_ACCEPTED_PATTERN = re.compile(r'Accepted\\s+(?:password|publickey)\\s+for\\s+(?P<user>[^\\s]+)\\s+from\\s+(?P<ip>[\\d\\.:a-fA-F]+)')`;
  } else {
    logPatternDefinition = `LOG_PATTERN = re.compile(r'${config.customRegex || '(?P<timestamp>[^ ]+) (?P<ip>[^ ]+) (?P<message>.*)'}')`;
  }

  let eventAnalysisBody = '';
  if (isWebLog) {
    eventAnalysisBody = `
        status = event.get("status")
        if status:
            self.stats["status_counts"][status] += 1

        path = event.get("path", "")
        ua = event.get("user_agent", "")

        ${config.enableScannerDetection ? `if ua and SUSPICIOUS_USER_AGENTS.search(ua):
            scanner_match = SUSPICIOUS_USER_AGENTS.search(ua).group(0)
            self.trigger_alert(
                severity="HIGH",
                title=f"Automated Security Scanner Identified ({scanner_match})",
                ip=ip,
                details=f"Scanner probe on {path} with User-Agent: {ua}",
                mitre_id="T1595.002"
            )` : ''}

        ${config.enableWebAttackDetection ? `decoded_path = urllib.parse.unquote(path)
        for pattern, attack_name, mitre_code, sev in WEB_ATTACK_SIGNATURES:
            if pattern.search(decoded_path):
                self.trigger_alert(
                    severity=sev,
                    title=f"Web Exploitation Pattern: {attack_name}",
                    ip=ip,
                    details=f"Exploit payload detected in URI: {decoded_path}",
                    mitre_id=mitre_code
                )
                break` : ''}

        ${config.enableBruteForceDetection ? `if status in ["401", "403"]:
            self.check_brute_force(ip, datetime.now(timezone.utc))` : ''}
    `;
  } else if (isSshLog) {
    eventAnalysisBody = `
        msg = event.get("message", "")
        failed_match = SSH_FAILED_PATTERN.search(msg)
        if failed_match:
            f_user = failed_match.group("user")
            f_ip = failed_match.group("ip")
            ${config.enableBruteForceDetection ? `self.check_brute_force(f_ip, datetime.now(timezone.utc))` : ''}

        accepted_match = SSH_ACCEPTED_PATTERN.search(msg)
        if accepted_match:
            acc_user = accepted_match.group("user")
            acc_ip = accepted_match.group("ip")
            if acc_user == "root":
                self.trigger_alert(
                    severity="MEDIUM",
                    title="Direct Root SSH Login Accepted",
                    ip=acc_ip,
                    details=f"Successful root login from {acc_ip}. Consider disabling PermitRootLogin in sshd_config.",
                    mitre_id="T1078.003"
                )
    `;
  } else if (isCloudTrail) {
    eventAnalysisBody = `
        event_name = event.get("eventName", "")
        error_code = event.get("errorCode", "")
        if error_code in ["AccessDenied", "UnauthorizedOperation"]:
            self.trigger_alert(
                severity="HIGH",
                title=f"CloudTrail Unauthorized API Attempt ({event_name})",
                ip=ip,
                details=f"Denied calling {event_name}: {event.get('errorMessage', '')}",
                mitre_id="T1078.004"
            )
        elif event_name in ["ConsoleLogin", "CreateUser", "AttachUserPolicy", "AuthorizeSecurityGroupIngress"]:
            self.trigger_alert(
                severity="MEDIUM",
                title=f"Sensitive Cloud IAM Activity ({event_name})",
                ip=ip,
                details=f"High privilege action executed: {event_name}",
                mitre_id="T1098"
            )
    `;
  } else {
    eventAnalysisBody = `
        msg = event.get("message", "")
        for pattern, attack_name, mitre_code, sev in WEB_ATTACK_SIGNATURES:
            if pattern.search(msg):
                self.trigger_alert(sev, attack_name, ip, msg, mitre_code)
                break
    `;
  }

  const cloudTrailJsonParsing = isCloudTrail ? `
    try:
        data = json.loads(line)
        return {
            "ip": data.get("sourceIPAddress", "unknown"),
            "eventName": data.get("eventName"),
            "errorCode": data.get("errorCode"),
            "errorMessage": data.get("errorMessage")
        }
    except Exception:
        pass
` : '';

  const defaultFilePath = config.filePath || (isWebLog ? '/var/log/nginx/access.log' : isSshLog ? '/var/log/auth.log' : 'security.log');

  return `#!/usr/bin/env python3
"""
PySecStudio - High-Performance Python Log Parser & Threat Detection Script
Generated: ${new Date().toISOString()}
Author: Cyber Forensics & Threat Hunting Automation

Target Log Type: ${config.logType.toUpperCase()}
Input Mode: ${config.inputMode.toUpperCase()}
Processing Engine: Streaming Generator (O(1) Memory Overhead)
"""

import os
import sys
import re
import time
import json
import csv
import argparse
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from typing import Generator, Dict, Any, Optional, List
import urllib.request
import urllib.parse

class Colors:
    HEADER = '\\x1b[95m'
    BLUE = '\\x1b[94m'
    CYAN = '\\x1b[96m'
    GREEN = '\\x1b[92m'
    YELLOW = '\\x1b[93m'
    RED = '\\x1b[91m'
    BOLD = '\\x1b[1m'
    RESET = '\\x1b[0m'

WEB_ATTACK_SIGNATURES = [
    (re.compile(r"(\\bunion\\b.*\\bselect\\b|'\\s*or\\s*['\"\\d]|--|\\bselect\\b.*\\bfrom\\b|sleep\\(\\d+\\)|benchmark\\()", re.IGNORECASE), "SQL Injection (SQLi)", "T1190", "CRITICAL"),
    (re.compile(r"(<script\\b|javascript:|onerror\\s*=|onload\\s*=|alert\\(|document\\.cookie)", re.IGNORECASE), "Cross-Site Scripting (XSS)", "T1189", "HIGH"),
    (re.compile(r"(\\.\\./|\\.\\.\\\\|/etc/passwd|/windows/win\\.ini|boot\\.ini)", re.IGNORECASE), "Directory Traversal / LFI", "T1083", "HIGH"),
    (re.compile(r"(cmd\\.exe|/bin/sh|/bin/bash|eval\\(|base64_decode|system\\()", re.IGNORECASE), "Remote Code Execution / Shell", "T1059", "CRITICAL"),
    (re.compile(r"(\\.(env|git|bak|sql|config|yml)|phpinfo\\.php|actuator/)", re.IGNORECASE), "Sensitive File Reconnaissance", "T1595", "MEDIUM")
]

SUSPICIOUS_USER_AGENTS = re.compile(r"(sqlmap|nikto|masscan|gobuster|dirbuster|nmap|acunetix|w3af|zgrab|curl/|python-requests)", re.IGNORECASE)

${logPatternDefinition}

class ThreatDetectionEngine:
    def __init__(self, brute_threshold: int = ${config.bruteForceThreshold}, brute_window: int = ${config.bruteForceWindowSeconds}):
        self.brute_threshold = brute_threshold
        self.brute_window = brute_window
        self.failure_tracker: Dict[str, deque] = defaultdict(deque)
        self.banned_ips: set = set()
        self.alerts: List[Dict[str, Any]] = []
        self.stats = {
            "total_lines_read": 0,
            "parsed_events": 0,
            "total_alerts": 0,
            "ip_counts": defaultdict(int),
            "status_counts": defaultdict(int),
            "mitre_counts": defaultdict(int)
        }

    def trigger_alert(self, severity: str, title: str, ip: str, details: str, mitre_id: str = "T1110"):
        alert_event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "title": title,
            "ip": ip,
            "mitre_id": mitre_id,
            "details": details
        }
        self.alerts.append(alert_event)
        self.stats["total_alerts"] += 1
        self.stats["mitre_counts"][mitre_id] += 1

        color = Colors.RED if severity in ["CRITICAL", "HIGH"] else (Colors.YELLOW if severity == "MEDIUM" else Colors.CYAN)
        print(f"{color}[ALERT: {severity}]{Colors.RESET} [{mitre_id}] {title} from {Colors.BOLD}{ip}{Colors.RESET}")
        print(f"   └── Details: {details}")
        ${needsWebhook ? 'self.dispatch_webhook(alert_event)' : ''}

    ${webhookMethod}

    def check_brute_force(self, ip: str, timestamp_dt: datetime):
        timestamps = self.failure_tracker[ip]
        timestamps.append(timestamp_dt)

        cutoff = timestamp_dt - timedelta(seconds=self.brute_window)
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        if len(timestamps) >= self.brute_threshold:
            if ip not in self.banned_ips:
                self.banned_ips.add(ip)
                self.trigger_alert(
                    severity="CRITICAL",
                    title="Credential Brute-Force Burst Detected",
                    ip=ip,
                    details=f"{len(timestamps)} failed authentication attempts within {self.brute_window}s window.",
                    mitre_id="T1110.001"
                )

    def analyze_event(self, event: Dict[str, Any]):
        self.stats["parsed_events"] += 1
        ip = event.get("ip", "unknown")
        if ip:
            self.stats["ip_counts"][ip] += 1

        ${eventAnalysisBody}

    def export_firewall_rules(self, file_path: str = "banned_ips.sh"):
        if not self.banned_ips:
            return
        ban_type = "${config.autoBanType}"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("#!/usr/bin/env bash\\n# Auto-generated firewall ban script\\n\\n")
            for ip in sorted(self.banned_ips):
                if ban_type == "ufw":
                    f.write(f"ufw insert 1 deny from {ip} comment 'Auto-banned by PySecStudio'\\n")
                elif ban_type == "iptables":
                    f.write(f"iptables -A INPUT -s {ip} -j DROP\\n")
                elif ban_type == "fail2ban":
                    f.write(f"fail2ban-client set sshd banip {ip}\\n")
        print(f"  {Colors.GREEN}[EXPORTED]{Colors.RESET} {len(self.banned_ips)} IPs written to {file_path}")


def stream_log_lines(source: str, mode: str = "file") -> Generator[str, None, None]:
    if mode == "stdin" or source == "-":
        for line in sys.stdin:
            yield line
    elif mode == "tail":
        with open(source, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    else:
        with open(source, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                yield line


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    match = LOG_PATTERN.match(line.strip())
    if match:
        return match.groupdict()
    ${cloudTrailJsonParsing}
    return None


def main():
    parser = argparse.ArgumentParser(description="PySecStudio - Custom Python Log Threat Detection & Parser")
    parser.add_argument("-f", "--file", default="${defaultFilePath}", help="Path to log file (or '-' for stdin)")
    parser.add_argument("-m", "--mode", choices=["file", "stdin", "tail"], default="${config.inputMode === 'tail' ? 'tail' : config.inputMode === 'stdin' ? 'stdin' : 'file'}", help="Read mode")
    parser.add_argument("-o", "--output", default="log_analysis_report.json", help="Report export filename")
    parser.add_argument("--ban-export", action="store_true", default=${config.enableAutoBanExport ? 'True' : 'False'}, help="Export firewall commands for offending IPs")
    args = parser.parse_args()

    print(f"{Colors.CYAN}PySecStudio Threat Parser initialized...{Colors.RESET}")
    print(f"Reading from: {args.file} (mode: {args.mode})\\n")

    engine = ThreatDetectionEngine()

    try:
        for raw_line in stream_log_lines(args.file, args.mode):
            engine.stats["total_lines_read"] += 1
            event = parse_line(raw_line)
            if event:
                engine.analyze_event(event)

    except KeyboardInterrupt:
        print(f"\\n{Colors.YELLOW}[!] Processing halted by user.{Colors.RESET}")
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: File '{args.file}' not found.{Colors.RESET}")
        sys.exit(1)

    print("\\n" + "=" * 65)
    print(f"{Colors.BOLD}LOG THREAT ANALYSIS SUMMARY{Colors.RESET}")
    print(f"Total Lines Processed : {engine.stats['total_lines_read']}")
    print(f"Parsed Security Events: {engine.stats['parsed_events']}")
    print(f"Total Threats Alerted : {engine.stats['total_alerts']}")
    print(f"Banned / Hostile IPs  : {len(engine.banned_ips)}")
    
    if engine.stats["mitre_counts"]:
        print(f"\\n{Colors.HEADER}MITRE ATT&CK Breakdown:{Colors.RESET}")
        for mitre_id, count in engine.stats["mitre_counts"].items():
            print(f"  [{mitre_id}]: {count} occurrences")

    if args.ban_export:
        engine.export_firewall_rules("banned_threat_ips.sh")

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump({
            "summary": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_lines": engine.stats["total_lines_read"],
                "total_alerts": engine.stats["total_alerts"]
            },
            "alerts": engine.alerts,
            "banned_ips": list(engine.banned_ips)
        }, f, indent=2)
    print(f"\\n{Colors.GREEN}[SAVED]{Colors.RESET} Threat intelligence report written to {args.output}")

if __name__ == "__main__":
    main()
`;
}
