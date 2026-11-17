export interface SecurityLibDoc {
  name: string;
  category: string;
  description: string;
  installation: string;
  useCase: string;
  snippet: string;
}

export const SECURITY_LIBRARIES: SecurityLibDoc[] = [
  {
    name: 'asyncio & socket',
    category: 'Network Reconnaissance',
    description: 'Native asynchronous I/O and low-level TCP/UDP socket management. Capable of scanning thousands of ports per second without threads.',
    installation: 'Built into Python 3.8+ (No pip needed)',
    useCase: 'High-concurrency port scanning, banner grabbing, raw packet probing.',
    snippet: `import asyncio

async def test_port(host, port):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=1.5
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False`
  },
  {
    name: 'requests / httpx',
    category: 'HTTP & Web Exploitation',
    description: 'Human-friendly HTTP clients supporting connection pooling, SSL verification, cookie jars, and custom headers/proxies.',
    installation: 'pip install requests httpx',
    useCase: 'Web vulnerability scanning, API fuzzing, CORS verification, header inspection.',
    snippet: `import requests

resp = requests.get(
    "https://api.internal/v1",
    headers={"User-Agent": "PySecStudio/1.0", "Origin": "https://evil.com"},
    timeout=5.0,
    allow_redirects=False
)
if resp.headers.get("Access-Control-Allow-Origin") == "*":
    print("Wildcard CORS detected!")`
  },
  {
    name: 're & collections.deque',
    category: 'Log Parsing & SIEM',
    description: 'Compiled regular expressions combined with double-ended queues to implement sliding-window brute force and pattern detection.',
    installation: 'Built into Python standard library',
    useCase: 'High-throughput log stream threat detection with O(1) memory overhead.',
    snippet: `from collections import defaultdict, deque
import datetime

# Sliding window: track timestamps per IP
tracker = defaultdict(deque)

def is_bruteforce(ip, dt, threshold=5, window_sec=60):
    timestamps = tracker[ip]
    timestamps.append(dt)
    cutoff = dt - datetime.timedelta(seconds=window_sec)
    while timestamps and timestamps[0] < cutoff:
        timestamps.popleft()
    return len(timestamps) >= threshold`
  },
  {
    name: 'cryptography & ssl',
    category: 'Cryptography & TLS',
    description: 'Industry-standard Python cryptography package for inspecting X.509 certificates, cipher suites, public keys, and hashing algorithms.',
    installation: 'pip install cryptography',
    useCase: 'SSL certificate expiration auditing, deprecated TLS 1.0/1.1 detection.',
    snippet: `import ssl, socket
from datetime import datetime

ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.socket(), server_hostname="example.com") as s:
    s.connect(("example.com", 443))
    cert = s.getpeercert()
    expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    print(f"Valid until: {expiry}")`
  },
  {
    name: 'rich',
    category: 'Console UI & Terminal Output',
    description: 'Rich terminal formatting with colorful tables, progress bars, Markdown rendering, and syntax highlighting in Python.',
    installation: 'pip install rich',
    useCase: 'Interactive vulnerability reports and real-time SIEM alerts in the CLI.',
    snippet: `from rich.console import Console
from rich.table import Table

console = Console()
table = Table(title="Vulnerability Findings")
table.add_column("Severity", style="red bold")
table.add_column("Target", style="cyan")
table.add_column("Description", style="white")

table.add_row("CRITICAL", "192.168.1.5", "Exposed .env containing AWS keys")
console.print(table)`
  }
];

export const SCANNING_RULES_AND_ETHICS = [
  {
    title: 'Explicit Authorization Required',
    desc: 'Only scan hosts, IP addresses, or networks that you own or have explicit, written legal authorization (Rules of Engagement) to test.'
  },
  {
    title: 'Rate-Limiting & Jitter',
    desc: 'Always introduce slight delays or jitter between requests to avoid causing Denial of Service (DoS) or overwhelming production services.'
  },
  {
    title: 'Non-Destructive Payloads',
    desc: 'When testing SQLi or XSS, use read-only non-destructive heuristics (e.g. harmless mathematical conditions or unique probe strings) rather than DROP or UPDATE.'
  },
  {
    title: 'Responsible Disclosure',
    desc: 'If you discover sensitive data or severe vulnerabilities, immediately notify the system administrators or follow coordinated vulnerability disclosure guidelines.'
  }
];
