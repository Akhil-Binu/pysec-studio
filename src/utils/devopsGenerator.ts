import { VulnScanConfig, LogParserConfig } from '../types/script';

export function generateRequirements(category: 'vuln_scanning' | 'log_parsing', config: any): string {
  if (category === 'vuln_scanning') {
    const lines = [
      '# PySecStudio - Python Vulnerability Scanner Dependencies',
      '# Python 3.9+',
      'urllib3>=2.2.0',
      'requests>=2.31.0',
    ];
    if (config.concurrency === 'asyncio') {
      lines.push('aiohttp>=3.9.0', 'asyncio>=3.4.3');
    }
    if (config.enableSslCheck) {
      lines.push('cryptography>=42.0.0', 'pyOpenSSL>=24.0.0');
    }
    if (config.enableSubdomainEnum) {
      lines.push('dnspython>=2.6.0');
    }
    lines.push('rich>=13.7.0  # Optional for beautiful console formatting');
    lines.push('pydantic>=2.6.0  # Optional for strict finding validation');
    return lines.join('\n');
  } else {
    return [
      '# PySecStudio - Python Log Threat Parser Dependencies',
      '# Python 3.9+',
      'rich>=13.7.0  # Terminal visual tables and progress bars',
      'pydantic>=2.6.0  # Data models and normalization',
      'python-dateutil>=2.9.0  # Flexible timestamp parsing',
      '# Optional for SIEM integrations:',
      'requests>=2.31.0  # Webhook and REST API dispatch',
      '# Optional for EVTX Windows event logs:',
      '# python-evtx>=0.7.4',
    ].join('\n');
  }
}

export function generateDockerfile(category: 'vuln_scanning' | 'log_parsing'): string {
  const scriptName = category === 'vuln_scanning' ? 'scanner.py' : 'parser.py';
  return `# Containerized DevSecOps Runtime
FROM python:3.12-alpine AS builder

WORKDIR /app

# Install security certificates & build dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# --- Final Production Stage ---
FROM python:3.12-alpine

WORKDIR /app

# Create non-privileged service user for defense-in-depth
RUN addgroup -S secops && adduser -S secops -G secops

COPY --from=builder /root/.local /home/secops/.local
COPY ${scriptName} /app/

# Set ownership and secure permissions
RUN chown -R secops:secops /app
USER secops

ENV PATH=/home/secops/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "${scriptName}"]
CMD ["--help"]
`;
}

export function generateGitHubAction(category: 'vuln_scanning' | 'log_parsing'): string {
  if (category === 'vuln_scanning') {
    return `name: Automated Vulnerability & Security Audit

on:
  schedule:
    # Run daily at 02:00 AM UTC
    - cron: '0 2 * * *'
  workflow_dispatch:
    inputs:
      target:
        description: 'Target IP or Hostname to scan'
        required: true
        default: 'staging.internal.corp'

jobs:
  security-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python 3.12
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Execute PySecStudio Scanner
        env:
          DISCORD_WEBHOOK_URL: \${{ secrets.SEC_DISCORD_WEBHOOK }}
        run: |
          python scanner.py --target "\${{ github.event.inputs.target || 'staging.internal.corp' }}" --output audit_report

      - name: Archive Security Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: |
            audit_report.json
            audit_report.csv
`;
  } else {
    return `name: Threat Log Parsing & SIEM Alerting Pipeline

on:
  schedule:
    - cron: '*/30 * * * *' # Every 30 minutes
  workflow_dispatch:

jobs:
  analyze-access-logs:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Run Forensic Log Threat Parser
        env:
          SLACK_WEBHOOK_URL: \${{ secrets.SLACK_ALERT_WEBHOOK }}
        run: |
          python parser.py --file /var/log/nginx/access.log --ban-export --output threat_summary.json

      - name: Upload Threat Intelligence
        uses: actions/upload-artifact@v4
        with:
          name: threat-intelligence-report
          path: threat_summary.json
`;
  }
}

export function generateSystemdService(category: 'vuln_scanning' | 'log_parsing'): string {
  const serviceName = category === 'vuln_scanning' ? 'vuln-scanner' : 'log-threat-parser';
  const scriptName = category === 'vuln_scanning' ? 'scanner.py' : 'parser.py';
  return `[Unit]
Description=PySecStudio Daemon - Automated ${category === 'vuln_scanning' ? 'Vulnerability Scanner' : 'Log Threat Parser'}
After=network.target

[Service]
Type=simple
User=secops
WorkingDirectory=/opt/pysecstudio
ExecStart=/usr/bin/python3 /opt/pysecstudio/${scriptName} ${category === 'log_parsing' ? '--mode tail --ban-export' : '--target prod.internal.corp'}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`;
}
