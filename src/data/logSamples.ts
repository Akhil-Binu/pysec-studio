export interface LogSampleItem {
  id: string;
  name: string;
  type: 'nginx' | 'apache' | 'ssh' | 'cloudtrail' | 'windows';
  description: string;
  content: string;
  defaultRegex: string;
}

export const LOG_SAMPLES: LogSampleItem[] = [
  {
    id: 'nginx-attacks',
    name: 'Nginx Access Logs (SQLi, XSS, Path Traversal & Scanners)',
    type: 'nginx',
    description: 'Realistic web server traffic containing normal browsing interleaved with SQL Injection, XSS, and automated directory scanners.',
    defaultRegex: '^([\\d\\.]+)\\s+-\\s+\\S+\\s+\\[([^\\]]+)\\]\\s+"([A-Z]+)\\s+(\\S+)\\s+\\S+"\\s+(\\d{3})\\s+(\\S+)(?:\\s+"([^"]*)"\\s+"([^"]*)")?',
    content: `192.168.1.105 - - [17/Nov/2026:14:10:01 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.105 - - [17/Nov/2026:14:10:03 +0000] "GET /assets/main.css HTTP/1.1" 200 1205 "http://example.com/" "Mozilla/5.0"
203.0.113.19 - - [17/Nov/2026:14:10:15 +0000] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password_hash%20FROM%20users-- HTTP/1.1" 200 8920 "-" "Mozilla/5.0"
45.33.32.156 - - [17/Nov/2026:14:10:22 +0000] "GET /api/v1/users?order=id HTTP/1.1" 200 412 "-" "sqlmap/1.6.4#stable (https://sqlmap.org)"
185.220.101.5 - - [17/Nov/2026:14:10:30 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 404 162 "-" "curl/7.88.1"
198.51.100.88 - - [17/Nov/2026:14:10:45 +0000] "GET /search?q=%3Cscript%3Ealert('xss')%3C/script%3E HTTP/1.1" 200 3410 "-" "Mozilla/5.0"
198.51.100.42 - - [17/Nov/2026:14:11:01 +0000] "POST /api/auth/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
198.51.100.42 - - [17/Nov/2026:14:11:03 +0000] "POST /api/auth/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
198.51.100.42 - - [17/Nov/2026:14:11:05 +0000] "POST /api/auth/login HTTP/1.1" 401 89 "-" "python-requests/2.31.0"
91.240.118.77 - - [17/Nov/2026:14:11:15 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Go-http-client/1.1"
91.240.118.77 - - [17/Nov/2026:14:11:16 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "Go-http-client/1.1"
10.0.0.12 - - [17/Nov/2026:14:11:25 +0000] "GET /dashboard HTTP/1.1" 200 5120 "http://internal.corp/" "Mozilla/5.0"`
  },
  {
    id: 'ssh-auth-bruteforce',
    name: 'Linux SSH Auth.log (/var/log/auth.log)',
    type: 'ssh',
    description: 'Linux authentication logs containing brute-force dictionary attacks against SSH alongside normal sysadmin logins.',
    defaultRegex: '^([A-Z][a-z]{2}\\s+\\d+\\s+[\\d:]+)\\s+(\\S+)\\s+(sshd\\[\\d+\\]):\\s+(.*)',
    content: `Nov 17 14:10:01 web-prod-01 sshd[2210]: Accepted publickey for devops from 10.0.0.12 port 52140 ssh2
Nov 17 14:10:05 web-prod-01 sshd[2215]: Failed password for invalid user admin from 198.51.100.42 port 48122 ssh2
Nov 17 14:10:08 web-prod-01 sshd[2216]: Failed password for invalid user root from 198.51.100.42 port 48124 ssh2
Nov 17 14:10:10 web-prod-01 sshd[2218]: Failed password for invalid user test from 198.51.100.42 port 48126 ssh2
Nov 17 14:10:12 web-prod-01 sshd[2220]: Failed password for invalid user oracle from 198.51.100.42 port 48128 ssh2
Nov 17 14:10:15 web-prod-01 sshd[2222]: Failed password for invalid user deploy from 198.51.100.42 port 48130 ssh2
Nov 17 14:10:18 web-prod-01 sshd[2225]: Failed password for invalid user support from 198.51.100.42 port 48132 ssh2
Nov 17 14:10:25 web-prod-01 sshd[2230]: Accepted password for root from 10.0.0.99 port 59120 ssh2`
  },
  {
    id: 'cloudtrail-json',
    name: 'AWS CloudTrail JSON Security Events',
    type: 'cloudtrail',
    description: 'CloudTrail management events with IAM privilege escalations, root account activity, and AccessDenied anomalies.',
    defaultRegex: '^\\{"eventTime":\\s*"([^"]+)",\\s*"eventName":\\s*"([^"]+)"',
    content: `{"eventTime": "2026-11-17T14:00:12Z", "eventName": "ConsoleLogin", "userIdentity": {"type": "Root"}, "sourceIPAddress": "198.51.100.99", "responseElements": {"ConsoleLogin": "Success"}}
{"eventTime": "2026-11-17T14:02:45Z", "eventName": "DescribeInstances", "userIdentity": {"userName": "developer_bob"}, "sourceIPAddress": "10.0.1.5"}
{"eventTime": "2026-11-17T14:05:10Z", "eventName": "PutBucketPolicy", "userIdentity": {"userName": "intern_alice"}, "sourceIPAddress": "54.210.12.33", "errorCode": "AccessDenied", "errorMessage": "User is not authorized to perform s3:PutBucketPolicy on resource arn:aws:s3:::prod-customer-pii"}
{"eventTime": "2026-11-17T14:08:20Z", "eventName": "AttachUserPolicy", "userIdentity": {"userName": "compromised_service_account"}, "sourceIPAddress": "185.220.101.5", "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}}`
  }
];
