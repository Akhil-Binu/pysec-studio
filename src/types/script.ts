export type TargetType = 'single' | 'cidr' | 'url_list' | 'file';
export type PortPreset = 'common' | 'top100' | 'custom' | 'full';
export type ConcurrencyType = 'asyncio' | 'threadpool' | 'multiprocessing';

export interface VulnScanConfig {
  targetType: TargetType;
  targetValue: string;
  portPreset: PortPreset;
  customPorts: string;
  concurrency: ConcurrencyType;
  workers: number;
  timeout: number;
  rateLimitDelay: number;
  userAgent: string;
  enableBannerGrabbing: boolean;
  enableHeaderAudit: boolean;
  enableSslCheck: boolean;
  enableSensitivePaths: boolean;
  enableCorsCheck: boolean;
  enableSubdomainEnum: boolean;
  enableCveCheck: boolean;
  enableSqlInjectionProbe: boolean;
  outputFormats: ('terminal' | 'json' | 'csv' | 'html')[];
  enableWebhook: boolean;
  webhookType: 'discord' | 'slack';
  webhookUrl: string;
  stealthMode: boolean;
  proxyUrl: string;
  scanTitle: string;
}

export type LogType = 'nginx' | 'apache' | 'ssh' | 'windows_sysmon' | 'cloudtrail' | 'custom';
export type LogInputMode = 'file' | 'stdin' | 'tail' | 'syslog_udp';
export type LogStreamMode = 'streaming' | 'batch' | 'multiprocess';
export type AutoBanType = 'ufw' | 'iptables' | 'fail2ban';

export interface LogParserConfig {
  logType: LogType;
  inputMode: LogInputMode;
  filePath: string;
  streamMode: LogStreamMode;
  enableBruteForceDetection: boolean;
  bruteForceThreshold: number;
  bruteForceWindowSeconds: number;
  enableWebAttackDetection: boolean;
  enableScannerDetection: boolean;
  enableMitreMapping: boolean;
  enableGeoLookup: boolean;
  enableAutoBanExport: boolean;
  autoBanType: AutoBanType;
  outputFormat: 'rich_console' | 'json' | 'cef' | 'csv';
  enableWebhookAlert: boolean;
  webhookType: 'discord' | 'slack';
  webhookUrl: string;
  alertMinSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  customRegex: string;
  customFields: string[];
}

export interface ScriptTemplate {
  id: string;
  title: string;
  category: 'vuln_scanning' | 'log_parsing' | 'hybrid';
  description: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  tags: string[];
  dependencies: string[];
  pythonCode: string;
  cliExample: string;
  mitreTags?: string[];
}

export interface SimulationResult {
  stdout: string[];
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  durationMs: number;
  analyzedCount: number;
}
