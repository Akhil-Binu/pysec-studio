import React from 'react';
import { VulnScanConfig, PortPreset, ConcurrencyType } from '../types/script';
import { 
  ShieldCheck, 
  Globe, 
  Terminal, 
  Zap, 
  Lock, 
  FileSearch, 
  Layers, 
  Sliders, 
  Bell, 
  Radio, 
  CheckCircle2, 
  RotateCcw,
  Sparkles,
  Server
} from 'lucide-react';

interface VulnScannerBuilderProps {
  config: VulnScanConfig;
  onChange: (newConfig: VulnScanConfig) => void;
  onReset: () => void;
}

export const VulnScannerBuilder: React.FC<VulnScannerBuilderProps> = ({
  config,
  onChange,
  onReset
}) => {
  const update = (patch: Partial<VulnScanConfig>) => {
    onChange({ ...config, ...patch });
  };

  const applyPreset = (presetName: string) => {
    switch (presetName) {
      case 'web_auditor':
        update({
          targetValue: 'https://staging.internal.corp',
          portPreset: 'common',
          concurrency: 'asyncio',
          workers: 30,
          enableBannerGrabbing: true,
          enableHeaderAudit: true,
          enableSslCheck: true,
          enableSensitivePaths: true,
          enableCorsCheck: true,
          enableSqlInjectionProbe: false,
          enableSubdomainEnum: false
        });
        break;
      case 'port_fingerprint':
        update({
          targetValue: '192.168.1.1',
          portPreset: 'top100',
          concurrency: 'asyncio',
          workers: 100,
          enableBannerGrabbing: true,
          enableHeaderAudit: false,
          enableSslCheck: false,
          enableSensitivePaths: false,
          enableCorsCheck: false,
          enableSqlInjectionProbe: false,
          enableSubdomainEnum: false
        });
        break;
      case 'full_pentest':
        update({
          targetValue: 'app.example.com',
          portPreset: 'top100',
          concurrency: 'asyncio',
          workers: 50,
          enableBannerGrabbing: true,
          enableHeaderAudit: true,
          enableSslCheck: true,
          enableSensitivePaths: true,
          enableCorsCheck: true,
          enableSqlInjectionProbe: true,
          enableSubdomainEnum: true
        });
        break;
      case 'stealth_recon':
        update({
          targetValue: 'target-corp.com',
          portPreset: 'common',
          concurrency: 'threadpool',
          workers: 5,
          rateLimitDelay: 0.5,
          timeout: 4.0,
          stealthMode: true,
          enableBannerGrabbing: true,
          enableHeaderAudit: true,
          enableSslCheck: true,
          enableSensitivePaths: false,
          enableCorsCheck: false,
          enableSqlInjectionProbe: false,
          enableSubdomainEnum: true
        });
        break;
    }
  };

  return (
    <div className="space-y-6 text-sm text-slate-300">
      {/* Presets Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-sm">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Quick Start Presets</span>
          </div>
          <button
            onClick={onReset}
            className="flex items-center space-x-1 text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset Defaults</span>
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          <button
            onClick={() => applyPreset('web_auditor')}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/10 hover:border-cyan-500/40 border border-slate-700/60 text-xs font-medium text-slate-200 text-left transition-all"
          >
            <div className="font-semibold text-cyan-300">Web App Auditor</div>
            <div className="text-[11px] text-slate-400">Headers, SSL, CORS & Leaks</div>
          </button>

          <button
            onClick={() => applyPreset('port_fingerprint')}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/10 hover:border-cyan-500/40 border border-slate-700/60 text-xs font-medium text-slate-200 text-left transition-all"
          >
            <div className="font-semibold text-emerald-300">Port Fingerprinter</div>
            <div className="text-[11px] text-slate-400">High-speed AsyncIO sockets</div>
          </button>

          <button
            onClick={() => applyPreset('full_pentest')}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/10 hover:border-cyan-500/40 border border-slate-700/60 text-xs font-medium text-slate-200 text-left transition-all"
          >
            <div className="font-semibold text-purple-300">Full Deep Pentest</div>
            <div className="text-[11px] text-slate-400">All audit modules active</div>
          </button>

          <button
            onClick={() => applyPreset('stealth_recon')}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/10 hover:border-cyan-500/40 border border-slate-700/60 text-xs font-medium text-slate-200 text-left transition-all"
          >
            <div className="font-semibold text-amber-300">Stealth Recon</div>
            <div className="text-[11px] text-slate-400">Delays & WAF evasion</div>
          </button>
        </div>
      </div>

      {/* Target Scope Configuration */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
          <Globe className="w-3.5 h-3.5" />
          <span>1. Target Scope & Ports</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2 space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Target Hostname or IP</label>
            <div className="relative">
              <input
                type="text"
                value={config.targetValue}
                onChange={(e) => update({ targetValue: e.target.value })}
                placeholder="e.g. scanme.nmap.org or 192.168.1.100"
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-slate-100 font-mono text-xs transition-colors"
              />
            </div>
            <p className="text-[11px] text-slate-500">Supports Domain, Single IPv4/IPv6, or URL hostname.</p>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Port Range Preset</label>
            <select
              value={config.portPreset}
              onChange={(e) => update({ portPreset: e.target.value as PortPreset })}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-slate-100 text-xs transition-colors"
            >
              <option value="common">Common Top 20 Ports (Fast)</option>
              <option value="top100">Top 100 Services (Standard)</option>
              <option value="full">Full Port Sweep (1-65535)</option>
              <option value="custom">Custom Ports Specification</option>
            </select>
            <p className="text-[11px] text-slate-500">
              {config.portPreset === 'common' && '80, 443, 22, 21, 3306, 8080, 8443, etc.'}
              {config.portPreset === 'top100' && 'Top 100 registered IANA services'}
              {config.portPreset === 'full' && 'Scans ports 1 through 65535'}
              {config.portPreset === 'custom' && 'Specify custom comma-separated list'}
            </p>
          </div>
        </div>

        {config.portPreset === 'custom' && (
          <div className="space-y-1.5 pt-1">
            <label className="text-xs font-medium text-slate-300">Custom Ports String</label>
            <input
              type="text"
              value={config.customPorts}
              onChange={(e) => update({ customPorts: e.target.value })}
              placeholder="e.g. 80,443,8080,8443,3000-3010,9000"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 focus:border-cyan-500 text-slate-100 font-mono text-xs"
            />
          </div>
        )}
      </div>

      {/* Concurrency & Engine Settings */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
          <Zap className="w-3.5 h-3.5" />
          <span>2. Concurrency & Performance Engine</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Execution Model</label>
            <select
              value={config.concurrency}
              onChange={(e) => update({ concurrency: e.target.value as ConcurrencyType })}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 focus:border-cyan-500 text-slate-100 text-xs"
            >
              <option value="asyncio">AsyncIO Coroutines (Highest Speed)</option>
              <option value="threadpool">ThreadPoolExecutor (Multi-Threaded)</option>
              <option value="multiprocessing">Multiprocessing (Multi-Core CPU)</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <label className="text-xs font-medium text-slate-300">Concurrency Workers</label>
              <span className="font-mono text-xs text-cyan-400">{config.workers} workers</span>
            </div>
            <input
              type="range"
              min="1"
              max="200"
              value={config.workers}
              onChange={(e) => update({ workers: parseInt(e.target.value) })}
              className="w-full accent-cyan-500 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-500">
              <span>1 (Serial)</span>
              <span>50 (Balanced)</span>
              <span>200 (Max Async)</span>
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <label className="text-xs font-medium text-slate-300">Socket Timeout</label>
              <span className="font-mono text-xs text-cyan-400">{config.timeout}s</span>
            </div>
            <input
              type="range"
              min="0.5"
              max="10"
              step="0.5"
              value={config.timeout}
              onChange={(e) => update({ timeout: parseFloat(e.target.value) })}
              className="w-full accent-cyan-500 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-500">
              <span>0.5s (LAN)</span>
              <span>2.0s (WAN)</span>
              <span>10s (Slow)</span>
            </div>
          </div>
        </div>

        {/* Rate-limiting & Stealth */}
        <div className="pt-2 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <label className="text-xs font-medium text-slate-300">Rate-Limit Jitter Delay (s)</label>
              <span className="font-mono text-xs text-cyan-400">{config.rateLimitDelay}s</span>
            </div>
            <input
              type="range"
              min="0"
              max="2"
              step="0.05"
              value={config.rateLimitDelay}
              onChange={(e) => update({ rateLimitDelay: parseFloat(e.target.value) })}
              className="w-full accent-cyan-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">Adds interval delay between requests to avoid triggering IDS/WAF threshold rate blocks.</p>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Custom User-Agent</label>
            <input
              type="text"
              value={config.userAgent}
              onChange={(e) => update({ userAgent: e.target.value })}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 font-mono text-xs"
            />
          </div>
        </div>
      </div>

      {/* Vulnerability Scanning Modules (Toggles) */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>3. Vulnerability Audit Modules</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {/* Module: Banner Grab */}
          <div 
            onClick={() => update({ enableBannerGrabbing: !config.enableBannerGrabbing })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableBannerGrabbing
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <Server className={`w-4 h-4 ${config.enableBannerGrabbing ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">TCP Port & Banner Grab</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableBannerGrabbing}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Extracts raw daemon banner strings (SSH, Apache, MySQL, Nginx versions).
            </p>
          </div>

          {/* Module: HTTP Headers */}
          <div 
            onClick={() => update({ enableHeaderAudit: !config.enableHeaderAudit })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableHeaderAudit
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <Globe className={`w-4 h-4 ${config.enableHeaderAudit ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">HTTP Security Headers Audit</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableHeaderAudit}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Checks HSTS, CSP, X-Frame-Options, X-Content-Type, and Server disclosure.
            </p>
          </div>

          {/* Module: SSL/TLS Check */}
          <div 
            onClick={() => update({ enableSslCheck: !config.enableSslCheck })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableSslCheck
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <Lock className={`w-4 h-4 ${config.enableSslCheck ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">SSL/TLS & Cipher Evaluator</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableSslCheck}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Validates certificate expiry days, self-signed warnings, and TLS 1.0/1.1 deprecation.
            </p>
          </div>

          {/* Module: Sensitive Paths */}
          <div 
            onClick={() => update({ enableSensitivePaths: !config.enableSensitivePaths })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableSensitivePaths
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <FileSearch className={`w-4 h-4 ${config.enableSensitivePaths ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">Sensitive File & Config Leaks</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableSensitivePaths}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Fuzzes for exposed .env, .git/HEAD, wp-config backups, actuator, swagger docs.
            </p>
          </div>

          {/* Module: CORS Audit */}
          <div 
            onClick={() => update({ enableCorsCheck: !config.enableCorsCheck })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableCorsCheck
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <Radio className={`w-4 h-4 ${config.enableCorsCheck ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">CORS Misconfiguration Tester</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableCorsCheck}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Detects arbitrary origin reflection with credentials enabled (ACAO + ACAC).
            </p>
          </div>

          {/* Module: SQLi / XSS heuristic */}
          <div 
            onClick={() => update({ enableSqlInjectionProbe: !config.enableSqlInjectionProbe })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableSqlInjectionProbe
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <Layers className={`w-4 h-4 ${config.enableSqlInjectionProbe ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">Heuristic SQLi / XSS Probes</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableSqlInjectionProbe}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Tests non-destructive reflection indicators and input sanitization response checks.
            </p>
          </div>
        </div>
      </div>

      {/* Output & Webhook Integration */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
          <Bell className="w-3.5 h-3.5" />
          <span>4. Artifact Export & Alerts</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-medium text-slate-300">Generated Report Artifacts</label>
            <div className="flex flex-wrap gap-2">
              <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-200 text-xs border border-slate-700 flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                <span>JSON Report</span>
              </span>
              <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-200 text-xs border border-slate-700 flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                <span>CSV Spreadsheet</span>
              </span>
              <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-200 text-xs border border-slate-700 flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                <span>ANSI Terminal Log</span>
              </span>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-slate-300">Push Notifications (Webhook)</label>
              <label className="flex items-center space-x-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.enableWebhook}
                  onChange={(e) => update({ enableWebhook: e.target.checked })}
                  className="accent-cyan-500 rounded"
                />
                <span className="text-slate-400">Enable</span>
              </label>
            </div>
            {config.enableWebhook && (
              <div className="space-y-2 pt-1">
                <input
                  type="text"
                  value={config.webhookUrl}
                  onChange={(e) => update({ webhookUrl: e.target.value })}
                  placeholder="https://discord.com/api/webhooks/..."
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-200 font-mono text-xs"
                />
                <p className="text-[11px] text-slate-500">Sends instant alert on Critical or High findings.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
