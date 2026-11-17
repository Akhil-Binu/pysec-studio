import React from 'react';
import { LogParserConfig, LogType, LogInputMode, AutoBanType } from '../types/script';
import { 
  FileText, 
  Terminal, 
  ShieldAlert, 
  Sliders, 
  Zap, 
  Flame, 
  Ban, 
  Bell, 
  RotateCcw, 
  Sparkles, 
  Activity, 
  Cpu, 
  Crosshair 
} from 'lucide-react';

interface LogParserBuilderProps {
  config: LogParserConfig;
  onChange: (newConfig: LogParserConfig) => void;
  onReset: () => void;
}

export const LogParserBuilder: React.FC<LogParserBuilderProps> = ({
  config,
  onChange,
  onReset
}) => {
  const update = (patch: Partial<LogParserConfig>) => {
    onChange({ ...config, ...patch });
  };

  const applyPreset = (presetName: string) => {
    switch (presetName) {
      case 'web_hunter':
        update({
          logType: 'nginx',
          inputMode: 'file',
          filePath: '/var/log/nginx/access.log',
          enableBruteForceDetection: true,
          bruteForceThreshold: 10,
          bruteForceWindowSeconds: 60,
          enableWebAttackDetection: true,
          enableScannerDetection: true,
          enableMitreMapping: true,
          enableAutoBanExport: true,
          autoBanType: 'ufw',
          outputFormat: 'rich_console'
        });
        break;
      case 'ssh_defense':
        update({
          logType: 'ssh',
          inputMode: 'file',
          filePath: '/var/log/auth.log',
          enableBruteForceDetection: true,
          bruteForceThreshold: 5,
          bruteForceWindowSeconds: 45,
          enableWebAttackDetection: false,
          enableScannerDetection: false,
          enableMitreMapping: true,
          enableAutoBanExport: true,
          autoBanType: 'iptables',
          outputFormat: 'rich_console'
        });
        break;
      case 'realtime_daemon':
        update({
          logType: 'nginx',
          inputMode: 'tail',
          filePath: '/var/log/nginx/access.log',
          enableBruteForceDetection: true,
          enableWebAttackDetection: true,
          enableScannerDetection: true,
          enableWebhookAlert: true,
          enableAutoBanExport: true,
          outputFormat: 'json'
        });
        break;
      case 'cloudtrail_audit':
        update({
          logType: 'cloudtrail',
          inputMode: 'file',
          filePath: './cloudtrail_audit.json',
          enableBruteForceDetection: false,
          enableWebAttackDetection: false,
          enableScannerDetection: false,
          enableMitreMapping: true,
          enableAutoBanExport: false,
          outputFormat: 'rich_console'
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
            <span>Pre-Configured Threat Templates</span>
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
            onClick={() => applyPreset('web_hunter')}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/10 hover:border-cyan-500/40 border border-slate-700/60 text-xs font-medium text-slate-200 text-left transition-all"
          >
            <div className="font-semibold text-cyan-300">Nginx / Apache Hunter</div>
            <div className="text-[11px] text-slate-400">SQLi, XSS, Scanners & UFW ban</div>
          </button>

          <button
            onClick={() => applyPreset('ssh_defense')}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/10 hover:border-cyan-500/40 border border-slate-700/60 text-xs font-medium text-slate-200 text-left transition-all"
          >
            <div className="font-semibold text-emerald-300">SSH Bastion Defense</div>
            <div className="text-[11px] text-slate-400">Brute-force auto-ban (iptables)</div>
          </button>

          <button
            onClick={() => applyPreset('realtime_daemon')}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/10 hover:border-cyan-500/40 border border-slate-700/60 text-xs font-medium text-slate-200 text-left transition-all"
          >
            <div className="font-semibold text-purple-300">Live `tail -f` Daemon</div>
            <div className="text-[11px] text-slate-400">Zero-latency webhook alerts</div>
          </button>

          <button
            onClick={() => applyPreset('cloudtrail_audit')}
            className="px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-cyan-500/10 hover:border-cyan-500/40 border border-slate-700/60 text-xs font-medium text-slate-200 text-left transition-all"
          >
            <div className="font-semibold text-amber-300">AWS CloudTrail Audit</div>
            <div className="text-[11px] text-slate-400">IAM privilege escalation hunter</div>
          </button>
        </div>
      </div>

      {/* Log Source & Ingestion Mode */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
          <FileText className="w-3.5 h-3.5" />
          <span>1. Log Source & Ingestion Engine</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Target Log Format</label>
            <select
              value={config.logType}
              onChange={(e) => update({ logType: e.target.value as LogType })}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 focus:border-cyan-500 text-slate-100 text-xs"
            >
              <option value="nginx">Nginx Access Log (Combined Format)</option>
              <option value="apache">Apache Access Log (CLF)</option>
              <option value="ssh">Linux SSH Auth Log (/var/log/auth.log)</option>
              <option value="cloudtrail">AWS CloudTrail JSON Event Trail</option>
              <option value="windows_sysmon">Windows Sysmon / Security EVTX</option>
              <option value="custom">Custom Regex Pattern</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Ingestion Mode</label>
            <select
              value={config.inputMode}
              onChange={(e) => update({ inputMode: e.target.value as LogInputMode })}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 focus:border-cyan-500 text-slate-100 text-xs"
            >
              <option value="file">Batch Static File (Generator Streaming)</option>
              <option value="tail">Live File Watcher (tail -f polling)</option>
              <option value="stdin">UNIX Pipeline (STDIN stream)</option>
              <option value="syslog_udp">Syslog UDP Server (Port 514)</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Default File Path</label>
            <input
              type="text"
              value={config.filePath}
              onChange={(e) => update({ filePath: e.target.value })}
              placeholder="/var/log/nginx/access.log"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 font-mono text-xs"
            />
          </div>
        </div>

        {/* Streaming memory advantage info card */}
        <div className="p-2.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 text-xs text-cyan-300 flex items-center space-x-2">
          <Cpu className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span>
            <strong>O(1) Streaming Architecture:</strong> The generated script yields line-by-line generators. It will process 50 GB log files using less than 15 MB of RAM!
          </span>
        </div>
      </div>

      {/* Threat Detection Engine & Behavioral Heuristics */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
          <Crosshair className="w-3.5 h-3.5" />
          <span>2. Threat Rules & Behavioral Heuristics</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {/* Brute Force Module */}
          <div 
            onClick={() => update({ enableBruteForceDetection: !config.enableBruteForceDetection })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableBruteForceDetection
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <Flame className={`w-4 h-4 ${config.enableBruteForceDetection ? 'text-rose-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">Sliding-Window Brute-Force Hunter</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableBruteForceDetection}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Maintains rolling timestamp queues to flag IP credential stuffing bursts.
            </p>
          </div>

          {/* Web Attack Signatures */}
          <div 
            onClick={() => update({ enableWebAttackDetection: !config.enableWebAttackDetection })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableWebAttackDetection
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <ShieldAlert className={`w-4 h-4 ${config.enableWebAttackDetection ? 'text-amber-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">Web Exploit Signatures (SQLi/XSS/LFI)</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableWebAttackDetection}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Catches UNION SELECT, &lt;script&gt;, ../../../../etc/passwd, and cmd.exe webshells.
            </p>
          </div>

          {/* Scanner Fingerprints */}
          <div 
            onClick={() => update({ enableScannerDetection: !config.enableScannerDetection })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableScannerDetection
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <Activity className={`w-4 h-4 ${config.enableScannerDetection ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">Automated Scanner Fingerprints</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableScannerDetection}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Flags sqlmap, nikto, masscan, gobuster, nmap, and headless bot user-agents.
            </p>
          </div>

          {/* MITRE ATT&CK Mapping */}
          <div 
            onClick={() => update({ enableMitreMapping: !config.enableMitreMapping })}
            className={`p-3 rounded-xl border cursor-pointer transition-all ${
              config.enableMitreMapping
                ? 'bg-cyan-950/20 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2">
                <Zap className={`w-4 h-4 ${config.enableMitreMapping ? 'text-purple-400' : 'text-slate-500'}`} />
                <span className="font-semibold text-xs text-slate-200">MITRE ATT&CK Enterprise Mapping</span>
              </div>
              <input
                type="checkbox"
                checked={config.enableMitreMapping}
                onChange={() => {}}
                className="accent-cyan-500 rounded"
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Tags every incident with T1110, T1190, T1059, T1083 for SIEM correlation.
            </p>
          </div>
        </div>

        {/* Sliding Window Parameters */}
        {config.enableBruteForceDetection && (
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-300">Failure Threshold Count</span>
                <span className="font-mono text-cyan-400 font-semibold">{config.bruteForceThreshold} attempts</span>
              </div>
              <input
                type="range"
                min="3"
                max="50"
                value={config.bruteForceThreshold}
                onChange={(e) => update({ bruteForceThreshold: parseInt(e.target.value) })}
                className="w-full accent-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Flags IP once failed auth exceeds this count</span>
            </div>

            <div className="space-y-1">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-300">Sliding Time Window</span>
                <span className="font-mono text-cyan-400 font-semibold">{config.bruteForceWindowSeconds} seconds</span>
              </div>
              <input
                type="range"
                min="10"
                max="300"
                step="5"
                value={config.bruteForceWindowSeconds}
                onChange={(e) => update({ bruteForceWindowSeconds: parseInt(e.target.value) })}
                className="w-full accent-cyan-500"
              />
              <span className="text-[10px] text-slate-500">Rolling window span for counting failures</span>
            </div>
          </div>
        )}
      </div>

      {/* Mitigation & Automated Response */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
          <Ban className="w-3.5 h-3.5" />
          <span>3. Automated Firewall Mitigation & Output</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-200">Auto-Ban Firewall Script Export</span>
              <input
                type="checkbox"
                checked={config.enableAutoBanExport}
                onChange={(e) => update({ enableAutoBanExport: e.target.checked })}
                className="accent-cyan-500 rounded"
              />
            </div>
            {config.enableAutoBanExport && (
              <div className="space-y-2">
                <label className="text-[11px] text-slate-400">Firewall Utility Format</label>
                <div className="flex space-x-2">
                  {(['ufw', 'iptables', 'fail2ban'] as AutoBanType[]).map((type) => (
                    <button
                      key={type}
                      type="button"
                      onClick={() => update({ autoBanType: type })}
                      className={`px-3 py-1 rounded text-xs font-mono uppercase transition-all ${
                        config.autoBanType === type
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-300'
                      }`}
                    >
                      {type}
                    </button>
                  ))}
                </div>
                <p className="text-[11px] text-slate-500">
                  Writes immediate ban command lines to `banned_threat_ips.sh`.
                </p>
              </div>
            )}
          </div>

          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-200">SIEM / Webhook Alert Dispatch</span>
              <input
                type="checkbox"
                checked={config.enableWebhookAlert}
                onChange={(e) => update({ enableWebhookAlert: e.target.checked })}
                className="accent-cyan-500 rounded"
              />
            </div>
            {config.enableWebhookAlert && (
              <div className="space-y-2">
                <input
                  type="text"
                  value={config.webhookUrl}
                  onChange={(e) => update({ webhookUrl: e.target.value })}
                  placeholder="https://discord.com/api/webhooks/..."
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 font-mono text-xs"
                />
                <p className="text-[11px] text-slate-500">
                  Sends structured JSON alerts directly into your Discord, Slack, or SIEM receiver.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
