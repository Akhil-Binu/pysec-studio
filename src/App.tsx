import React, { useState, useMemo } from 'react';
import { VulnScanConfig, LogParserConfig } from './types/script';
import { generateVulnScanScript } from './utils/vulnScriptGenerator';
import { generateLogParserScript } from './utils/logScriptGenerator';
import { Header, ActiveTab } from './components/Header';
import { VulnScannerBuilder } from './components/VulnScannerBuilder';
import { LogParserBuilder } from './components/LogParserBuilder';
import { CodeViewer } from './components/CodeViewer';
import { InteractiveRunner } from './components/InteractiveRunner';
import { RegexPlayground } from './components/RegexPlayground';
import { TemplateLibrary } from './components/TemplateLibrary';
import { DevOpsExportModal } from './components/DevOpsExportModal';
import { SecurityCheatsheet } from './components/SecurityCheatsheet';
import { Footer } from './components/Footer';
import { ShieldCheck, FileText, Play, Download, Sparkles, Terminal } from 'lucide-react';

const DEFAULT_VULN_CONFIG: VulnScanConfig = {
  targetType: 'single',
  targetValue: 'staging.corp-internal.net',
  portPreset: 'common',
  customPorts: '80,443,22,21,3306,8080,8443',
  concurrency: 'asyncio',
  workers: 40,
  timeout: 2.5,
  rateLimitDelay: 0,
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  enableBannerGrabbing: true,
  enableHeaderAudit: true,
  enableSslCheck: true,
  enableSensitivePaths: true,
  enableCorsCheck: true,
  enableSubdomainEnum: false,
  enableCveCheck: true,
  enableSqlInjectionProbe: false,
  outputFormats: ['terminal', 'json', 'csv'],
  enableWebhook: false,
  webhookType: 'discord',
  webhookUrl: '',
  stealthMode: false,
  proxyUrl: '',
  scanTitle: 'Internal Web Audit'
};

const DEFAULT_LOG_CONFIG: LogParserConfig = {
  logType: 'nginx',
  inputMode: 'file',
  filePath: '/var/log/nginx/access.log',
  streamMode: 'streaming',
  enableBruteForceDetection: true,
  bruteForceThreshold: 8,
  bruteForceWindowSeconds: 60,
  enableWebAttackDetection: true,
  enableScannerDetection: true,
  enableMitreMapping: true,
  enableGeoLookup: false,
  enableAutoBanExport: true,
  autoBanType: 'ufw',
  outputFormat: 'rich_console',
  enableWebhookAlert: false,
  webhookType: 'discord',
  webhookUrl: '',
  alertMinSeverity: 'HIGH',
  customRegex: '',
  customFields: []
};

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('vuln_studio');
  const [vulnConfig, setVulnConfig] = useState<VulnScanConfig>(DEFAULT_VULN_CONFIG);
  const [logConfig, setLogConfig] = useState<LogParserConfig>(DEFAULT_LOG_CONFIG);

  // Real-time generated Python scripts
  const currentVulnScript = useMemo(() => generateVulnScanScript(vulnConfig), [vulnConfig]);
  const currentLogScript = useMemo(() => generateLogParserScript(logConfig), [logConfig]);

  const activeGeneratedScript = activeTab === 'log_studio' ? currentLogScript : currentVulnScript;
  const activeScriptFilename = activeTab === 'log_studio' ? 'threat_log_parser.py' : 'vulnerability_scanner.py';
  const activeCategory = activeTab === 'log_studio' ? 'log_parsing' : 'vuln_scanning';

  const handleDownloadActiveScript = () => {
    const blob = new Blob([activeGeneratedScript], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = activeScriptFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleTriggerSimulation = () => {
    setActiveTab('sandbox_runner');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header & Navigation */}
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onRunSimulation={handleTriggerSimulation}
        onDownloadScript={handleDownloadActiveScript}
        activeScriptCategory={activeCategory}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Tab 1: Vulnerability Scanner Studio */}
        {activeTab === 'vuln_studio' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-900 pb-4">
              <div>
                <h1 className="text-xl sm:text-2xl font-black text-slate-100 flex items-center space-x-2.5">
                  <span className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    <ShieldCheck className="w-5 h-5" />
                  </span>
                  <span>Vulnerability Scanning Automation Studio</span>
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  Design, configure, and output production-ready Python 3.8+ vulnerability scanners with async port enumeration, HTTP headers audit, and sensitive path fuzzing.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setActiveTab('sandbox_runner')}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-semibold transition-all"
                >
                  <Play className="w-3.5 h-3.5 fill-cyan-400" />
                  <span>Test in Sandbox</span>
                </button>
              </div>
            </div>

            {/* Split Grid: Left Config, Right Live Code */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              <div className="lg:col-span-6 space-y-6">
                <VulnScannerBuilder
                  config={vulnConfig}
                  onChange={setVulnConfig}
                  onReset={() => setVulnConfig(DEFAULT_VULN_CONFIG)}
                />
              </div>

              <div className="lg:col-span-6 sticky top-24 min-h-[620px] max-h-[820px] flex flex-col">
                <CodeViewer
                  code={currentVulnScript}
                  language="python"
                  filename="vulnerability_scanner.py"
                  className="h-full"
                />
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Log Threat Parser Studio */}
        {activeTab === 'log_studio' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-900 pb-4">
              <div>
                <h1 className="text-xl sm:text-2xl font-black text-slate-100 flex items-center space-x-2.5">
                  <span className="p-1.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30">
                    <FileText className="w-5 h-5" />
                  </span>
                  <span>Log Parsing &amp; Threat Detection Studio</span>
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  Generate memory-efficient streaming Python scripts for SIEM ingestion, brute-force correlation, web exploit signatures, and firewall auto-bans.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setActiveTab('sandbox_runner')}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 text-xs font-semibold transition-all"
                >
                  <Play className="w-3.5 h-3.5 fill-purple-400" />
                  <span>Test in Sandbox</span>
                </button>
              </div>
            </div>

            {/* Split Grid: Left Config, Right Live Code */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              <div className="lg:col-span-6 space-y-6">
                <LogParserBuilder
                  config={logConfig}
                  onChange={setLogConfig}
                  onReset={() => setLogConfig(DEFAULT_LOG_CONFIG)}
                />
              </div>

              <div className="lg:col-span-6 sticky top-24 min-h-[620px] max-h-[820px] flex flex-col">
                <CodeViewer
                  code={currentLogScript}
                  language="python"
                  filename="threat_log_parser.py"
                  className="h-full"
                />
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Interactive Sandbox Runner */}
        {activeTab === 'sandbox_runner' && (
          <div className="space-y-6">
            <div className="border-b border-slate-900 pb-4">
              <h1 className="text-xl sm:text-2xl font-black text-slate-100 flex items-center space-x-2.5">
                <span className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  <Terminal className="w-5 h-5" />
                </span>
                <span>Interactive Cyber Sandbox &amp; Script Simulator</span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Execute and observe the behavioral runtime of your generated Python scripts in an interactive simulated virtual terminal.
              </p>
            </div>

            <InteractiveRunner
              vulnConfig={vulnConfig}
              logConfig={logConfig}
            />
          </div>
        )}

        {/* Tab 4: Regex / Grok Workbench */}
        {activeTab === 'regex_workbench' && (
          <div className="space-y-6">
            <div className="border-b border-slate-900 pb-4">
              <h1 className="text-xl sm:text-2xl font-black text-slate-100 flex items-center space-x-2.5">
                <span className="p-1.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/30">
                  <Sparkles className="w-5 h-5" />
                </span>
                <span>Interactive Log Regex &amp; Tokenizer Workbench</span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Test regular expressions against real web server, SSH auth, and cloud audit logs with live named capture tokenization and copy-paste ready Python code.
              </p>
            </div>

            <RegexPlayground />
          </div>
        )}

        {/* Tab 5: Pre-Built Script Library (12 Templates) */}
        {activeTab === 'library' && (
          <div className="space-y-6">
            <div className="border-b border-slate-900 pb-4">
              <h1 className="text-xl sm:text-2xl font-black text-slate-100 flex items-center space-x-2.5">
                <span className="p-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/30">
                  <ShieldCheck className="w-5 h-5" />
                </span>
                <span>Curated Battle-Tested Python Security Scripts</span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                12 production-grade, documented, and modular Python scripts with standard library compatibility, ready for immediate execution.
              </p>
            </div>

            <TemplateLibrary />
          </div>
        )}

        {/* Tab 6: DevOps & Deployment */}
        {activeTab === 'devops' && (
          <div className="space-y-6">
            <div className="border-b border-slate-900 pb-4">
              <h1 className="text-xl sm:text-2xl font-black text-slate-100 flex items-center space-x-2.5">
                <span className="p-1.5 rounded-lg bg-pink-500/10 text-pink-400 border border-pink-500/30">
                  <Sparkles className="w-5 h-5" />
                </span>
                <span>Containerization &amp; CI/CD Pipeline Automation</span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Deploy your vulnerability scanner or log threat hunter to Docker, GitHub Actions cron schedules, or Linux systemd background daemons.
              </p>
            </div>

            <DevOpsExportModal
              category={activeCategory}
              config={activeCategory === 'vuln_scanning' ? vulnConfig : logConfig}
            />
          </div>
        )}

        {/* Tab 7: Cheatsheet & Ethics */}
        {activeTab === 'cheatsheet' && (
          <div className="space-y-6">
            <div className="border-b border-slate-900 pb-4">
              <h1 className="text-xl sm:text-2xl font-black text-slate-100 flex items-center space-x-2.5">
                <span className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  <Sparkles className="w-5 h-5" />
                </span>
                <span>Python Security Engineering Cheatsheet &amp; Guidelines</span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Master asyncio sockets, regex ReDoS defense, stream generators, and safe ethical scanning principles.
              </p>
            </div>

            <SecurityCheatsheet />
          </div>
        )}
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
}

export default App;
