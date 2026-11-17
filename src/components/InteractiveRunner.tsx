import React, { useState } from 'react';
import { VulnScanConfig, LogParserConfig } from '../types/script';
import { TerminalOutput } from './TerminalOutput';
import { generateVulnScanSimulation, generateLogParserSimulation, SimulationStep } from '../utils/pythonSimulator';
import { Play, Square, Download, Sparkles, ShieldAlert, CheckCircle2, Server, FileText } from 'lucide-react';

interface InteractiveRunnerProps {
  vulnConfig: VulnScanConfig;
  logConfig: LogParserConfig;
}

export const InteractiveRunner: React.FC<InteractiveRunnerProps> = ({
  vulnConfig,
  logConfig
}) => {
  const [activeMode, setActiveMode] = useState<'vuln' | 'log'>('vuln');
  const [logs, setLogs] = useState<string[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [durationMs, setDurationMs] = useState(0);
  const [completed, setCompleted] = useState(false);

  // Run simulation with progressive delays
  const runSimulation = () => {
    setIsRunning(true);
    setLogs([]);
    setCompleted(false);
    const startTime = Date.now();

    const steps: SimulationStep[] = activeMode === 'vuln'
      ? generateVulnScanSimulation(vulnConfig)
      : generateLogParserSimulation(logConfig);

    let cumulativeDelay = 0;

    steps.forEach((step, idx) => {
      cumulativeDelay += step.delayMs;
      setTimeout(() => {
        setLogs((prev) => [...prev, step.text]);

        if (idx === steps.length - 1) {
          setIsRunning(false);
          setCompleted(true);
          setDurationMs(Date.now() - startTime);
        }
      }, cumulativeDelay);
    });
  };

  const stopSimulation = () => {
    setIsRunning(false);
  };

  const handleDownloadReport = () => {
    const reportData = {
      engine: 'PySecStudio Sandbox Runner',
      mode: activeMode,
      timestamp: new Date().toISOString(),
      executionDurationMs: durationMs,
      rawOutput: logs
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `simulation_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-full">
      {/* Control & Configuration Sidebar */}
      <div className="lg:col-span-4 space-y-4">
        {/* Mode Selector */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-3">
          <label className="text-xs font-semibold text-cyan-400 uppercase tracking-wider block">
            Select Simulation Target
          </label>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => { setActiveMode('vuln'); setLogs([]); setCompleted(false); }}
              className={`flex items-center space-x-2 p-2.5 rounded-lg border text-xs font-medium transition-all ${
                activeMode === 'vuln'
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Vulnerability Scanner</span>
            </button>

            <button
              onClick={() => { setActiveMode('log'); setLogs([]); setCompleted(false); }}
              className={`flex items-center space-x-2 p-2.5 rounded-lg border text-xs font-medium transition-all ${
                activeMode === 'log'
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <FileText className="w-4 h-4 text-purple-400" />
              <span>Log Threat Parser</span>
            </button>
          </div>

          {/* Details on current simulation target */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 text-xs space-y-1.5 font-mono">
            {activeMode === 'vuln' ? (
              <>
                <div className="text-slate-400">Target: <span className="text-cyan-300 font-bold">{vulnConfig.targetValue || 'staging.corp-internal.net'}</span></div>
                <div className="text-slate-400">Model: <span className="text-slate-200">{vulnConfig.concurrency.toUpperCase()} ({vulnConfig.workers} workers)</span></div>
                <div className="text-slate-400">Ports: <span className="text-slate-200">{vulnConfig.portPreset.toUpperCase()}</span></div>
                <div className="text-slate-400">Modules: <span className="text-emerald-400">Headers, SSL, Leaks, CORS</span></div>
              </>
            ) : (
              <>
                <div className="text-slate-400">Format: <span className="text-purple-300 font-bold">{logConfig.logType.toUpperCase()}</span></div>
                <div className="text-slate-400">Engine: <span className="text-slate-200">Streaming Generator</span></div>
                <div className="text-slate-400">Threshold: <span className="text-slate-200">{logConfig.bruteForceThreshold} fails in {logConfig.bruteForceWindowSeconds}s</span></div>
                <div className="text-slate-400">Detection: <span className="text-emerald-400">SQLi, XSS, Scanners, MITRE</span></div>
              </>
            )}
          </div>

          {/* Run / Stop Actions */}
          <div className="pt-2">
            {!isRunning ? (
              <button
                onClick={runSimulation}
                className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/25 transition-all active:scale-[0.98]"
              >
                <Play className="w-4 h-4 fill-slate-950" />
                <span>Run Script Simulation</span>
              </button>
            ) : (
              <button
                onClick={stopSimulation}
                className="w-full py-3 px-4 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 shadow-lg shadow-rose-600/25 transition-all"
              >
                <Square className="w-4 h-4 fill-white" />
                <span>Halt Simulation</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Finding Scorecard */}
        {completed && (
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 space-y-3 animate-fadeIn">
            <div className="flex items-center space-x-2 text-xs font-semibold text-emerald-400 uppercase tracking-wider">
              <CheckCircle2 className="w-4 h-4" />
              <span>Execution Verdict</span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-center text-xs">
              <div className="p-2 rounded bg-rose-500/10 border border-rose-500/20">
                <div className="text-rose-400 font-bold text-base">2</div>
                <div className="text-[10px] text-slate-400">Critical Threats</div>
              </div>
              <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20">
                <div className="text-amber-400 font-bold text-base">2</div>
                <div className="text-[10px] text-slate-400">High Risks</div>
              </div>
            </div>

            <button
              onClick={handleDownloadReport}
              className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 flex items-center justify-center space-x-2 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Download JSON Findings</span>
            </button>
          </div>
        )}

        {/* Real-world deployment tip */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-3.5 text-xs text-slate-400 space-y-1">
          <div className="font-semibold text-slate-300 flex items-center space-x-1.5">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Ready for Production</span>
          </div>
          <p className="text-[11px] leading-relaxed">
            The simulation verifies the execution flow and alert triggers. You can copy the generated Python code and run it directly in your terminal using standard Python 3.8+!
          </p>
        </div>
      </div>

      {/* Terminal View */}
      <div className="lg:col-span-8 min-h-[480px]">
        <TerminalOutput
          logs={logs}
          isRunning={isRunning}
          onClear={() => setLogs([])}
          durationMs={durationMs}
          title={activeMode === 'vuln' ? 'Vulnerability Scanner Terminal Output' : 'Log Threat Ingestion Terminal'}
        />
      </div>
    </div>
  );
};
