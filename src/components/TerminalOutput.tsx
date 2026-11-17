import React, { useRef, useEffect } from 'react';
import { Terminal, Trash2, ShieldAlert, CheckCircle2, Clock } from 'lucide-react';

interface TerminalOutputProps {
  logs: string[];
  isRunning: boolean;
  onClear: () => void;
  title?: string;
  durationMs?: number;
}

// Convert common ANSI color escape sequences into HTML styling spans
function parseAnsi(text: string): React.ReactNode[] {
  // Regex to split text by ANSI codes
  const parts = text.split(/(\x1b\[[0-9;]*m)/g);
  let currentClass = 'text-slate-300';
  let isBold = false;

  const nodes: React.ReactNode[] = [];

  parts.forEach((part, idx) => {
    if (part.startsWith('\x1b[')) {
      if (part === '\x1b[0m') {
        currentClass = 'text-slate-300';
        isBold = false;
      } else if (part === '\x1b[1m') {
        isBold = true;
      } else if (part.includes('91m') || part.includes('31m')) {
        currentClass = 'text-rose-400';
      } else if (part.includes('92m') || part.includes('32m')) {
        currentClass = 'text-emerald-400';
      } else if (part.includes('93m') || part.includes('33m')) {
        currentClass = 'text-amber-400';
      } else if (part.includes('94m') || part.includes('34m')) {
        currentClass = 'text-blue-400';
      } else if (part.includes('95m') || part.includes('35m')) {
        currentClass = 'text-purple-400 font-semibold';
      } else if (part.includes('96m') || part.includes('36m')) {
        currentClass = 'text-cyan-400';
      } else if (part.includes('90m') || part.includes('30m')) {
        currentClass = 'text-slate-500';
      }
    } else if (part) {
      nodes.push(
        <span key={idx} className={`${currentClass} ${isBold ? 'font-bold' : ''}`}>
          {part}
        </span>
      );
    }
  });

  return nodes;
}

export const TerminalOutput: React.FC<TerminalOutputProps> = ({
  logs,
  isRunning,
  onClear,
  title = 'Interactive Cyber Sandbox Terminal',
  durationMs = 0
}) => {
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Count findings in logs for summary stats
  const criticalCount = logs.filter(l => l.includes('CRITICAL')).length;
  const highCount = logs.filter(l => l.includes('[ALERT: HIGH]') || l.includes('[HIGH]') || l.includes('Exposed Git') || l.includes('Missing Header: STRICT-TRANSPORT')).length;
  const mediumCount = logs.filter(l => l.includes('MEDIUM') || l.includes('Database Port')).length;

  return (
    <div className="flex flex-col h-full rounded-xl border border-slate-800 bg-slate-950 shadow-2xl overflow-hidden font-mono text-xs">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/90 px-4 py-2.5">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="font-semibold text-slate-200">{title}</span>
          {isRunning && (
            <span className="flex items-center space-x-1.5 px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-[10px] animate-pulse">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
              <span>RUNNING...</span>
            </span>
          )}
        </div>

        <div className="flex items-center space-x-3">
          {/* Finding Counters */}
          <div className="hidden sm:flex items-center space-x-2 text-[11px]">
            {criticalCount > 0 && (
              <span className="flex items-center space-x-1 px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-medium">
                <ShieldAlert className="w-3 h-3 text-rose-400" />
                <span>{criticalCount} Critical</span>
              </span>
            )}
            {highCount > 0 && (
              <span className="flex items-center space-x-1 px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-medium">
                <span>{highCount} High</span>
              </span>
            )}
            {durationMs > 0 && (
              <span className="flex items-center space-x-1 text-slate-400">
                <Clock className="w-3 h-3" />
                <span>{(durationMs / 1000).toFixed(2)}s</span>
              </span>
            )}
          </div>

          <button
            onClick={onClear}
            className="flex items-center space-x-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700 text-[11px] transition-all"
            title="Clear output"
          >
            <Trash2 className="w-3 h-3" />
            <span>Clear</span>
          </button>
        </div>
      </div>

      {/* Terminal Screen Body */}
      <div className="flex-1 overflow-auto p-4 bg-[#050811] text-slate-300 leading-relaxed space-y-1">
        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500 text-center">
            <Terminal className="w-8 h-8 mb-2 text-slate-600 animate-pulse" />
            <p className="text-slate-400 font-medium">Sandbox Ready for Execution</p>
            <p className="text-slate-600 text-[11px] mt-1 max-w-sm">
              Click &quot;Run Script Simulation&quot; to test your custom Python script against virtual targets or realistic security logs.
            </p>
          </div>
        ) : (
          logs.map((logLine, index) => (
            <div key={index} className="whitespace-pre-wrap break-all hover:bg-slate-900/40 px-1 py-0.5 rounded">
              {parseAnsi(logLine)}
            </div>
          ))
        )}

        {isRunning && (
          <div className="flex items-center space-x-2 text-cyan-400 pt-2">
            <span className="inline-block w-2 h-4 bg-cyan-400 animate-pulse" />
            <span className="text-slate-500 italic">Executing coroutine thread tasks...</span>
          </div>
        )}
        <div ref={terminalEndRef} />
      </div>

      {/* Terminal Status Footer */}
      <div className="flex items-center justify-between border-t border-slate-900 bg-slate-950 px-4 py-1.5 text-[10px] text-slate-500">
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
          <span>Python 3.12 Sandboxed Runtime (Virtual Execution Engine)</span>
        </div>
        <div>
          <span>Lines: {logs.length}</span>
        </div>
      </div>
    </div>
  );
};
