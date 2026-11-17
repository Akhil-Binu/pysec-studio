import React from 'react';
import { SECURITY_LIBRARIES, SCANNING_RULES_AND_ETHICS } from '../data/docsData';
import { BookOpen, ShieldAlert, Cpu, Terminal, Copy, Check, Sparkles, AlertTriangle } from 'lucide-react';

export const SecurityCheatsheet: React.FC = () => {
  return (
    <div className="space-y-8 text-sm text-slate-300">
      {/* Ethics and Safe Scanning Guide */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-950/10 p-5 space-y-4">
        <div className="flex items-center space-x-2 text-amber-400 font-bold text-sm">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <span>Rules of Engagement, Ethics & Safe Scanning Guidelines</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Automated scanning scripts interact directly with remote network sockets and services. Improper usage can unintentionally crash services or violate computer fraud legislation (CFAA, Computer Misuse Act). Always adhere to these principles:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
          {SCANNING_RULES_AND_ETHICS.map((rule, idx) => (
            <div key={idx} className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
              <div className="font-semibold text-xs text-amber-300">{rule.title}</div>
              <p className="text-xs text-slate-400 leading-relaxed">{rule.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Python Security Engineering Libraries Guide */}
      <div className="space-y-4">
        <div className="flex items-center space-x-2 text-cyan-400 font-bold text-sm">
          <BookOpen className="w-5 h-5" />
          <span>Essential Python Libraries for Cybersecurity Automation</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {SECURITY_LIBRARIES.map((lib, idx) => (
            <div key={idx} className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-sm text-slate-100 font-mono">{lib.name}</h4>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800">
                    {lib.category}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">{lib.description}</p>
                <div className="mt-2 text-xs font-mono text-emerald-400 bg-slate-950 px-2 py-1 rounded inline-block">
                  {lib.installation}
                </div>
              </div>

              {/* Snippet box */}
              <div className="rounded-lg bg-[#0a0f1d] border border-slate-800/80 p-3 font-mono text-xs overflow-auto text-slate-300">
                <pre className="text-[11px] leading-relaxed">{lib.snippet}</pre>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Log Parsing Optimization Guide */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3">
        <h4 className="font-bold text-sm text-slate-100 flex items-center space-x-2">
          <Cpu className="w-4 h-4 text-purple-400" />
          <span>High-Performance Log Parsing Best Practices (O(1) Streaming)</span>
        </h4>
        <div className="space-y-2 text-xs text-slate-400 leading-relaxed">
          <p>
            <strong>Avoid readlines() or reading full files into memory:</strong> Loading a 20 GB access log with <code>f.readlines()</code> will immediately crash your machine with an <code>OutOfMemoryError</code>. Always use standard Python generator loops:
          </p>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300">
            <code>with open(&quot;access.log&quot;, &quot;r&quot;) as f:<br />&nbsp;&nbsp;&nbsp;&nbsp;for line in f:<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;process(line) # Consumes &lt; 10MB of RAM regardless of file size!</code>
          </div>
          <p>
            <strong>ReDoS (Regular Expression Denial of Service) Prevention:</strong> Avoid nested quantifiers like <code>(a+)+</code> or unanchored wildcards <code>.*.*</code> on untrusted log strings, which trigger catastrophic polynomial backtracking.
          </p>
        </div>
      </div>
    </div>
  );
};
