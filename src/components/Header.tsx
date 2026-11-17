import React from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  FileText, 
  Play, 
  BookOpen, 
  Container, 
  Sparkles, 
  Cpu, 
  Download,
  Code2,
  Layers
} from 'lucide-react';

export type ActiveTab = 'vuln_studio' | 'log_studio' | 'sandbox_runner' | 'regex_workbench' | 'library' | 'devops' | 'cheatsheet';

interface HeaderProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  onRunSimulation: () => void;
  onDownloadScript: () => void;
  activeScriptCategory: 'vuln_scanning' | 'log_parsing';
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onTabChange,
  onRunSimulation,
  onDownloadScript,
  activeScriptCategory
}) => {
  return (
    <header className="sticky top-0 z-40 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
      {/* Top Banner Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => onTabChange('vuln_studio')}>
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
              <ShieldCheck className="w-6 h-6 text-slate-950 stroke-[2.2]" />
              <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-emerald-400 border-2 border-slate-950 animate-pulse" />
            </div>

            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-lg tracking-tight bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-400 bg-clip-text text-transparent">
                  PySecStudio
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800/60 uppercase">
                  v2.5 Pro
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Custom Python Automation for Vulnerability Scanning &amp; Log Threat Parsing
              </p>
            </div>
          </div>

          {/* Quick Header Action Buttons */}
          <div className="flex items-center space-x-2.5">
            <button
              onClick={onRunSimulation}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-semibold transition-all hover:border-cyan-500/50 shadow-sm"
              title="Test script in interactive terminal"
            >
              <Play className="w-3.5 h-3.5 fill-cyan-400 text-cyan-400" />
              <span className="hidden sm:inline">Simulate Run</span>
            </button>

            <button
              onClick={onDownloadScript}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 text-xs font-bold transition-all shadow-md shadow-cyan-500/20 active:scale-95"
              title="Download Python Script"
            >
              <Download className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>Download .py</span>
            </button>
          </div>
        </div>

        {/* Global Navigation Tabs */}
        <nav className="flex space-x-1 overflow-x-auto pb-2 pt-1 no-scrollbar text-xs">
          <button
            onClick={() => onTabChange('vuln_studio')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg font-medium whitespace-nowrap transition-all ${
              activeTab === 'vuln_studio'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>Vulnerability Scanner Studio</span>
          </button>

          <button
            onClick={() => onTabChange('log_studio')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg font-medium whitespace-nowrap transition-all ${
              activeTab === 'log_studio'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            <FileText className="w-4 h-4 text-purple-400" />
            <span>Log Threat Parser Studio</span>
          </button>

          <button
            onClick={() => onTabChange('sandbox_runner')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg font-medium whitespace-nowrap transition-all ${
              activeTab === 'sandbox_runner'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span>Interactive Cyber Sandbox</span>
          </button>

          <button
            onClick={() => onTabChange('regex_workbench')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg font-medium whitespace-nowrap transition-all ${
              activeTab === 'regex_workbench'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            <Layers className="w-4 h-4 text-amber-400" />
            <span>Log Regex Workbench</span>
          </button>

          <button
            onClick={() => onTabChange('library')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg font-medium whitespace-nowrap transition-all ${
              activeTab === 'library'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            <Code2 className="w-4 h-4 text-blue-400" />
            <span>Script Library (12)</span>
          </button>

          <button
            onClick={() => onTabChange('devops')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg font-medium whitespace-nowrap transition-all ${
              activeTab === 'devops'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            <Container className="w-4 h-4 text-pink-400" />
            <span>DevOps &amp; Docker</span>
          </button>

          <button
            onClick={() => onTabChange('cheatsheet')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg font-medium whitespace-nowrap transition-all ${
              activeTab === 'cheatsheet'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
            }`}
          >
            <BookOpen className="w-4 h-4 text-emerald-400" />
            <span>Cheatsheet &amp; Ethics</span>
          </button>
        </nav>
      </div>
    </header>
  );
};
