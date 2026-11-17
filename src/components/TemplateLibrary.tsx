import React, { useState } from 'react';
import { SCRIPT_TEMPLATES } from '../data/templates';
import { ScriptTemplate } from '../types/script';
import { CodeViewer } from './CodeViewer';
import { 
  Search, 
  Tag, 
  Terminal, 
  Zap, 
  ShieldCheck, 
  FileText, 
  Download, 
  Copy, 
  Check, 
  Layers, 
  ArrowRight,
  ExternalLink
} from 'lucide-react';

interface TemplateLibraryProps {
  onSelectTemplate?: (template: ScriptTemplate) => void;
}

export const TemplateLibrary: React.FC<TemplateLibraryProps> = () => {
  const [selectedCategory, setSelectedCategory] = useState<'all' | 'vuln_scanning' | 'log_parsing'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedScript, setSelectedScript] = useState<ScriptTemplate>(SCRIPT_TEMPLATES[0]);

  const filteredTemplates = SCRIPT_TEMPLATES.filter(script => {
    const matchesCategory = selectedCategory === 'all' || script.category === selectedCategory;
    const matchesSearch = 
      script.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      script.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      script.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-6 text-sm text-slate-300">
      {/* Top Filter Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* Category Pills */}
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setSelectedCategory('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
              selectedCategory === 'all'
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
          >
            All Scripts ({SCRIPT_TEMPLATES.length})
          </button>
          <button
            onClick={() => setSelectedCategory('vuln_scanning')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
              selectedCategory === 'vuln_scanning'
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
          >
            Vulnerability Scanning
          </button>
          <button
            onClick={() => setSelectedCategory('log_parsing')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
              selectedCategory === 'log_parsing'
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50'
                : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
            }`}
          >
            Log Parsing & SIEM
          </button>
        </div>

        {/* Search Box */}
        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search keywords (e.g. ssh, ssl, sqli)..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Main Split Layout: Script Cards on Left, Full Code on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left List of Templates */}
        <div className="lg:col-span-5 space-y-3 max-h-[750px] overflow-auto pr-1">
          {filteredTemplates.map((template) => {
            const isSelected = selectedScript.id === template.id;
            return (
              <div
                key={template.id}
                onClick={() => setSelectedScript(template)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-cyan-950/20 border-cyan-500/50 ring-1 ring-cyan-500/30 shadow-lg shadow-cyan-500/5'
                    : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/40 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-2">
                    {template.category === 'vuln_scanning' ? (
                      <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    ) : (
                      <FileText className="w-4 h-4 text-purple-400" />
                    )}
                    <span className="font-semibold text-xs text-slate-100">{template.title}</span>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase font-semibold ${
                    template.difficulty === 'Beginner' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                    template.difficulty === 'Intermediate' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                    'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  }`}>
                    {template.difficulty}
                  </span>
                </div>

                <p className="text-xs text-slate-400 mt-2 line-clamp-2 leading-relaxed">
                  {template.description}
                </p>

                <div className="flex flex-wrap gap-1.5 mt-3">
                  {template.tags.slice(0, 4).map(tag => (
                    <span key={tag} className="text-[10px] px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                      #{tag}
                    </span>
                  ))}
                </div>

                {template.mitreTags && template.mitreTags.length > 0 && (
                  <div className="mt-2 text-[10px] text-purple-400 font-mono">
                    MITRE: {template.mitreTags.join(', ')}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Right Code Preview & CLI Execution Card */}
        <div className="lg:col-span-7 flex flex-col space-y-4">
          {/* Active Script Metadata Header */}
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="font-bold text-sm text-slate-100 flex items-center space-x-2">
                <span>{selectedScript.title}</span>
              </h3>
              <span className="text-xs text-cyan-400 font-mono">
                {selectedScript.category === 'vuln_scanning' ? 'Vulnerability Scanner' : 'Threat Log Hunter'}
              </span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              {selectedScript.description}
            </p>

            {/* CLI usage command box */}
            <div className="pt-2">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Command-Line Quickstart:
              </div>
              <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 flex items-center justify-between">
                <span>{selectedScript.cliExample}</span>
              </div>
            </div>
          </div>

          {/* Full Code Viewer */}
          <div className="flex-1 min-h-[500px]">
            <CodeViewer
              code={selectedScript.pythonCode}
              language="python"
              filename={`${selectedScript.id}.py`}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
