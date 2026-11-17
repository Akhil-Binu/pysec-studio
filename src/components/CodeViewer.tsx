import React, { useState, useEffect } from 'react';
import Prism from 'prismjs';
import 'prismjs/components/prism-python';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-yaml';
import 'prismjs/components/prism-docker';
import { Copy, Check, Download, FileCode, Maximize2, Minimize2 } from 'lucide-react';

interface CodeViewerProps {
  code: string;
  language?: string;
  filename?: string;
  className?: string;
}

export const CodeViewer: React.FC<CodeViewerProps> = ({
  code,
  language = 'python',
  filename = 'script.py',
  className = ''
}) => {
  const [copied, setCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  useEffect(() => {
    Prism.highlightAll();
  }, [code, language]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  const handleDownload = () => {
    const blob = new Blob([code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const lineCount = code.split('\n').length;
  const estimatedKb = (new Blob([code]).size / 1024).toFixed(1);

  return (
    <div className={`relative flex flex-col rounded-xl border border-slate-800 bg-slate-900/90 shadow-2xl backdrop-blur-md overflow-hidden transition-all duration-200 ${isExpanded ? 'fixed inset-4 z-50' : 'h-full'} ${className}`}>
      {/* Code Header Bar */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/80 px-4 py-2.5 select-none">
        <div className="flex items-center space-x-3">
          <div className="flex space-x-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/80 border border-red-600/40" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/80 border border-yellow-600/40" />
            <div className="w-3 h-3 rounded-full bg-emerald-500/80 border border-emerald-600/40" />
          </div>
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-300">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-200">{filename}</span>
            <span className="text-slate-600">•</span>
            <span className="text-slate-400">{lineCount} lines</span>
            <span className="text-slate-600">•</span>
            <span className="text-slate-400">{estimatedKb} KB</span>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleCopy}
            className={`flex items-center space-x-1.5 px-3 py-1 rounded-md text-xs font-medium transition-all ${
              copied
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60'
            }`}
            title="Copy to clipboard"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
            <span>{copied ? 'Copied!' : 'Copy Code'}</span>
          </button>

          <button
            onClick={handleDownload}
            className="flex items-center space-x-1.5 px-3 py-1 rounded-md text-xs font-medium bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-all hover:border-cyan-500/50"
            title="Download file"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download</span>
          </button>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700/60"
            title={isExpanded ? 'Collapse' : 'Expand full view'}
          >
            {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Code Body */}
      <div className="relative flex-1 overflow-auto bg-[#0a0f1d] font-mono text-sm leading-relaxed p-4">
        <pre className={`language-${language} m-0 p-0 bg-transparent overflow-visible`}>
          <code className={`language-${language} bg-transparent`}>
            {code}
          </code>
        </pre>
      </div>
    </div>
  );
};
