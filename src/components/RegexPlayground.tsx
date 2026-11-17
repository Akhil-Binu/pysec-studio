import React, { useState, useMemo } from 'react';
import { LOG_SAMPLES } from '../data/logSamples';
import { Search, Sparkles, Copy, Check, ShieldAlert, Cpu, Terminal, Layers } from 'lucide-react';

export const RegexPlayground: React.FC = () => {
  const [selectedSampleId, setSelectedSampleId] = useState<string>('nginx-attacks');
  const [customText, setCustomText] = useState<string>(LOG_SAMPLES[0].content);
  const [regexPattern, setRegexPattern] = useState<string>(
    '(?P<ip>[\\d\\.]+)\\s+-\\s+\\S+\\s+\\[(?P<time>[^\\]]+)\\]\\s+"(?P<method>[A-Z]+)\\s+(?P<uri>\\S+)\\s+\\S+"\\s+(?P<status>\\d{3})\\s+(?P<bytes>\\S+)(?:\\s+"(?P<ref>[^"]*)"\\s+"(?P<ua>[^"]*)")?'
  );
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const activeSample = LOG_SAMPLES.find(s => s.id === selectedSampleId);

  const handleSelectSample = (sampleId: string) => {
    setSelectedSampleId(sampleId);
    const sample = LOG_SAMPLES.find(s => s.id === sampleId);
    if (sample) {
      setCustomText(sample.content);
      if (sample.type === 'nginx' || sample.type === 'apache') {
        setRegexPattern('(?P<ip>[\\d\\.]+)\\s+-\\s+\\S+\\s+\\[(?P<time>[^\\]]+)\\]\\s+"(?P<method>[A-Z]+)\\s+(?P<uri>\\S+)\\s+\\S+"\\s+(?P<status>\\d{3})\\s+(?P<bytes>\\S+)(?:\\s+"(?P<ref>[^"]*)"\\s+"(?P<ua>[^"]*)")?');
      } else if (sample.type === 'ssh') {
        setRegexPattern('(?P<time>[A-Z][a-z]{2}\\s+\\d+\\s+[\\d:]+)\\s+(?P<host>\\S+)\\s+(?P<daemon>sshd\\[\\d+\\]):\\s+(?P<message>.*)');
      } else {
        setRegexPattern('\\{"eventTime":\\s*"(?P<time>[^"]+)",\\s*"eventName":\\s*"(?P<event>[^"]+)"');
      }
    }
  };

  // Parse lines against current regex
  const parsedResults = useMemo(() => {
    const lines = customText.split('\n').filter(l => l.trim() !== '');
    let re: RegExp;
    try {
      // Convert Python (?P<name>...) to JS (?<name>...) for live client-side browser regex parsing
      const jsPattern = regexPattern.replace(/\(\?P<([a-zA-Z0-9_]+)>/g, '(?<$1>');
      re = new RegExp(jsPattern);
    } catch {
      return { isValid: false, items: [], error: 'Invalid regular expression syntax' };
    }

    const items = lines.map((line, idx) => {
      const match = line.match(re);
      if (!match) {
        return { index: idx, line, matched: false, groups: {} };
      }

      // Check if named groups exist
      const groups = match.groups || {};
      return {
        index: idx,
        line,
        matched: true,
        groups
      };
    });

    return { isValid: true, items, error: null };
  }, [customText, regexPattern]);

  const copyPythonCode = async () => {
    const code = `import re

# Compiled Python regex with named capture groups
LOG_PATTERN = re.compile(
    r"""${regexPattern}"""
)

def parse_log_line(line: str):
    match = LOG_PATTERN.match(line.strip())
    if match:
        return match.groupdict()
    return None
`;
    await navigator.clipboard.writeText(code);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  const matchedCount = parsedResults.items.filter(i => i.matched).length;
  const totalCount = parsedResults.items.length;

  return (
    <div className="space-y-6 text-sm text-slate-300">
      {/* Sample Selector & Quick Patterns */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-semibold text-cyan-400 uppercase tracking-wider">
            <Layers className="w-3.5 h-3.5" />
            <span>Select Log Preset or Paste Custom Logs</span>
          </div>
          <span className="text-xs text-slate-400">
            Matched: <strong className="text-emerald-400">{matchedCount}</strong> / {totalCount} lines
          </span>
        </div>

        <div className="flex flex-wrap gap-2">
          {LOG_SAMPLES.map(sample => (
            <button
              key={sample.id}
              onClick={() => handleSelectSample(sample.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                selectedSampleId === sample.id
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-sm'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              {sample.name}
            </button>
          ))}
        </div>
      </div>

      {/* Regex Editor Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center space-x-1.5">
            <Cpu className="w-3.5 h-3.5" />
            <span>Python Regex Pattern (Named Capture Groups: (?P&lt;name&gt;...))</span>
          </label>
          <button
            onClick={copyPythonCode}
            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition-colors"
          >
            {copiedSnippet ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
            <span>{copiedSnippet ? 'Copied Snippet!' : 'Copy Python re.compile'}</span>
          </button>
        </div>

        <div className="relative">
          <textarea
            rows={3}
            value={regexPattern}
            onChange={(e) => setRegexPattern(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-cyan-300 font-mono text-xs leading-relaxed"
          />
        </div>

        {!parsedResults.isValid && (
          <div className="p-2.5 rounded-lg bg-rose-950/30 border border-rose-800/40 text-xs text-rose-300 flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>{parsedResults.error}</span>
          </div>
        )}
      </div>

      {/* Input Log Stream & Live Tokenized Extraction Results */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Raw Log Input Area */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-2 flex flex-col">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Input Log Stream (Editable)
            </label>
            <span className="text-[11px] text-slate-500 font-mono">{totalCount} lines</span>
          </div>
          <textarea
            rows={14}
            value={customText}
            onChange={(e) => setCustomText(e.target.value)}
            placeholder="Paste log lines here..."
            className="w-full flex-1 p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs leading-relaxed resize-none focus:border-cyan-500"
          />
        </div>

        {/* Live Extracted Fields View */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Extracted Named Entities & Token Chips
            </label>
            <span className="text-[11px] text-emerald-400 font-mono">
              {matchedCount} successful extractions
            </span>
          </div>

          <div className="flex-1 overflow-auto max-h-[380px] space-y-2.5 pr-1">
            {parsedResults.items.map((item, idx) => (
              <div
                key={idx}
                className={`p-2.5 rounded-lg border text-xs font-mono transition-all ${
                  item.matched
                    ? 'bg-slate-950 border-slate-800/90'
                    : 'bg-rose-950/10 border-rose-900/30 text-rose-400'
                }`}
              >
                {!item.matched ? (
                  <div>
                    <span className="text-rose-400 font-semibold">[NO MATCH] </span>
                    <span className="text-slate-500 text-[11px]">{item.line}</span>
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    <div className="text-slate-400 text-[10px] truncate">{item.line}</div>
                    <div className="flex flex-wrap gap-1.5 pt-0.5">
                      {Object.entries(item.groups).map(([k, v]) => (
                        <span
                          key={k}
                          className="inline-flex items-center px-2 py-0.5 rounded bg-slate-900 border border-slate-700/80 text-[11px]"
                        >
                          <span className="text-cyan-400 font-bold mr-1">{k}:</span>
                          <span className="text-slate-200">{v || '<empty>'}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
