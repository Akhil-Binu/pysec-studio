import React, { useState } from 'react';
import { VulnScanConfig, LogParserConfig } from '../types/script';
import { CodeViewer } from './CodeViewer';
import { generateDockerfile, generateGitHubAction, generateRequirements, generateSystemdService } from '../utils/devopsGenerator';
import { Container, FileText, GitBranch, Cpu, Terminal, CheckCircle2, Download } from 'lucide-react';

interface DevOpsExportModalProps {
  category: 'vuln_scanning' | 'log_parsing';
  config: VulnScanConfig | LogParserConfig;
}

export const DevOpsExportModal: React.FC<DevOpsExportModalProps> = ({
  category,
  config
}) => {
  const [activeTab, setActiveTab] = useState<'docker' | 'github' | 'requirements' | 'systemd'>('docker');

  const dockerfileCode = generateDockerfile(category);
  const githubActionCode = generateGitHubAction(category);
  const requirementsCode = generateRequirements(category, config);
  const systemdCode = generateSystemdService(category);

  return (
    <div className="space-y-6 text-sm text-slate-300">
      {/* Intro banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex items-center justify-between">
        <div>
          <h3 className="font-bold text-base text-slate-100 flex items-center space-x-2">
            <Container className="w-5 h-5 text-cyan-400" />
            <span>DevSecOps & Production Automation Deployment</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Turn your custom Python script into a containerized microservice, scheduled CI/CD security audit, or systemd daemon.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 space-x-1">
        <button
          onClick={() => setActiveTab('docker')}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'docker'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <Container className="w-4 h-4" />
          <span>Dockerfile (Alpine Slim)</span>
        </button>

        <button
          onClick={() => setActiveTab('github')}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'github'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <GitBranch className="w-4 h-4" />
          <span>GitHub Actions (.github/workflows)</span>
        </button>

        <button
          onClick={() => setActiveTab('requirements')}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'requirements'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>requirements.txt</span>
        </button>

        <button
          onClick={() => setActiveTab('systemd')}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'systemd'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>systemd Service Unit</span>
        </button>
      </div>

      {/* Tab Contents */}
      <div className="min-h-[460px]">
        {activeTab === 'docker' && (
          <CodeViewer
            code={dockerfileCode}
            language="docker"
            filename="Dockerfile"
          />
        )}

        {activeTab === 'github' && (
          <CodeViewer
            code={githubActionCode}
            language="yaml"
            filename="security-pipeline.yml"
          />
        )}

        {activeTab === 'requirements' && (
          <CodeViewer
            code={requirementsCode}
            language="bash"
            filename="requirements.txt"
          />
        )}

        {activeTab === 'systemd' && (
          <CodeViewer
            code={systemdCode}
            language="bash"
            filename="pysec-daemon.service"
          />
        )}
      </div>
    </div>
  );
};
