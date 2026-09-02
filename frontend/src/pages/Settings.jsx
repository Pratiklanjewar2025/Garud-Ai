import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Settings as SettingsIcon, Server, Shield, Database,
  Cpu, CheckCircle2, XCircle, AlertTriangle, RefreshCw,
  Activity, Layers, Info, GitBranch
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const PIPELINE_STAGES = [
  { key: 'INTAKE',             label: 'Stage 1 — APK Intake & Validation',    desc: 'File validation, SHA-256, MD5, SHA-1 hashing, Androguard metadata extraction' },
  { key: 'MALWARE_DNA',        label: 'Stage 2 — Malware DNA Fingerprinting', desc: 'Composite DNA signature, threat memory check, known variant detection' },
  { key: 'STATIC_ANALYSIS',    label: 'Stage 3 — Static Analysis',            desc: 'Permission analysis, API detection, YARA rules, obfuscation, string extraction' },
  { key: 'DYNAMIC_ANALYSIS',   label: 'Stage 4 — Dynamic Behavior Analysis',  desc: 'SMS, contacts, accessibility, screen, file, network behavior inference' },
  { key: 'NETWORK_ANALYSIS',   label: 'Stage 5 — Network & IOC Extraction',   desc: 'Domain, IP, URL, C2 candidate extraction, DGA detection, suspicious infra' },
  { key: 'FEATURE_CORRELATION','label': 'Stage 6 — Feature Correlation',       desc: 'Cross-layer evidence fusion bridging static, dynamic, and network findings' },
  { key: 'AGENT_INVESTIGATION','label': 'Stage 7 — Agentic AI Investigation',  desc: 'All 8 AI agents: Threat Reasoning, Behavioral, Intelligence, Campaign, MITRE, Risk, Orchestrator, Report' },
  { key: 'COMPLETED',          label: 'Stage 8 — Report Generation',           desc: 'Executive + Technical + IOC + MITRE + Campaign reports, Threat Memory update' },
];

const AI_AGENTS = [
  { name: 'Threat Reasoning Agent',       index: 1, desc: 'Determines likely threat behavior from correlated evidence' },
  { name: 'Behavioral Correlation Agent', index: 2, desc: 'Correlates SMS, accessibility, overlay, and network behaviors' },
  { name: 'Threat Intelligence Agent',    index: 3, desc: 'Identifies malware families, campaigns, similar samples' },
  { name: 'Campaign Correlation Agent',   index: 4, desc: 'Links APK to larger fraud or malware campaigns' },
  { name: 'MITRE ATT&CK Mapping Agent',  index: 5, desc: 'Maps evidence to validated MITRE ATT&CK techniques' },
  { name: 'Risk Scoring Agent',           index: 6, desc: 'Calculates composite risk score 0–100 with breakdown' },
  { name: 'Orchestrator Agent',           index: 7, desc: 'Consensus aggregation across all agent verdicts' },
  { name: 'Report Generation Agent',      index: 8, desc: 'Generates executive, technical, and IOC reports' },
];

function StatusDot({ online }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${online ? 'text-success' : 'text-danger'}`}>
      <span className={`w-2 h-2 rounded-full ${online ? 'bg-success animate-pulse' : 'bg-danger'}`} />
      {online ? 'Online' : 'Offline'}
    </span>
  );
}

export function Settings() {
  const [apiStatus, setApiStatus]   = useState(null);
  const [checking, setChecking]     = useState(false);
  const [stats, setStats]           = useState(null);

  const checkApi = async () => {
    setChecking(true);
    try {
      const res  = await fetch(`${API_BASE}/`);
      const data = await res.json();
      setApiStatus({ online: true, version: data.version, message: data.status });
    } catch {
      setApiStatus({ online: false, version: null, message: 'Connection refused' });
    } finally {
      setChecking(false);
    }
  };

  const loadStats = async () => {
    try {
      const res  = await fetch(`${API_BASE}/api/v1/dashboard/stats`);
      const data = await res.json();
      setStats(data);
    } catch {
      // silent
    }
  };

  useEffect(() => {
    checkApi();
    loadStats();
  }, []);

  return (
    <div className="space-y-8 max-w-4xl">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
          <SettingsIcon className="w-7 h-7 text-primary" />
          Settings & System Info
        </h1>
        <p className="text-textMuted mt-1">
          Platform configuration, API health, and pipeline architecture overview.
        </p>
      </div>

      {/* API Connection */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="w-5 h-5 text-primary" />
              API Connection
            </CardTitle>
            <CardDescription>Backend FastAPI server status</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 rounded-lg bg-surfaceHighlight/30 border border-borderSubtle">
              <div>
                <p className="text-sm font-medium text-textMain">GARUD-AI Backend</p>
                <p className="text-xs text-textMuted font-mono mt-0.5">{API_BASE}</p>
                {apiStatus?.message && (
                  <p className="text-xs text-textMuted mt-1">{apiStatus.message}</p>
                )}
              </div>
              <div className="flex items-center gap-3">
                {apiStatus !== null && <StatusDot online={apiStatus.online} />}
                <button
                  id="settings-check-api-btn"
                  onClick={checkApi}
                  disabled={checking}
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-borderSubtle bg-surface hover:bg-surfaceHighlight transition-colors text-textMuted"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${checking ? 'animate-spin' : ''}`} />
                  Check
                </button>
              </div>
            </div>

            {apiStatus?.version && (
              <div className="flex items-center gap-2 text-xs text-textMuted">
                <GitBranch className="w-3.5 h-3.5" />
                API Version: <span className="text-textMain font-mono">{apiStatus.version}</span>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Database Statistics */}
      {stats && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="w-5 h-5 text-primary" />
                Database Statistics
              </CardTitle>
              <CardDescription>Current platform intelligence data</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                {[
                  { label: 'Total Analyzed', value: stats.total_analyzed, color: 'text-primary' },
                  { label: 'Malicious',       value: stats.malicious,       color: 'text-danger' },
                  { label: 'Suspicious',      value: stats.suspicious,      color: 'text-warning' },
                  { label: 'Safe',            value: stats.safe,            color: 'text-success' },
                ].map((item) => (
                  <div key={item.label} className="text-center p-4 rounded-lg bg-surfaceHighlight/30 border border-borderSubtle">
                    <p className={`text-3xl font-black ${item.color}`}>{item.value}</p>
                    <p className="text-xs text-textMuted mt-1">{item.label}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Analysis Pipeline */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-primary" />
              Analysis Pipeline
            </CardTitle>
            <CardDescription>8-stage deterministic APK analysis pipeline</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {PIPELINE_STAGES.map((stage, i) => (
              <div key={stage.key} className="flex gap-4 p-3 rounded-lg border border-borderSubtle hover:bg-surfaceHighlight/20 transition-colors">
                <div className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/10 border border-primary/20 shrink-0">
                  <span className="text-[11px] font-bold text-primary">{i + 1}</span>
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-textMain">{stage.label}</p>
                  <p className="text-xs text-textMuted mt-0.5">{stage.desc}</p>
                </div>
                <CheckCircle2 className="w-4 h-4 text-success shrink-0 mt-0.5" />
              </div>
            ))}
          </CardContent>
        </Card>
      </motion.div>

      {/* AI Agent Architecture */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Cpu className="w-5 h-5 text-primary" />
              AI Agent Architecture
            </CardTitle>
            <CardDescription>8 specialized agents coordinated by the Orchestrator</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {AI_AGENTS.map((agent) => (
                <div
                  key={agent.index}
                  className="flex gap-3 p-3 rounded-lg border border-borderSubtle hover:border-primary/30 hover:bg-surfaceHighlight/20 transition-all"
                >
                  <div className="flex items-center justify-center w-6 h-6 rounded bg-primary/10 border border-primary/20 shrink-0 text-[10px] font-bold text-primary">
                    {agent.index}
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-textMain truncate">{agent.name}</p>
                    <p className="text-[11px] text-textMuted mt-0.5">{agent.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Technology Stack */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Layers className="w-5 h-5 text-primary" />
              Technology Stack
            </CardTitle>
            <CardDescription>Core technologies powering GARUD-AI CyberShield</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { layer: 'Frontend',     tech: 'React + Vite + Tailwind CSS' },
                { layer: 'Backend',      tech: 'Python + FastAPI' },
                { layer: 'Database',     tech: 'SQLite / PostgreSQL' },
                { layer: 'APK Analysis', tech: 'Androguard + YARA' },
                { layer: 'AI Agents',    tech: 'LangGraph + LLM API' },
                { layer: 'Background',   tech: 'FastAPI BackgroundTasks' },
              ].map((item) => (
                <div key={item.layer} className="p-3 rounded-lg border border-borderSubtle bg-surfaceHighlight/20">
                  <p className="text-[10px] uppercase tracking-widest text-textMuted font-semibold">{item.layer}</p>
                  <p className="text-xs font-medium text-textMain mt-1">{item.tech}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Footer */}
      <div className="flex items-center gap-2 text-xs text-textMuted border-t border-borderSubtle pt-6">
        <Info className="w-4 h-4" />
        <p>GARUD-AI CyberShield v1.0 — AI-powered Android Malware Analysis & Fraud Detection Platform</p>
      </div>
    </div>
  );
}
