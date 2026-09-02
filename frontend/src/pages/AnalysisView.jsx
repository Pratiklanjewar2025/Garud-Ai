import React, { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, CheckCircle2, CircleDashed, XCircle, Clock,
  Server, Fingerprint, FileSearch, Search, Cpu, Network,
  GitMerge, Bot, FileText, AlertTriangle, ChevronRight,
  Lock, Globe, Hash, Zap, Eye, MessageSquare, Activity,
  BarChart3, Target, Flag
} from 'lucide-react';
import { Badge } from '../components/ui/Badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const TABS = [
  { id: 'pipeline',  label: 'Pipeline',       icon: Activity },
  { id: 'metadata',  label: 'Metadata',        icon: FileSearch },
  { id: 'static',    label: 'Static Analysis', icon: Cpu },
  { id: 'dynamic',   label: 'Behavior',        icon: Eye },
  { id: 'network',   label: 'Network & IOCs',  icon: Network },
  { id: 'agents',    label: 'AI Agents',       icon: Bot },
  { id: 'mitre',     label: 'MITRE ATT&CK',    icon: Target },
  { id: 'risk',      label: 'Risk & Classification', icon: BarChart3 },
  { id: 'report',    label: 'Report',          icon: FileText },
];

const PIPELINE_STAGES = [
  { key: 'INTAKE',             label: 'APK Intake & Validation',      icon: Server },
  { key: 'MALWARE_DNA',        label: 'Malware DNA Fingerprinting',   icon: Fingerprint },
  { key: 'STATIC_ANALYSIS',    label: 'Static Analysis',              icon: FileSearch },
  { key: 'DYNAMIC_ANALYSIS',   label: 'Dynamic Behavior Analysis',    icon: Eye },
  { key: 'NETWORK_ANALYSIS',   label: 'Network & IOC Extraction',     icon: Network },
  { key: 'FEATURE_CORRELATION','label': 'Feature Correlation Engine', icon: GitMerge },
  { key: 'AGENT_INVESTIGATION','label': 'AI Agent Investigation',     icon: Bot },
  { key: 'COMPLETED',          label: 'Report Generation',            icon: FileText },
];

const AGENT_ICONS = {
  threat_reasoning:       { icon: Shield,       color: 'text-danger' },
  behavioral_correlation: { icon: Activity,     color: 'text-warning' },
  threat_intelligence:    { icon: Search,        color: 'text-primary' },
  campaign_correlation:   { icon: Flag,          color: 'text-accent' },
  mitre_mapping:          { icon: Target,        color: 'text-purple-400' },
  risk_scoring:           { icon: BarChart3,     color: 'text-orange-400' },
  orchestrator_agent:     { icon: GitMerge,      color: 'text-success' },
  report_generation:      { icon: FileText,      color: 'text-blue-400' },
};

const severityColor = (s) => ({
  CRITICAL: 'text-red-400', HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400', LOW: 'text-green-400'
}[s] || 'text-textMuted');

const classColor = (c) => ({
  MALICIOUS: 'text-danger', SUSPICIOUS: 'text-warning', SAFE: 'text-success'
}[c] || 'text-textMuted');

const riskBg = (score) => score >= 70 ? 'bg-danger' : score >= 40 ? 'bg-warning' : 'bg-success';

export function AnalysisView() {
  const { id } = useParams();
  const [activeTab, setActiveTab] = useState('pipeline');
  const [pipeline, setPipeline]   = useState(null);
  const [metadata, setMetadata]   = useState(null);
  const [staticData, setStatic]   = useState(null);
  const [dynData, setDynamic]     = useState(null);
  const [netData, setNetwork]     = useState(null);
  const [agents, setAgents]       = useState(null);
  const [iocs, setIocs]           = useState(null);
  const [risk, setRisk]           = useState(null);
  const [mitre, setMitre]         = useState(null);
  const [report, setReport]       = useState(null);
  const [completed, setCompleted] = useState(false);

  const loadAll = useCallback(async () => {
    const fetches = [
      fetch(`${API_BASE}/api/v1/apks/${id}/metadata`).then(r => r.json()).then(setMetadata).catch(() => {}),
      fetch(`${API_BASE}/api/v1/apks/${id}/static-analysis`).then(r => r.json()).then(setStatic).catch(() => {}),
      fetch(`${API_BASE}/api/v1/apks/${id}/dynamic-analysis`).then(r => r.json()).then(setDynamic).catch(() => {}),
      fetch(`${API_BASE}/api/v1/apks/${id}/network-analysis`).then(r => r.json()).then(setNetwork).catch(() => {}),
      fetch(`${API_BASE}/api/v1/apks/${id}/agents`).then(r => r.json()).then(setAgents).catch(() => {}),
      fetch(`${API_BASE}/api/v1/apks/${id}/iocs`).then(r => r.json()).then(setIocs).catch(() => {}),
      fetch(`${API_BASE}/api/v1/apks/${id}/risk-score`).then(r => r.json()).then(setRisk).catch(() => {}),
      fetch(`${API_BASE}/api/v1/apks/${id}/mitre`).then(r => r.json()).then(setMitre).catch(() => {}),
      fetch(`${API_BASE}/api/v1/apks/${id}/report`).then(r => r.json()).then(setReport).catch(() => {}),
    ];
    await Promise.all(fetches);
  }, [id]);

  // Poll pipeline status
  useEffect(() => {
    if (completed) return;
    const poll = setInterval(async () => {
      try {
        const res  = await fetch(`${API_BASE}/api/v1/apks/${id}/pipeline-status`);
        const data = await res.json();
        setPipeline(data);
        if (data.status === 'COMPLETED' || data.status === 'FAILED') {
          setCompleted(true);
          clearInterval(poll);
          loadAll();
        }
      } catch {}
    }, 3000);
    // Initial fetch
    fetch(`${API_BASE}/api/v1/apks/${id}/pipeline-status`).then(r => r.json()).then(d => {
      setPipeline(d);
      if (d.status === 'COMPLETED' || d.status === 'FAILED') { setCompleted(true); loadAll(); }
    }).catch(() => {});
    return () => clearInterval(poll);
  }, [id, completed, loadAll]);

  const riskScore = risk?.risk_score ?? 0;
  const classification = risk?.classification || metadata?.status || 'UNKNOWN';

  return (
    <div className="space-y-4 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3 flex-wrap">
            APK Investigation Report
            {!completed && pipeline?.status === 'ANALYZING'
              ? <Badge variant="warning" className="animate-pulse text-xs">⚙ Analyzing</Badge>
              : completed && risk
                ? <Badge variant={classification === 'MALICIOUS' ? 'danger' : classification === 'SAFE' ? 'success' : 'warning'}>
                    {classification}
                  </Badge>
                : null
            }
          </h1>
          <p className="text-textMuted font-mono text-sm mt-1">{id}</p>
        </div>
        {risk && (
          <div className="flex items-center gap-2">
            <div className={`text-4xl font-black ${severityColor(risk.severity)}`}>{riskScore}</div>
            <div className="text-textMuted text-sm">/100<br/>Risk Score</div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 overflow-x-auto pb-1 border-b border-borderSubtle">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm whitespace-nowrap transition-all ${
              activeTab === tab.id
                ? 'bg-primary/10 text-primary border border-borderSubtle border-b-transparent -mb-px font-semibold'
                : 'text-textMuted hover:text-textMain hover:bg-surfaceHighlight'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.15 }}
        >
          {activeTab === 'pipeline'  && <PipelineTab pipeline={pipeline} />}
          {activeTab === 'metadata'  && <MetadataTab data={metadata} />}
          {activeTab === 'static'    && <StaticTab data={staticData} />}
          {activeTab === 'dynamic'   && <DynamicTab data={dynData} />}
          {activeTab === 'network'   && <NetworkTab data={netData} iocs={iocs} />}
          {activeTab === 'agents'    && <AgentsTab data={agents} />}
          {activeTab === 'mitre'     && <MitreTab data={mitre} />}
          {activeTab === 'risk'      && <RiskTab data={risk} />}
          {activeTab === 'report'    && <ReportTab data={report} />}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

// ─── Pipeline Tab ────────────────────────────────────────────
function PipelineTab({ pipeline }) {
  if (!pipeline) return <LoadingCard text="Connecting to analysis pipeline..." />;
  const stages    = pipeline.stages || [];
  const agentRecs = pipeline.agents || [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card className="glass-card">
        <CardHeader><CardTitle>Analysis Pipeline Stages</CardTitle><CardDescription>8-stage automated investigation</CardDescription></CardHeader>
        <CardContent>
          <div className="space-y-3">
            {PIPELINE_STAGES.map((ps, i) => {
              const stageInfo = stages.find(s => s.stage === ps.key);
              const status = stageInfo?.status || 'PENDING';
              return (
                <div key={ps.key} className="flex items-center gap-3">
                  <div className={`p-1.5 rounded-full ${status === 'COMPLETED' ? 'bg-success/20 text-success' : status === 'RUNNING' ? 'bg-primary/20 text-primary' : 'bg-surfaceHighlight text-textMuted'}`}>
                    {status === 'COMPLETED' ? <CheckCircle2 className="w-4 h-4" />
                     : status === 'RUNNING'  ? <CircleDashed className="w-4 h-4 animate-spin" />
                     : <ps.icon className="w-4 h-4" />}
                  </div>
                  <div className="flex-1">
                    <p className={`text-sm font-medium ${status === 'RUNNING' ? 'text-primary' : status === 'COMPLETED' ? 'text-textMain' : 'text-textMuted'}`}>{ps.label}</p>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${status === 'COMPLETED' ? 'bg-success/10 text-success' : status === 'RUNNING' ? 'bg-primary/10 text-primary animate-pulse' : 'bg-surface text-textMuted'}`}>
                    {status}
                  </span>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card">
        <CardHeader><CardTitle>AI Agent Status</CardTitle><CardDescription>8 AI agents — agentic investigation layer</CardDescription></CardHeader>
        <CardContent>
          <div className="space-y-2">
            {agentRecs.length === 0
              ? <p className="text-textMuted text-sm">Agents not yet initialized</p>
              : agentRecs.map(agent => {
                  const info = AGENT_ICONS[agent.name] || { icon: Bot, color: 'text-textMuted' };
                  return (
                    <div key={agent.name} className="flex items-center gap-3 p-2 rounded-lg bg-surfaceHighlight/30">
                      <info.icon className={`w-4 h-4 ${info.color}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{agent.label}</p>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${agent.status === 'COMPLETED' ? 'bg-success/10 text-success' : agent.status === 'RUNNING' ? 'bg-primary/10 text-primary animate-pulse' : agent.status === 'FAILED' ? 'bg-danger/10 text-danger' : 'bg-surface text-textMuted'}`}>
                        {agent.status}
                      </span>
                    </div>
                  );
              })
            }
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Metadata Tab ─────────────────────────────────────────────
function MetadataTab({ data }) {
  if (!data) return <LoadingCard />;
  const m = data.metadata || {};
  const c = data.certificate || {};
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card className="glass-card">
        <CardHeader><CardTitle>APK Information</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          <Row label="Package"   value={m.package_name} mono />
          <Row label="App Name"  value={m.app_name} />
          <Row label="Version"   value={`${m.version_name} (${m.version_code})`} />
          <Row label="Min SDK"   value={m.min_sdk} />
          <Row label="Target SDK"value={m.target_sdk} />
          <Row label="File Size" value={data.file_size ? `${(data.file_size / 1024 / 1024).toFixed(2)} MB` : 'N/A'} />
          <Row label="SHA-256"   value={data.sha256?.substring(0,32) + '...'} mono />
          <Row label="MD5"       value={data.md5} mono />
        </CardContent>
      </Card>
      <Card className="glass-card">
        <CardHeader><CardTitle>Certificate</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          <Row label="Subject"      value={c.subject || 'N/A'} />
          <Row label="Issuer"       value={c.issuer || 'N/A'} />
          <Row label="Self-Signed"  value={c.is_self_signed ? '⚠️ Yes' : '✓ No'} />
          <Row label="Valid From"   value={c.valid_from || 'N/A'} />
          <Row label="Valid To"     value={c.valid_to || 'N/A'} />
          <Row label="Fingerprint"  value={c.fingerprint?.substring(0,24) + '...' || 'N/A'} mono />
        </CardContent>
      </Card>
      <Card className="glass-card lg:col-span-2">
        <CardHeader><CardTitle>Permissions ({m.permissions?.length || 0})</CardTitle></CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">
            {(m.permissions || []).map(p => (
              <span key={p} className={`text-xs px-2 py-1 rounded-full border font-mono ${
                p.includes('SMS') || p.includes('ACCESSIBILITY') || p.includes('ADMIN') ? 'bg-danger/10 border-danger/30 text-danger' :
                p.includes('CONTACT') || p.includes('LOCATION') || p.includes('CAMERA') ? 'bg-warning/10 border-warning/30 text-warning' :
                'bg-surface border-borderSubtle text-textMuted'
              }`}>{p.replace('android.permission.', '')}</span>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Static Analysis Tab ──────────────────────────────────────
function StaticTab({ data }) {
  if (!data || !data.available) return <LoadingCard text="Static analysis in progress..." />;
  const flags = data.risk_flags || {};
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <ScoreCard label="Permission Risk" value={data.permission_risk_score} suffix="/100" color={data.permission_risk_score > 60 ? 'text-danger' : data.permission_risk_score > 30 ? 'text-warning' : 'text-success'} />
        <ScoreCard label="Obfuscation Score" value={data.obfuscation_score} suffix="/100" color={data.obfuscation_score > 50 ? 'text-warning' : 'text-success'} />
        <ScoreCard label="Suspicious APIs" value={data.suspicious_apis?.length || 0} color="text-primary" />
        <ScoreCard label="Extracted URLs" value={data.extracted_urls?.length || 0} color="text-accent" />
      </div>

      {/* Risk Flags */}
      <Card className="glass-card">
        <CardHeader><CardTitle>Critical Risk Flags</CardTitle></CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(flags).map(([key, val]) => (
              <div key={key} className={`flex items-center gap-2 p-3 rounded-lg border ${val ? 'bg-danger/10 border-danger/30' : 'bg-surface border-borderSubtle opacity-50'}`}>
                {val ? <AlertTriangle className="w-4 h-4 text-danger shrink-0" /> : <CheckCircle2 className="w-4 h-4 text-success shrink-0" />}
                <span className="text-xs font-medium">{key.replace(/_/g, ' ')}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Dangerous Permissions Table */}
      <Card className="glass-card">
        <CardHeader><CardTitle>Dangerous Permissions ({data.dangerous_permissions?.length || 0})</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-borderSubtle text-textMuted text-xs uppercase">
                <th className="text-left pb-2">Permission</th><th className="text-left pb-2">Risk</th><th className="text-left pb-2">Category</th>
              </tr></thead>
              <tbody className="divide-y divide-borderSubtle/30">
                {(data.dangerous_permissions || []).map((p, i) => (
                  <tr key={i} className="py-1">
                    <td className="py-2 font-mono text-xs text-textMuted">{(p.permission || '').replace('android.permission.', '')}</td>
                    <td className="py-2"><span className={`px-2 py-0.5 rounded-full text-xs ${p.risk === 'CRITICAL' ? 'bg-danger/20 text-danger' : p.risk === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-warning/20 text-warning'}`}>{p.risk}</span></td>
                    <td className="py-2 text-textMuted capitalize">{p.category}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Obfuscation */}
      {data.obfuscation_indicators?.length > 0 && (
        <Card className="glass-card border-warning/30">
          <CardHeader><CardTitle className="text-warning">⚠ Obfuscation Detected</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm text-textMuted">
              {data.obfuscation_indicators.map((o, i) => <li key={i} className="flex gap-2"><ChevronRight className="w-4 h-4 text-warning shrink-0 mt-0.5" />{o}</li>)}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Dynamic / Behavior Tab ───────────────────────────────────
function DynamicTab({ data }) {
  if (!data || !data.available) return <LoadingCard text="Behavior inference in progress..." />;
  const caps = data.capabilities || {};
  const allBehaviors = [
    ...(data.behaviors?.sms || []),
    ...(data.behaviors?.contact || []),
    ...(data.behaviors?.screen || []),
    ...(data.behaviors?.ui || []),
    ...(data.behaviors?.network || []),
    ...(data.behaviors?.file || []),
  ];
  return (
    <div className="space-y-6">
      <Card className="glass-card">
        <CardHeader><CardTitle>Capability Matrix</CardTitle><CardDescription>Method: {data.analysis_method} — Confidence: {Math.round((data.confidence || 0) * 100)}%</CardDescription></CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(caps).map(([key, val]) => (
              <div key={key} className={`p-3 rounded-lg border text-center ${val ? 'bg-danger/10 border-danger/30' : 'bg-surface border-borderSubtle opacity-40'}`}>
                <div className={`text-lg mb-1 ${val ? 'text-danger' : 'text-textMuted'}`}>{val ? '✓' : '✗'}</div>
                <p className="text-xs font-medium capitalize">{key.replace(/_/g, ' ')}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card className="glass-card">
        <CardHeader><CardTitle>Inferred Behaviors</CardTitle></CardHeader>
        <CardContent>
          <div className="space-y-3">
            {allBehaviors.map((b, i) => (
              <div key={i} className="flex gap-3 p-3 bg-danger/5 border border-danger/20 rounded-lg">
                <AlertTriangle className="w-4 h-4 text-danger shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm">{b.behavior || b}</p>
                  {b.evidence && <p className="text-xs text-textMuted mt-1">Evidence: {b.evidence}</p>}
                  {b.confidence && <p className="text-xs text-primary mt-0.5">Confidence: {Math.round(b.confidence * 100)}%</p>}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {(data.runtime_events || []).length > 0 && (
        <Card className="glass-card">
          <CardHeader><CardTitle>Simulated Runtime Events</CardTitle></CardHeader>
          <CardContent>
            <div className="font-mono text-xs space-y-1 bg-[#0a0c10] p-4 rounded-lg max-h-64 overflow-y-auto">
              {data.runtime_events.map((e, i) => (
                <div key={i} className="flex gap-3">
                  <span className="text-textMuted w-16 shrink-0">{e.time}</span>
                  <span className={`w-28 shrink-0 ${e.type?.includes('EXFIL') || e.type?.includes('C2') ? 'text-danger' : 'text-primary'}`}>[{e.type}]</span>
                  <span className="text-textMuted">{e.detail}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Network & IOC Tab ───────────────────────────────────────
function NetworkTab({ data, iocs }) {
  if (!data && !iocs) return <LoadingCard />;
  const hasC2 = data?.risk_flags?.c2_communication;
  return (
    <div className="space-y-6">
      {hasC2 && (
        <div className="p-4 bg-danger/10 border border-danger rounded-lg flex gap-3">
          <AlertTriangle className="w-5 h-5 text-danger shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-danger">C2 Communication Detected</p>
            <p className="text-sm text-textMuted">{data?.c2_candidates?.length || 0} potential command-and-control server(s) identified</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <ScoreCard label="Domains" value={data?.domains?.length || 0} color="text-primary" />
        <ScoreCard label="Suspicious Domains" value={data?.suspicious_domains?.length || 0} color="text-danger" />
        <ScoreCard label="C2 Candidates" value={data?.c2_candidates?.length || 0} color="text-danger" />
        <ScoreCard label="Total IOCs" value={iocs?.total || 0} color="text-warning" />
      </div>

      {/* IOC Table */}
      <Card className="glass-card">
        <CardHeader><CardTitle>Indicators of Compromise ({iocs?.total || 0})</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-borderSubtle text-textMuted text-xs uppercase">
                <th className="text-left pb-2 pr-4">Type</th>
                <th className="text-left pb-2 pr-4">Value</th>
                <th className="text-left pb-2 pr-4">Risk</th>
                <th className="text-left pb-2">Context</th>
              </tr></thead>
              <tbody className="divide-y divide-borderSubtle/30">
                {(iocs?.iocs || []).map(ioc => (
                  <tr key={ioc.id}>
                    <td className="py-2 pr-4"><span className="px-2 py-0.5 bg-surface border border-borderSubtle rounded text-xs font-mono">{ioc.type}</span></td>
                    <td className="py-2 pr-4 font-mono text-xs text-textMuted max-w-[200px] truncate">{ioc.value}</td>
                    <td className="py-2 pr-4"><span className={`text-xs ${ioc.risk_level === 'CRITICAL' ? 'text-danger' : ioc.risk_level === 'HIGH' ? 'text-orange-400' : 'text-warning'}`}>{ioc.risk_level}</span></td>
                    <td className="py-2 text-xs text-textMuted">{ioc.context}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Suspicious domains */}
      {(data?.suspicious_domains || []).length > 0 && (
        <Card className="glass-card">
          <CardHeader><CardTitle>Suspicious Domains</CardTitle></CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.suspicious_domains.map((d, i) => (
                <div key={i} className="flex items-start gap-3 p-3 bg-warning/5 border border-warning/20 rounded-lg">
                  <Globe className="w-4 h-4 text-warning shrink-0 mt-0.5" />
                  <div>
                    <p className="font-mono text-sm">{d.domain}</p>
                    <p className="text-xs text-textMuted">{(d.reasons || []).join(', ')}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Agents Tab ────────────────────────────────────────────────
function AgentsTab({ data }) {
  if (!data) return <LoadingCard />;
  const agents = data.agents || [];
  if (agents.length === 0) return <LoadingCard text="AI agents initializing..." />;
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {agents.map(agent => {
        const info = AGENT_ICONS[agent.name] || { icon: Bot, color: 'text-textMuted' };
        const AgIcon = info.icon;
        return (
          <Card key={agent.name} className={`glass-card ${agent.status === 'FAILED' ? 'border-danger/30' : agent.status === 'COMPLETED' ? 'border-success/20' : ''}`}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg bg-surfaceHighlight`}>
                    <AgIcon className={`w-4 h-4 ${info.color}`} />
                  </div>
                  <div>
                    <CardTitle className="text-sm">{agent.label}</CardTitle>
                    <p className="text-xs text-textMuted">Agent {agent.index}/8</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {agent.confidence > 0 && <span className="text-xs text-textMuted">{agent.confidence}%</span>}
                  <span className={`text-xs px-2 py-0.5 rounded-full ${agent.status === 'COMPLETED' ? 'bg-success/10 text-success' : agent.status === 'RUNNING' ? 'bg-primary/10 text-primary animate-pulse' : agent.status === 'FAILED' ? 'bg-danger/10 text-danger' : 'bg-surface text-textMuted'}`}>{agent.status}</span>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {agent.verdict && <p className="text-sm font-medium text-textMain mb-3 italic">"{agent.verdict}"</p>}
              {agent.risk_score != null && (
                <div className="flex items-center gap-3 mb-3 p-2 bg-surfaceHighlight rounded-lg">
                  <span className={`text-2xl font-bold ${severityColor(agent.severity)}`}>{agent.risk_score}</span>
                  <div className="text-xs">
                    <p className={classColor(agent.classification)}>{agent.classification}</p>
                    <p className={severityColor(agent.severity)}>{agent.severity}</p>
                  </div>
                </div>
              )}
              {(agent.reasoning || []).length > 0 && (
                <ul className="space-y-1">
                  {agent.reasoning.slice(0, 4).map((r, i) => (
                    <li key={i} className="flex gap-2 text-xs text-textMuted">
                      <ChevronRight className="w-3 h-3 text-primary shrink-0 mt-0.5" />
                      {r}
                    </li>
                  ))}
                </ul>
              )}
              {agent.status === 'PENDING' && <p className="text-xs text-textMuted italic">Waiting for previous agents to complete...</p>}
              {agent.status === 'FAILED' && <p className="text-xs text-danger">Error: {agent.error}</p>}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

// ─── MITRE Tab ─────────────────────────────────────────────────
function MitreTab({ data }) {
  if (!data || !data.available) return <LoadingCard text="MITRE ATT&CK mapping in progress..." />;
  const techniques = data.techniques || [];
  const tactics = [...new Set(techniques.map(t => t.tactic).filter(Boolean))];
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-2">
        {tactics.map(t => <span key={t} className="px-3 py-1 bg-primary/10 border border-primary/30 text-primary text-xs rounded-full">{t}</span>)}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {techniques.map((t, i) => (
          <Card key={i} className={`glass-card ${t.severity === 'CRITICAL' ? 'border-danger/30' : t.severity === 'HIGH' ? 'border-orange-500/30' : 'border-borderSubtle/50'}`}>
            <CardContent className="p-4">
              <div className="flex items-start justify-between gap-2 mb-2">
                <div>
                  <span className="font-mono text-xs text-primary bg-primary/10 px-2 py-0.5 rounded">{t.id}</span>
                  <h4 className="font-semibold text-sm mt-1">{t.name}</h4>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${t.severity === 'CRITICAL' ? 'bg-danger/20 text-danger' : t.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' : 'bg-warning/20 text-warning'}`}>{t.severity}</span>
              </div>
              <p className="text-xs text-textMuted mb-2">{t.description}</p>
              <div className="flex items-center gap-2 text-xs">
                <span className="bg-surfaceHighlight px-2 py-0.5 rounded text-textMuted">{t.tactic}</span>
                <span className="text-primary">{t.confidence || 0}% confidence</span>
              </div>
              {t.evidence && <p className="text-xs text-textMuted mt-2 italic">Evidence: {t.evidence}</p>}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ─── Risk Tab ──────────────────────────────────────────────────
function RiskTab({ data }) {
  if (!data || !data.available) return <LoadingCard text="Risk scoring in progress..." />;
  const score = data.risk_score || 0;
  const breakdown = data.score_breakdown || {};
  return (
    <div className="space-y-6">
      {/* Main Score */}
      <Card className="glass-card">
        <CardContent className="p-8">
          <div className="flex flex-col md:flex-row items-center gap-8">
            <div className="text-center">
              <div className={`text-8xl font-black mb-2 ${score >= 70 ? 'text-danger neon-text-danger' : score >= 40 ? 'text-warning' : 'text-success'}`}>{score}</div>
              <div className="text-textMuted text-lg">/ 100</div>
              <div className="mt-2">
                <span className={`text-2xl font-bold ${severityColor(data.severity)}`}>{data.severity}</span>
              </div>
            </div>
            <div className="flex-1 space-y-4">
              <div>
                <p className="text-textMuted text-sm mb-1">Classification</p>
                <p className={`text-3xl font-bold ${classColor(data.classification)}`}>{data.classification}</p>
              </div>
              <div>
                <p className="text-textMuted text-sm mb-1">Malware Type</p>
                <p className="text-xl font-semibold">{data.malware_type || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-textMuted text-sm mb-1">Malware Family</p>
                <p className="font-mono text-primary">{data.malware_family || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-textMuted text-sm mb-1">Confidence</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-surfaceHighlight rounded-full">
                    <div className="h-2 bg-primary rounded-full transition-all" style={{ width: `${data.confidence_score || 0}%` }} />
                  </div>
                  <span className="text-sm font-semibold">{data.confidence_score}%</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Score Breakdown */}
      <Card className="glass-card">
        <CardHeader><CardTitle>Score Breakdown</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          {Object.entries(breakdown).map(([key, val]) => (
            <div key={key}>
              <div className="flex justify-between text-sm mb-1">
                <span className="capitalize">{key.replace('_', ' ')} Analysis</span>
                <span className={`font-bold ${val >= 70 ? 'text-danger' : val >= 40 ? 'text-warning' : 'text-success'}`}>{val}/100</span>
              </div>
              <div className="h-2 bg-surfaceHighlight rounded-full">
                <div className={`h-2 rounded-full transition-all ${val >= 70 ? 'bg-danger' : val >= 40 ? 'bg-warning' : 'bg-success'}`} style={{ width: `${val}%` }} />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Report Tab ────────────────────────────────────────────────
function ReportTab({ data }) {
  if (!data || !data.available) return <LoadingCard text="Report generation in progress..." />;
  return (
    <div className="space-y-6">
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" /> Executive Summary
          </CardTitle>
          <CardDescription>For SOC management, regulators, and CERT-In</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="prose prose-invert max-w-none">
            {(data.executive_summary || '').split('\n\n').map((para, i) => (
              <p key={i} className="text-textMuted text-sm leading-relaxed mb-3">{para}</p>
            ))}
          </div>
        </CardContent>
      </Card>

      {data.behavioral_summary?.kill_chain?.length > 0 && (
        <Card className="glass-card border-danger/20">
          <CardHeader><CardTitle>Attack Kill Chain</CardTitle></CardHeader>
          <CardContent>
            <div className="space-y-2">
              {data.behavioral_summary.kill_chain.map((step, i) => (
                <div key={i} className="flex gap-3 items-start">
                  <div className="w-6 h-6 rounded-full bg-danger/20 text-danger text-xs flex items-center justify-center shrink-0 font-bold">{i + 1}</div>
                  <p className="text-sm text-textMuted">{step}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="glass-card border-danger/20">
          <CardHeader><CardTitle className="text-danger flex items-center gap-2"><Zap className="w-4 h-4" />Immediate Actions</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {(data.immediate_actions || []).map((a, i) => (
                <li key={i} className="flex gap-2 text-sm">
                  <span className="text-danger font-bold shrink-0">{i + 1}.</span>
                  <span className="text-textMuted">{a}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
        <Card className="glass-card border-primary/20">
          <CardHeader><CardTitle className="text-primary flex items-center gap-2"><Clock className="w-4 h-4" />Long-Term Actions</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {(data.long_term_actions || []).map((a, i) => (
                <li key={i} className="flex gap-2 text-sm">
                  <span className="text-primary font-bold shrink-0">{i + 1}.</span>
                  <span className="text-textMuted">{a}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      {data.dna && (
        <Card className="glass-card">
          <CardHeader><CardTitle>Malware DNA Profile</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="DNA Signature"    value={data.dna.signature} mono />
            <Row label="Suspected Family" value={data.dna.suspected_family || 'Unknown'} />
            <Row label="Known Variant"    value={data.dna.is_known_variant ? '⚠️ YES — threat memory match' : '✓ No match in threat memory'} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Shared helpers ────────────────────────────────────────────
function LoadingCard({ text = 'Loading data...' }) {
  return (
    <Card className="glass-card">
      <CardContent className="h-48 flex items-center justify-center">
        <div className="text-center">
          <CircleDashed className="w-8 h-8 text-primary animate-spin mx-auto mb-3" />
          <p className="text-textMuted text-sm">{text}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function ScoreCard({ label, value, suffix = '', color = 'text-textMain' }) {
  return (
    <Card className="glass-card">
      <CardContent className="p-4 text-center">
        <div className={`text-3xl font-bold ${color}`}>{value}{suffix}</div>
        <p className="text-textMuted text-xs mt-1">{label}</p>
      </CardContent>
    </Card>
  );
}

function Row({ label, value, mono = false }) {
  return (
    <div className="flex justify-between gap-4 py-1 border-b border-borderSubtle/30">
      <span className="text-textMuted text-xs shrink-0">{label}</span>
      <span className={`text-xs text-right ${mono ? 'font-mono' : ''}`}>{value || '—'}</span>
    </div>
  );
}


