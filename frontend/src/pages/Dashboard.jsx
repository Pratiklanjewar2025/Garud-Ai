import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import {
  ShieldAlert, ShieldCheck, Activity, Smartphone,
  AlertTriangle, TrendingUp, Eye, Target, ChevronRight
} from 'lucide-react';
import { motion } from 'framer-motion';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const classColor = c => ({
  MALICIOUS: 'text-danger', SUSPICIOUS: 'text-warning', SAFE: 'text-success'
}[c] || 'text-textMuted');

const classBadge = c => c === 'MALICIOUS' ? 'danger' : c === 'SAFE' ? 'success' : 'warning';

function timeAgo(date) {
  if (!date) return '';
  const diff = (Date.now() - new Date(date)) / 1000;
  if (diff < 60)   return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400)return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/v1/dashboard/stats`)
      .then(r => r.json())
      .then(d => { setStats(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  // Fallback placeholder stats while loading or if API not yet populated
  const s = stats || { total_analyzed: 0, malicious: 0, suspicious: 0, safe: 0, active_scans: 0, recent_investigations: [], top_malware_families: [] };

  const statCards = [
    { title: "Total Analyzed",  value: s.total_analyzed, icon: Smartphone,  color: "text-primary" },
    { title: "Malicious Found", value: s.malicious,       icon: ShieldAlert, color: "text-danger" },
    { title: "Suspicious",      value: s.suspicious,      icon: AlertTriangle, color: "text-warning" },
    { title: "Safe Apps",       value: s.safe,            icon: ShieldCheck, color: "text-success" },
    { title: "Active Scans",    value: s.active_scans,    icon: Activity,    color: "text-accent" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight">Threat Intelligence Dashboard</h1>
        <p className="text-textMuted">Real-time overview of GARUD-AI CyberShield APK investigations.</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {statCards.map((stat, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.08 }}>
            <Card className="glass-card">
              <CardContent className="p-5 flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-textMuted">{stat.title}</p>
                  <p className={`text-3xl font-bold mt-1 ${stat.color}`}>{loading ? '—' : stat.value}</p>
                </div>
                <div className={`p-3 rounded-xl bg-surfaceHighlight ${stat.color}`}>
                  <stat.icon className="w-5 h-5" />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Investigations */}
        <Card className="glass-card lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent Investigations</CardTitle>
            <CardDescription>Latest APKs processed by the GARUD-AI engine.</CardDescription>
          </CardHeader>
          <CardContent>
            {(s.recent_investigations || []).length === 0 ? (
              <div className="text-center py-12 text-textMuted">
                <Smartphone className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p className="text-sm">No investigations yet. Upload an APK to begin.</p>
                <Link to="/upload" className="mt-4 inline-block text-primary text-sm hover:underline">→ Analyze an APK</Link>
              </div>
            ) : (
              <div className="space-y-3">
                {s.recent_investigations.map((scan) => (
                  <Link key={scan.sample_id} to={`/analysis/${scan.sample_id}`}>
                    <div className="flex items-center justify-between p-3 rounded-lg border border-borderSubtle bg-surfaceHighlight/20 hover:bg-surfaceHighlight transition-colors cursor-pointer">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="p-2 bg-surface rounded-md border border-borderSubtle shrink-0">
                          <Smartphone className="w-4 h-4 text-textMuted" />
                        </div>
                        <div className="min-w-0">
                          <p className="font-medium text-sm truncate">{scan.filename}</p>
                          <p className="text-xs text-textMuted font-mono">{scan.sample_id}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 shrink-0 ml-3">
                        {scan.risk_score != null && (
                          <div className="text-right hidden md:block">
                            <p className="text-xs text-textMuted">Risk</p>
                            <p className={`text-lg font-bold ${scan.risk_score > 70 ? 'text-danger' : scan.risk_score > 40 ? 'text-warning' : 'text-success'}`}>{scan.risk_score}</p>
                          </div>
                        )}
                        {scan.classification
                          ? <Badge variant={classBadge(scan.classification)}>{scan.classification}</Badge>
                          : <Badge variant="outline">{scan.status}</Badge>
                        }
                        <span className="text-xs text-textMuted w-16 text-right">{timeAgo(scan.upload_time)}</span>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Top Malware Families */}
        <div className="space-y-4">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-warning" /> Active Malware Families
              </CardTitle>
              <CardDescription>Detected malware families</CardDescription>
            </CardHeader>
            <CardContent>
              {(s.top_malware_families || []).length === 0 ? (
                <p className="text-sm text-textMuted text-center py-6">No malware families detected yet</p>
              ) : (
                <div className="space-y-3">
                  {s.top_malware_families.map((f, i) => (
                    <div key={i} className="flex items-center justify-between border-b border-borderSubtle pb-2 last:border-0">
                      <div className="flex items-center gap-2">
                        <span className="text-textMuted text-xs w-4">{i + 1}.</span>
                        <p className="text-sm font-medium">{f.family}</p>
                      </div>
                      <span className="text-xs font-bold text-danger bg-danger/10 px-2 py-0.5 rounded">{f.count}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="glass-card">
            <CardHeader><CardTitle>System Status</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {[
                { label: "Pipeline Engine",    status: true },
                { label: "AI Agent Layer",     status: true },
                { label: "MITRE Knowledge Base",status: true },
                { label: "Threat Signatures",  status: true },
              ].map((item, i) => (
                <div key={i} className="flex items-center justify-between">
                  <span className="text-sm text-textMuted">{item.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
                    <span className="text-xs text-success">Online</span>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
