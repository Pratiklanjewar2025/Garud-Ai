import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  FileText, Shield, AlertTriangle, ChevronRight,
  Clock, RefreshCw, ExternalLink, Zap
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const classBadge = (c) => c === 'MALICIOUS' ? 'danger' : c === 'SAFE' ? 'success' : c === 'SUSPICIOUS' ? 'warning' : 'outline';
const severityColor = (s) => ({
  CRITICAL: 'text-red-400 bg-red-400/10 border-red-400/20',
  HIGH:     'text-orange-400 bg-orange-400/10 border-orange-400/20',
  MEDIUM:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
  LOW:      'text-green-400 bg-green-400/10 border-green-400/20',
}[s] || 'text-textMuted bg-surfaceHighlight border-borderSubtle');

const riskGradient = (score) => {
  if (!score) return 'from-textMuted/20 to-textMuted/10';
  if (score >= 70) return 'from-danger/30 to-danger/10';
  if (score >= 40) return 'from-warning/30 to-warning/10';
  return 'from-success/30 to-success/10';
};
const riskTextColor = (score) => {
  if (!score) return 'text-textMuted';
  if (score >= 70) return 'text-danger';
  if (score >= 40) return 'text-warning';
  return 'text-success';
};

function timeAgo(date) {
  if (!date) return '—';
  const diff = (Date.now() - new Date(date)) / 1000;
  if (diff < 60)    return 'just now';
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function Reports() {
  const [items, setItems]           = useState([]);
  const [total, setTotal]           = useState(0);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [page, setPage]             = useState(1);
  const limit = 12;

  const load = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/api/v1/reports?page=${page}&limit=${limit}`);
      const data = await res.json();
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, [page]);

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <FileText className="w-7 h-7 text-primary" />
            Threat Reports
          </h1>
          <p className="text-textMuted mt-1">
            Completed AI-generated investigation reports for all analyzed APKs.
          </p>
        </div>
        <button
          onClick={() => load(true)}
          disabled={refreshing}
          className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg border border-borderSubtle bg-surface hover:bg-surfaceHighlight transition-colors text-textMuted hover:text-textMain"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Summary */}
      <p className="text-xs text-textMuted">
        <span className="font-semibold text-textMain">{total}</span> report{total !== 1 && 's'} available
        {totalPages > 1 && ` — Page ${page} of ${totalPages}`}
      </p>

      {/* Reports grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-56 rounded-xl bg-surfaceHighlight/40 animate-pulse" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <Card className="glass-card">
          <CardContent className="py-16 text-center text-textMuted">
            <FileText className="w-12 h-12 mx-auto mb-4 opacity-20" />
            <p className="text-sm">No reports generated yet. Upload and analyze an APK first.</p>
            <Link to="/upload" className="mt-4 inline-block text-primary text-sm hover:underline">
              → Analyze an APK
            </Link>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {items.map((item, i) => (
            <motion.div
              key={item.sample_id}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
            >
              <Link to={`/analysis/${item.sample_id}`} className="block h-full group">
                <div className="glass-card h-full rounded-xl border border-borderSubtle overflow-hidden hover:border-primary/40 transition-all hover:shadow-lg hover:shadow-primary/10">
                  {/* Risk score banner */}
                  <div className={`bg-gradient-to-r ${riskGradient(item.risk_score)} px-5 py-3 flex items-center justify-between border-b border-borderSubtle`}>
                    <div className="flex items-center gap-2">
                      {item.severity ? (
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${severityColor(item.severity)}`}>
                          {item.severity}
                        </span>
                      ) : null}
                      {item.classification && (
                        <Badge variant={classBadge(item.classification)}>
                          {item.classification}
                        </Badge>
                      )}
                    </div>
                    {item.risk_score != null && (
                      <div className="text-right">
                        <p className="text-[10px] text-textMuted">Risk</p>
                        <p className={`text-2xl font-black ${riskTextColor(item.risk_score)}`}>
                          {item.risk_score}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Card body */}
                  <div className="p-5 space-y-3">
                    {/* APK identity */}
                    <div>
                      <p className="font-semibold text-sm truncate group-hover:text-primary transition-colors">
                        {item.app_name || item.filename || item.sample_id}
                      </p>
                      <p className="text-[11px] text-textMuted font-mono truncate mt-0.5">
                        {item.package_name || item.sha256?.slice(0, 32) + '…'}
                      </p>
                    </div>

                    {/* Malware type */}
                    {item.malware_type && (
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 text-warning shrink-0" />
                        <p className="text-xs text-warning font-medium truncate">{item.malware_type}</p>
                      </div>
                    )}

                    {/* Executive summary */}
                    {item.executive_summary && (
                      <p className="text-[12px] text-textMuted leading-relaxed line-clamp-3">
                        {item.executive_summary}
                      </p>
                    )}

                    {/* Immediate actions count */}
                    {item.immediate_actions && item.immediate_actions.length > 0 && (
                      <div className="flex items-center gap-1.5 text-xs text-accent">
                        <Zap className="w-3.5 h-3.5" />
                        <span>{item.immediate_actions.length} immediate action{item.immediate_actions.length !== 1 && 's'} required</span>
                      </div>
                    )}
                  </div>

                  {/* Footer */}
                  <div className="px-5 pb-4 flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-textMuted">
                      <Clock className="w-3 h-3" />
                      <span className="text-[11px]">{timeAgo(item.generated_at)}</span>
                    </div>
                    <div className="flex items-center gap-1 text-primary text-xs opacity-0 group-hover:opacity-100 transition-opacity">
                      View Report
                      <ChevronRight className="w-3.5 h-3.5" />
                    </div>
                  </div>
                </div>
              </Link>
            </motion.div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <button
            id="reports-prev-page"
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-4 py-2 text-sm rounded-lg border border-borderSubtle bg-surface hover:bg-surfaceHighlight transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            ← Previous
          </button>
          <span className="flex items-center px-4 text-sm text-textMuted">
            Page {page} / {totalPages}
          </span>
          <button
            id="reports-next-page"
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-4 py-2 text-sm rounded-lg border border-borderSubtle bg-surface hover:bg-surfaceHighlight transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
