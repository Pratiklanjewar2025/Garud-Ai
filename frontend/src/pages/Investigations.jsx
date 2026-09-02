import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Activity, Smartphone, Shield, AlertTriangle, CheckCircle2,
  XCircle, Clock, ChevronRight, Filter, RefreshCw, Search
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const STATUS_OPTIONS = ['ALL', 'COMPLETED', 'ANALYZING', 'FAILED', 'UPLOADED'];
const CLASS_OPTIONS  = ['ALL', 'MALICIOUS', 'SUSPICIOUS', 'SAFE'];

function timeAgo(date) {
  if (!date) return '—';
  const diff = (Date.now() - new Date(date)) / 1000;
  if (diff < 60)    return 'just now';
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function durationStr(start, end) {
  if (!start || !end) return null;
  const sec = (new Date(end) - new Date(start)) / 1000;
  if (sec < 60) return `${sec.toFixed(0)}s`;
  return `${Math.floor(sec / 60)}m ${Math.floor(sec % 60)}s`;
}

const statusIcon = (s) => ({
  COMPLETED: <CheckCircle2 className="w-4 h-4 text-success" />,
  ANALYZING: <Clock className="w-4 h-4 text-accent animate-pulse" />,
  FAILED:    <XCircle className="w-4 h-4 text-danger" />,
  UPLOADED:  <Clock className="w-4 h-4 text-textMuted" />,
}[s] || <Clock className="w-4 h-4 text-textMuted" />);

const classBadge = (c) => c === 'MALICIOUS' ? 'danger' : c === 'SAFE' ? 'success' : c === 'SUSPICIOUS' ? 'warning' : 'outline';

const riskColor = (score) => {
  if (!score) return 'text-textMuted';
  if (score >= 70) return 'text-danger';
  if (score >= 40) return 'text-warning';
  return 'text-success';
};

export function Investigations() {
  const [items, setItems]               = useState([]);
  const [total, setTotal]               = useState(0);
  const [loading, setLoading]           = useState(true);
  const [refreshing, setRefreshing]     = useState(false);
  const [page, setPage]                 = useState(1);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [classFilter, setClassFilter]   = useState('ALL');
  const [search, setSearch]             = useState('');
  const limit = 20;

  const load = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    try {
      const params = new URLSearchParams({ page, limit });
      if (statusFilter !== 'ALL') params.set('status', statusFilter);
      if (classFilter  !== 'ALL') params.set('classification', classFilter);
      const res  = await fetch(`${API_BASE}/api/v1/investigations?${params}`);
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

  useEffect(() => { load(); }, [page, statusFilter, classFilter]);

  const filtered = search
    ? items.filter(
        i =>
          (i.filename || '').toLowerCase().includes(search.toLowerCase()) ||
          (i.sample_id || '').toLowerCase().includes(search.toLowerCase()) ||
          (i.package_name || '').toLowerCase().includes(search.toLowerCase())
      )
    : items;

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <Activity className="w-7 h-7 text-primary" />
            Investigations
          </h1>
          <p className="text-textMuted mt-1">All APK investigations processed by GARUD-AI.</p>
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

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-textMuted" />
          <input
            id="inv-search"
            type="text"
            placeholder="Search by filename, ID, or package…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm bg-surface border border-borderSubtle rounded-lg text-textMain placeholder:text-textMuted focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        {/* Status filter */}
        <div className="flex items-center gap-2 bg-surface border border-borderSubtle rounded-lg px-3 py-1.5">
          <Filter className="w-4 h-4 text-textMuted" />
          <select
            id="inv-status-filter"
            value={statusFilter}
            onChange={e => { setPage(1); setStatusFilter(e.target.value); }}
            className="bg-transparent text-sm text-textMain focus:outline-none"
          >
            {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s === 'ALL' ? 'All Statuses' : s}</option>)}
          </select>
        </div>

        {/* Classification filter */}
        <div className="flex items-center gap-2 bg-surface border border-borderSubtle rounded-lg px-3 py-1.5">
          <Shield className="w-4 h-4 text-textMuted" />
          <select
            id="inv-class-filter"
            value={classFilter}
            onChange={e => { setPage(1); setClassFilter(e.target.value); }}
            className="bg-transparent text-sm text-textMain focus:outline-none"
          >
            {CLASS_OPTIONS.map(c => <option key={c} value={c}>{c === 'ALL' ? 'All Classifications' : c}</option>)}
          </select>
        </div>
      </div>

      {/* Summary strip */}
      <p className="text-xs text-textMuted">
        Showing <span className="font-semibold text-textMain">{filtered.length}</span> of{' '}
        <span className="font-semibold text-textMain">{total}</span> investigations
        {totalPages > 1 && ` — Page ${page} of ${totalPages}`}
      </p>

      {/* Table */}
      <Card className="glass-card overflow-hidden">
        <CardContent className="p-0">
          {loading ? (
            <div className="flex flex-col gap-3 p-6">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-14 rounded-lg bg-surfaceHighlight/40 animate-pulse" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-16 text-textMuted">
              <Smartphone className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="text-sm">No investigations found. Upload an APK to begin.</p>
              <Link to="/upload" className="mt-4 inline-block text-primary text-sm hover:underline">
                → Analyze an APK
              </Link>
            </div>
          ) : (
            <div className="divide-y divide-borderSubtle">
              {/* Table header */}
              <div className="grid grid-cols-12 gap-2 px-5 py-2.5 text-[10px] uppercase tracking-widest text-textMuted font-semibold bg-surfaceHighlight/30">
                <div className="col-span-1">Status</div>
                <div className="col-span-4">APK / Package</div>
                <div className="col-span-2">Classification</div>
                <div className="col-span-1 text-right">Risk</div>
                <div className="col-span-2 hidden md:block">Malware Type</div>
                <div className="col-span-1 hidden lg:block text-right">Duration</div>
                <div className="col-span-1 text-right">Time</div>
              </div>

              {filtered.map((item, i) => (
                <motion.div
                  key={item.sample_id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03 }}
                >
                  <Link
                    to={`/analysis/${item.sample_id}`}
                    className="grid grid-cols-12 gap-2 px-5 py-3.5 items-center hover:bg-surfaceHighlight/30 transition-colors group"
                  >
                    {/* Status icon */}
                    <div className="col-span-1 flex items-center">
                      {statusIcon(item.status)}
                    </div>

                    {/* APK name */}
                    <div className="col-span-4 min-w-0">
                      <p className="font-medium text-sm truncate group-hover:text-primary transition-colors">
                        {item.filename || item.sample_id}
                      </p>
                      <p className="text-[11px] text-textMuted font-mono truncate">
                        {item.package_name || item.sample_id}
                      </p>
                    </div>

                    {/* Classification */}
                    <div className="col-span-2">
                      {item.classification
                        ? <Badge variant={classBadge(item.classification)}>{item.classification}</Badge>
                        : <Badge variant="outline">{item.status}</Badge>
                      }
                    </div>

                    {/* Risk score */}
                    <div className="col-span-1 text-right">
                      {item.risk_score != null ? (
                        <span className={`text-lg font-bold ${riskColor(item.risk_score)}`}>
                          {item.risk_score}
                        </span>
                      ) : <span className="text-textMuted text-sm">—</span>}
                    </div>

                    {/* Malware type */}
                    <div className="col-span-2 hidden md:block">
                      <p className="text-xs text-textMuted truncate">
                        {item.malware_type || (item.status === 'ANALYZING' ? 'Analyzing…' : '—')}
                      </p>
                    </div>

                    {/* Duration */}
                    <div className="col-span-1 hidden lg:block text-right">
                      <p className="text-xs text-textMuted">
                        {durationStr(item.analysis_start, item.analysis_end) || '—'}
                      </p>
                    </div>

                    {/* Time ago */}
                    <div className="col-span-1 text-right flex items-center justify-end gap-1">
                      <span className="text-xs text-textMuted">{timeAgo(item.upload_time)}</span>
                      <ChevronRight className="w-3 h-3 text-textMuted opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </Link>
                </motion.div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <button
            id="inv-prev-page"
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
            id="inv-next-page"
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
