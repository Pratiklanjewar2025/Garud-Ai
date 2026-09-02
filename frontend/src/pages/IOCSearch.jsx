import React, { useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, Globe, Hash, Wifi, Link2, Shield, AlertTriangle,
  XCircle, ChevronRight, ExternalLink, Filter
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const IOC_TYPES = ['ALL', 'DOMAIN', 'IP', 'URL', 'HASH', 'CERT', 'EMAIL'];
const RISK_LEVELS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const IOC_ICONS = {
  DOMAIN: Globe,
  IP:     Wifi,
  URL:    Link2,
  HASH:   Hash,
  CERT:   Shield,
  EMAIL:  Search,
};

const riskBadge = (r) => ({
  CRITICAL: 'danger',
  HIGH:     'warning',
  MEDIUM:   'outline',
  LOW:      'success',
}[r] || 'outline');

const riskDot = (r) => ({
  CRITICAL: 'bg-red-500',
  HIGH:     'bg-orange-400',
  MEDIUM:   'bg-yellow-400',
  LOW:      'bg-green-500',
}[r] || 'bg-textMuted');

function timeAgo(date) {
  if (!date) return '—';
  const diff = (Date.now() - new Date(date)) / 1000;
  if (diff < 60)    return 'just now';
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function IOCSearch() {
  const [query, setQuery]           = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [results, setResults]       = useState(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState('');
  const inputRef = useRef(null);

  const doSearch = async (e) => {
    e?.preventDefault();
    const q = query.trim();
    if (!q && typeFilter === 'ALL' && riskFilter === 'ALL') return;
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams({ q });
      if (typeFilter !== 'ALL') params.set('ioc_type', typeFilter);
      if (riskFilter !== 'ALL') params.set('risk_level', riskFilter);
      const res  = await fetch(`${API_BASE}/api/v1/threats/search?${params}`);
      const data = await res.json();
      setResults(data);
    } catch (err) {
      setError('Search failed — backend may be unavailable.');
      setResults(null);
    } finally {
      setLoading(false);
    }
  };

  const clearSearch = () => {
    setQuery('');
    setResults(null);
    setError('');
    inputRef.current?.focus();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
          <Search className="w-7 h-7 text-primary" />
          IOC Search
        </h1>
        <p className="text-textMuted mt-1">
          Search Indicators of Compromise across all analyzed APK samples.
        </p>
      </div>

      {/* Search form */}
      <Card className="glass-card">
        <CardContent className="p-5">
          <form id="ioc-search-form" onSubmit={doSearch} className="space-y-4">
            <div className="relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-textMuted" />
              <input
                id="ioc-query-input"
                ref={inputRef}
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search domain, IP, URL, hash, certificate…"
                className="w-full pl-12 pr-12 py-3.5 text-sm bg-surface border border-borderSubtle rounded-xl text-textMain placeholder:text-textMuted focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
              />
              {query && (
                <button
                  type="button"
                  onClick={clearSearch}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-textMuted hover:text-textMain"
                >
                  <XCircle className="w-5 h-5" />
                </button>
              )}
            </div>

            <div className="flex flex-wrap gap-3 items-center">
              {/* IOC type filter */}
              <div className="flex items-center gap-2 bg-surface border border-borderSubtle rounded-lg px-3 py-1.5">
                <Filter className="w-4 h-4 text-textMuted" />
                <select
                  id="ioc-type-filter"
                  value={typeFilter}
                  onChange={e => setTypeFilter(e.target.value)}
                  className="bg-transparent text-sm text-textMain focus:outline-none"
                >
                  {IOC_TYPES.map(t => <option key={t} value={t}>{t === 'ALL' ? 'All Types' : t}</option>)}
                </select>
              </div>

              {/* Risk level filter */}
              <div className="flex items-center gap-2 bg-surface border border-borderSubtle rounded-lg px-3 py-1.5">
                <AlertTriangle className="w-4 h-4 text-textMuted" />
                <select
                  id="ioc-risk-filter"
                  value={riskFilter}
                  onChange={e => setRiskFilter(e.target.value)}
                  className="bg-transparent text-sm text-textMain focus:outline-none"
                >
                  {RISK_LEVELS.map(r => <option key={r} value={r}>{r === 'ALL' ? 'All Risk Levels' : r}</option>)}
                </select>
              </div>

              <button
                id="ioc-search-btn"
                type="submit"
                disabled={loading}
                className="ml-auto flex items-center gap-2 px-5 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors text-sm font-medium disabled:opacity-60"
              >
                {loading
                  ? <span className="animate-spin border-2 border-white border-t-transparent rounded-full w-4 h-4" />
                  : <Search className="w-4 h-4" />}
                Search
              </button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-3 p-4 rounded-lg border border-danger/30 bg-danger/10 text-danger text-sm">
          <XCircle className="w-5 h-5 shrink-0" />
          {error}
        </div>
      )}

      {/* No results yet */}
      {!results && !loading && !error && (
        <div className="text-center py-16 text-textMuted">
          <Search className="w-12 h-12 mx-auto mb-4 opacity-20" />
          <p className="text-sm">Enter a domain, IP, URL, or file hash to search for known IOCs.</p>
          <div className="mt-4 flex flex-wrap justify-center gap-2 text-xs">
            {['malicious-domain.com', '192.0.2.10', 'https://c2-server.com/upload', 'a83f91c5e8...'].map(ex => (
              <button
                key={ex}
                onClick={() => { setQuery(ex); }}
                className="px-3 py-1 bg-surface border border-borderSubtle rounded-full hover:border-primary hover:text-primary transition-colors font-mono"
              >
                {ex}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      <AnimatePresence>
        {results && (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-4"
          >
            <div className="flex items-center justify-between">
              <p className="text-sm text-textMuted">
                Found{' '}
                <span className="font-bold text-textMain">{results.total}</span> result
                {results.total !== 1 && 's'}
                {results.query && (
                  <> for <span className="font-mono text-primary">&quot;{results.query}&quot;</span></>
                )}
              </p>
            </div>

            {results.results.length === 0 ? (
              <Card className="glass-card">
                <CardContent className="py-12 text-center text-textMuted">
                  <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">No matching IOCs found in the database.</p>
                </CardContent>
              </Card>
            ) : (
              <Card className="glass-card overflow-hidden">
                <CardContent className="p-0">
                  {/* Table header */}
                  <div className="grid grid-cols-12 gap-2 px-5 py-2.5 text-[10px] uppercase tracking-widest text-textMuted font-semibold bg-surfaceHighlight/30">
                    <div className="col-span-1">Risk</div>
                    <div className="col-span-2">Type</div>
                    <div className="col-span-5">Value</div>
                    <div className="col-span-2">APK</div>
                    <div className="col-span-2 text-right">Found</div>
                  </div>

                  <div className="divide-y divide-borderSubtle">
                    {results.results.map((ioc, i) => {
                      const Icon = IOC_ICONS[ioc.ioc_type] || Hash;
                      return (
                        <motion.div
                          key={ioc.id}
                          initial={{ opacity: 0, x: -8 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.03 }}
                          className="grid grid-cols-12 gap-2 px-5 py-3 items-center hover:bg-surfaceHighlight/20 transition-colors group"
                        >
                          {/* Risk dot */}
                          <div className="col-span-1 flex items-center">
                            <span className={`w-2.5 h-2.5 rounded-full ${riskDot(ioc.risk_level)}`} />
                          </div>

                          {/* Type badge */}
                          <div className="col-span-2 flex items-center gap-1.5">
                            <Icon className="w-3.5 h-3.5 text-textMuted shrink-0" />
                            <span className="text-xs font-mono text-textMuted">{ioc.ioc_type}</span>
                          </div>

                          {/* Value */}
                          <div className="col-span-5 min-w-0">
                            <p className="font-mono text-sm truncate text-textMain">{ioc.ioc_value}</p>
                            {ioc.context && (
                              <p className="text-[11px] text-textMuted truncate">{ioc.context}</p>
                            )}
                            {ioc.tags && ioc.tags.length > 0 && (
                              <div className="flex gap-1 mt-0.5">
                                {ioc.tags.map(t => (
                                  <span key={t} className="text-[10px] px-1.5 py-0.5 bg-surfaceHighlight rounded text-textMuted">
                                    {t}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>

                          {/* Source APK */}
                          <div className="col-span-2 min-w-0">
                            <Link
                              to={`/analysis/${ioc.sample_id}`}
                              className="flex items-center gap-1 text-xs text-primary hover:underline truncate"
                            >
                              <ExternalLink className="w-3 h-3 shrink-0" />
                              <span className="truncate">{ioc.app_name || ioc.filename || ioc.sample_id}</span>
                            </Link>
                          </div>

                          {/* Timestamp */}
                          <div className="col-span-2 text-right">
                            <span className="text-xs text-textMuted">{timeAgo(ioc.created_at)}</span>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
