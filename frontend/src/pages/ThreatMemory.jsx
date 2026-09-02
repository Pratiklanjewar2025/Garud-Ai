import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Database, ShieldAlert, FileSearch, Search, Hash, Target, ChevronRight } from 'lucide-react';
import { motion } from 'framer-motion';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

function timeAgo(date) {
  if (!date) return '';
  const diff = (Date.now() - new Date(date)) / 1000;
  if (diff < 60)   return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400)return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function ThreatMemory() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/api/v1/threats/memory`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const memory = data?.memory || [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
          <Database className="w-8 h-8 text-primary" /> Threat Memory
        </h1>
        <p className="text-textMuted">GARUD-AI malware DNA fingerprint repository and known variant signatures.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="glass-card md:col-span-1">
          <CardHeader>
            <CardTitle>Memory Statistics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b border-borderSubtle">
              <span className="text-textMuted text-sm">Total Signatures</span>
              <span className="text-xl font-bold text-primary">{data?.total || 0}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-borderSubtle">
              <span className="text-textMuted text-sm">Known Variants Cached</span>
              <span className="text-xl font-bold text-warning">
                {memory.filter(m => m.is_known_variant).length}
              </span>
            </div>
            <div className="bg-surfaceHighlight p-4 rounded-lg mt-4 border border-borderSubtle">
              <div className="flex items-center gap-2 mb-2">
                <Target className="w-4 h-4 text-accent" />
                <span className="font-semibold text-sm">How it works</span>
              </div>
              <p className="text-xs text-textMuted leading-relaxed">
                GARUD-AI hashes permissions, APIs, strings, and structural components of every analyzed APK to create a unique DNA signature. When a new APK is uploaded, its DNA is compared against this Threat Memory cache to instantly identify known variants and bypass lengthy analysis.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="glass-card md:col-span-2">
          <CardHeader>
            <CardTitle>Signatures Database</CardTitle>
            <CardDescription>Recently recorded malware DNA signatures</CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex justify-center py-12"><div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>
            ) : memory.length === 0 ? (
              <div className="text-center py-12 text-textMuted">
                <Database className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p className="text-sm">Threat memory is empty. Analyze some APKs to build signatures.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {memory.map((m, i) => (
                  <motion.div key={m.sample_id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
                    <div className={`p-4 rounded-lg border ${m.is_known_variant ? 'bg-warning/5 border-warning/30' : 'bg-surfaceHighlight/20 border-borderSubtle'}`}>
                      <div className="flex justify-between items-start mb-2">
                        <div>
                          <Link to={`/analysis/${m.sample_id}`} className="font-medium hover:text-primary transition-colors flex items-center gap-2">
                            {m.filename} <ChevronRight className="w-3 h-3" />
                          </Link>
                          <div className="flex items-center gap-2 mt-1">
                            <Hash className="w-3 h-3 text-textMuted" />
                            <span className="text-xs font-mono text-textMuted truncate max-w-[200px] md:max-w-md">{m.dna_signature}</span>
                          </div>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <span className="text-xs text-textMuted">{timeAgo(m.created_at)}</span>
                          {m.is_known_variant ? (
                            <Badge variant="warning" className="text-[10px]">Variant Cached</Badge>
                          ) : (
                            <Badge variant="outline" className="text-[10px] text-textMuted">Original</Badge>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-borderSubtle/50">
                        <span className="text-xs px-2 py-1 bg-surface rounded text-textMuted font-mono">ID: {m.sample_id}</span>
                        {m.suspected_family && (
                          <span className="text-xs px-2 py-1 bg-danger/10 text-danger rounded flex items-center gap-1">
                            <ShieldAlert className="w-3 h-3" /> {m.suspected_family} ({m.family_confidence}%)
                          </span>
                        )}
                        {m.similar_sample_id && (
                          <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded flex items-center gap-1">
                            <FileSearch className="w-3 h-3" /> Matches: {m.similar_sample_id}
                          </span>
                        )}
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
