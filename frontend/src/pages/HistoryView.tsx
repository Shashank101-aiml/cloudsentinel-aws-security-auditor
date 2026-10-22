import React, { useState } from 'react';
import { History, GitCompare, ArrowRight, CheckCircle2, ShieldAlert } from 'lucide-react';
import { ScanSummary, ScanComparison } from '../types';
import { api } from '../services/api';

interface HistoryViewProps {
  scans: ScanSummary[];
  activeScanId: string;
  onSelectScan: (scanId: string) => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({
  scans,
  activeScanId,
  onSelectScan,
}) => {
  const [baseId, setBaseId] = useState<string>(scans[0]?.id || '');
  const [compId, setCompId] = useState<string>(scans[1]?.id || scans[0]?.id || '');
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [loadingComp, setLoadingComp] = useState<boolean>(false);

  const handleCompare = async () => {
    if (!baseId || !compId) return;
    setLoadingComp(true);
    try {
      const res = await api.compareScans(baseId, compId);
      setComparison(res);
    } catch (err) {
      console.error('Comparison failed:', err);
    } finally {
      setLoadingComp(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-2.5">
          <History className="w-5 h-5 text-sky-400" />
          <h1 className="text-xl font-bold text-white tracking-wide">Historical Scan Ledger</h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Review previous audit runs, observe risk drift over time, and compare findings across scans.
        </p>
      </div>

      {/* Comparison Tool Card */}
      {scans.length >= 2 && (
        <div className="glass-card p-6 border-sky-900/50 bg-sky-950/10">
          <div className="flex items-center gap-2 mb-3">
            <GitCompare className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Scan Comparison & Drift Analysis
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
            <div>
              <label className="text-xs text-slate-400 block mb-1">Baseline Scan</label>
              <select
                value={baseId}
                onChange={e => setBaseId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
              >
                {scans.map(s => (
                  <option key={s.id} value={s.id}>
                    {s.id.slice(0, 12)}... ({s.scan_mode.toUpperCase()} - {new Date(s.started_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400 block mb-1">Comparison Scan</label>
              <select
                value={compId}
                onChange={e => setCompId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
              >
                {scans.map(s => (
                  <option key={s.id} value={s.id}>
                    {s.id.slice(0, 12)}... ({s.scan_mode.toUpperCase()} - {new Date(s.started_at).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <button
                onClick={handleCompare}
                disabled={loadingComp || baseId === compId}
                className="w-full py-2 px-4 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 text-xs font-bold transition flex items-center justify-center gap-1.5"
              >
                <GitCompare className="w-3.5 h-3.5" />
                <span>{loadingComp ? 'Calculating...' : 'Compare Scans'}</span>
              </button>
            </div>
          </div>

          {/* Comparison Results */}
          {comparison && (
            <div className="mt-4 pt-4 border-t border-slate-800 grid grid-cols-3 gap-4 text-center">
              <div className="bg-slate-950/80 p-3 rounded-lg border border-red-900/40">
                <span className="text-xs text-red-400 font-bold uppercase block">New Findings</span>
                <span className="text-2xl font-extrabold text-red-400">
                  +{comparison.new_findings_count}
                </span>
              </div>
              <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 font-bold uppercase block">Persistent Findings</span>
                <span className="text-2xl font-extrabold text-slate-200">
                  {comparison.persistent_findings_count}
                </span>
              </div>
              <div className="bg-slate-950/80 p-3 rounded-lg border border-emerald-900/40">
                <span className="text-xs text-emerald-400 font-bold uppercase block">Resolved Findings</span>
                <span className="text-2xl font-extrabold text-emerald-400">
                  -{comparison.disappeared_findings_count}
                </span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scans Table */}
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase font-semibold text-[10px] tracking-wider">
                <th className="py-3 px-4">Scan Identifier</th>
                <th className="py-3 px-4">Target Account</th>
                <th className="py-3 px-4">Mode</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Findings</th>
                <th className="py-3 px-4">Inspected</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium text-slate-200">
              {scans.map(s => {
                const isActive = s.id === activeScanId;
                return (
                  <tr
                    key={s.id}
                    className={`hover:bg-slate-800/50 transition ${isActive ? 'bg-sky-950/20' : ''}`}
                  >
                    <td className="py-3 px-4 font-mono font-bold text-sky-400">
                      {s.id.slice(0, 14)}...
                      {isActive && (
                        <span className="ml-2 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-sky-950 border border-sky-800 text-sky-300">
                          Active
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">{s.account_id}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          s.scan_mode === 'real'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-amber-950 text-amber-400 border border-amber-800'
                        }`}
                      >
                        {s.scan_mode}
                      </span>
                    </td>
                    <td className="py-3 px-4 uppercase text-slate-300">{s.status}</td>
                    <td className="py-3 px-4 font-extrabold text-sm text-white">
                      {s.risk_score.toFixed(1)}
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-200">{s.findings_count}</td>
                    <td className="py-3 px-4 text-slate-400">{s.total_resources_inspected}</td>
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(s.started_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onSelectScan(s.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-300 font-semibold border border-slate-700 transition"
                      >
                        Load View
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
