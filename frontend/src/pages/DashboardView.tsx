import React from 'react';
import {
  ShieldAlert,
  AlertOctagon,
  AlertTriangle,
  Info,
  CheckCircle2,
  FileDown,
  Layers,
  ArrowRight,
  Database,
  Key,
  Server,
  Cloud,
} from 'lucide-react';
import { ScanSummary, Finding } from '../types';
import { RiskGauge } from '../components/RiskGauge';
import { SeverityBadge } from '../components/SeverityBadge';
import { api } from '../services/api';

interface DashboardViewProps {
  scan: ScanSummary | null;
  findings: Finding[];
  onNavigateTab: (tab: string, filter?: any) => void;
  onOpenFinding: (finding: Finding) => void;
  onOpenNewScan: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  scan,
  findings,
  onNavigateTab,
  onOpenFinding,
  onOpenNewScan,
}) => {
  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center p-16 glass-card text-center my-8">
        <ShieldAlert className="w-12 h-12 text-slate-500 mb-3" />
        <h3 className="text-lg font-bold text-white">No Scan Data Available</h3>
        <p className="text-sm text-slate-400 mt-1 max-w-sm">
          Start a new security scan in Demo mode or connect an AWS account to audit your cloud infrastructure.
        </p>
        <button
          onClick={onOpenNewScan}
          className="mt-4 px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold rounded-lg text-sm"
        >
          Run Initial Scan
        </button>
      </div>
    );
  }

  // Count findings by service
  const serviceCounts: Record<string, number> = {};
  findings.forEach(f => {
    serviceCounts[f.service] = (serviceCounts[f.service] || 0) + 1;
  });

  const getServiceIcon = (srv: string) => {
    switch (srv.toLowerCase()) {
      case 's3':
        return <Layers className="w-4 h-4 text-amber-400" />;
      case 'iam':
        return <Key className="w-4 h-4 text-purple-400" />;
      case 'ec2':
        return <Server className="w-4 h-4 text-sky-400" />;
      case 'rds':
        return <Database className="w-4 h-4 text-blue-400" />;
      case 'cloudtrail':
      default:
        return <Cloud className="w-4 h-4 text-emerald-400" />;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Welcome / Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 glass-card p-6">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Audit Posture</h1>
            <span
              className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider ${
                scan.scan_mode === 'real'
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : 'bg-amber-950 text-amber-400 border border-amber-800'
              }`}
            >
              {scan.scan_mode.toUpperCase()} SCAN
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Target Account: <code className="text-sky-300 font-mono">{scan.account_id}</code> | Scan ID:{' '}
            <code className="text-slate-300 font-mono">{scan.id.slice(0, 13)}...</code> | Completed:{' '}
            {new Date(scan.completed_at || scan.started_at).toLocaleString()}
          </p>
        </div>

        {/* Download Reports Button Group */}
        <div className="flex items-center gap-2">
          <a
            href={api.getReportJsonUrl(scan.id)}
            download
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition"
          >
            <FileDown className="w-3.5 h-3.5 text-sky-400" />
            <span>JSON</span>
          </a>
          <a
            href={api.getReportCsvUrl(scan.id)}
            download
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition"
          >
            <FileDown className="w-3.5 h-3.5 text-emerald-400" />
            <span>CSV</span>
          </a>
          <a
            href={api.getReportHtmlUrl(scan.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition"
          >
            <FileDown className="w-3.5 h-3.5 text-purple-400" />
            <span>HTML Report</span>
          </a>
        </div>
      </div>

      {/* Main Stats Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Gauge Card */}
        <div className="lg:col-span-1">
          <RiskGauge score={scan.risk_score} totalFindings={scan.findings_count} />
        </div>

        {/* Severity Metrics Breakdown */}
        <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-3 gap-4">
          <div
            onClick={() => onNavigateTab('findings', { severity: 'CRITICAL' })}
            className="glass-card p-4 cursor-pointer hover:border-red-600/50 transition group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-red-400 uppercase tracking-wider">Critical</span>
              <AlertOctagon className="w-4 h-4 text-red-500 group-hover:scale-110 transition" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-white">{scan.critical_count}</div>
            <span className="text-[11px] text-slate-400 mt-1 block">Immediate exposure threat</span>
          </div>

          <div
            onClick={() => onNavigateTab('findings', { severity: 'HIGH' })}
            className="glass-card p-4 cursor-pointer hover:border-orange-600/50 transition group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-orange-400 uppercase tracking-wider">High</span>
              <AlertTriangle className="w-4 h-4 text-orange-500 group-hover:scale-110 transition" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-white">{scan.high_count}</div>
            <span className="text-[11px] text-slate-400 mt-1 block">Severe misconfiguration</span>
          </div>

          <div
            onClick={() => onNavigateTab('findings', { severity: 'MEDIUM' })}
            className="glass-card p-4 cursor-pointer hover:border-amber-600/50 transition group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">Medium</span>
              <ShieldAlert className="w-4 h-4 text-amber-500 group-hover:scale-110 transition" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-white">{scan.medium_count}</div>
            <span className="text-[11px] text-slate-400 mt-1 block">Protective control missing</span>
          </div>

          <div
            onClick={() => onNavigateTab('findings', { severity: 'LOW' })}
            className="glass-card p-4 cursor-pointer hover:border-emerald-600/50 transition group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Low</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-500 group-hover:scale-110 transition" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-white">{scan.low_count}</div>
            <span className="text-[11px] text-slate-400 mt-1 block">Hardening opportunity</span>
          </div>

          <div
            onClick={() => onNavigateTab('findings', { severity: 'INFO' })}
            className="glass-card p-4 cursor-pointer hover:border-blue-600/50 transition group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-blue-400 uppercase tracking-wider">Informational</span>
              <Info className="w-4 h-4 text-blue-500 group-hover:scale-110 transition" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-white">{scan.info_count}</div>
            <span className="text-[11px] text-slate-400 mt-1 block">Contextual observation</span>
          </div>

          <div className="glass-card p-4 bg-slate-900/40">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Inspected</span>
              <Layers className="w-4 h-4 text-slate-400" />
            </div>
            <div className="mt-2 text-3xl font-extrabold text-white">{scan.total_resources_inspected}</div>
            <span className="text-[11px] text-slate-400 mt-1 block">
              {scan.checks_passed} checks passed, {scan.checks_skipped} skipped
            </span>
          </div>
        </div>
      </div>

      {/* Service Breakdown & Top Findings Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Service Breakdown */}
        <div className="glass-card p-6">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center justify-between">
            <span>Findings by AWS Service</span>
            <span className="text-xs font-normal text-slate-400">{Object.keys(serviceCounts).length} active</span>
          </h3>

          <div className="space-y-3">
            {['s3', 'iam', 'ec2', 'rds', 'cloudtrail'].map(srv => {
              const count = serviceCounts[srv] || 0;
              const total = scan.findings_count || 1;
              const pct = Math.round((count / total) * 100);
              return (
                <div
                  key={srv}
                  onClick={() => onNavigateTab('findings', { service: srv })}
                  className="p-3 rounded-lg bg-slate-950/50 hover:bg-slate-800/60 border border-slate-800/80 cursor-pointer transition flex items-center justify-between group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-1.5 rounded-md bg-slate-900 border border-slate-800">
                      {getServiceIcon(srv)}
                    </div>
                    <div>
                      <span className="text-sm font-semibold text-slate-200 uppercase group-hover:text-sky-400 transition">
                        {srv}
                      </span>
                      <div className="w-24 bg-slate-800 h-1 rounded-full mt-1 overflow-hidden">
                        <div className="bg-sky-500 h-full rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  </div>
                  <span className="text-sm font-extrabold text-white">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Priority Action Findings */}
        <div className="lg:col-span-2 glass-card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Priority Remediations (Critical & High)
            </h3>
            <button
              onClick={() => onNavigateTab('findings')}
              className="text-xs text-sky-400 hover:text-sky-300 font-medium flex items-center gap-1"
            >
              <span>View all {findings.length}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {findings
              .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
              .slice(0, 4)
              .map(f => (
                <div
                  key={f.id}
                  onClick={() => onOpenFinding(f)}
                  className="p-3.5 rounded-lg bg-slate-950/60 hover:bg-slate-800/70 border border-slate-800/80 cursor-pointer transition flex items-center justify-between gap-4"
                >
                  <div className="space-y-1 truncate">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-xs font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded">
                        {f.rule_id}
                      </span>
                      <span className="text-xs uppercase text-slate-400 font-semibold">{f.service}</span>
                    </div>
                    <div className="text-sm font-bold text-slate-100 truncate">{f.title}</div>
                    <div className="text-xs text-slate-400 font-mono truncate">{f.resource_id}</div>
                  </div>
                  <button className="flex-shrink-0 px-2.5 py-1 text-xs font-semibold rounded bg-slate-800 hover:bg-slate-700 text-sky-300 border border-slate-700 transition">
                    Inspect
                  </button>
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
};
