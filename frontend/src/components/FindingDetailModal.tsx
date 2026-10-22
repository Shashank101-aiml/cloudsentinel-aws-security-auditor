import React, { useState } from 'react';
import { X, ExternalLink, ShieldCheck, AlertCircle, Copy, Check, Info } from 'lucide-react';
import { Finding, FindingStatus } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { api } from '../services/api';

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onStatusUpdated: (updated: Finding) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onStatusUpdated,
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [updating, setUpdating] = useState<boolean>(false);

  if (!finding) return null;

  const handleCopyEvidence = () => {
    navigator.clipboard.writeText(JSON.stringify(finding.evidence, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleStatusChange = async (newStatus: FindingStatus) => {
    setUpdating(true);
    try {
      const updated = await api.updateFindingStatus(finding.id, newStatus);
      onStatusUpdated(updated);
    } catch (err) {
      console.error('Failed to update status:', err);
    } finally {
      setUpdating(false);
    }
  };

  const statusOptions: FindingStatus[] = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'ACCEPTED_RISK'];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="glass-card w-full max-w-3xl border-slate-700 bg-slate-900/95 p-6 shadow-2xl relative max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                {finding.rule_id}
              </span>
              <span className="text-xs uppercase font-medium text-slate-400">
                Confidence: <strong className="text-slate-200">{finding.confidence}</strong>
              </span>
            </div>
            <h2 className="text-lg font-bold text-white pt-1">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="mt-5 space-y-6 text-sm">
          {/* Risk Description */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Risk Impact</h3>
            <p className="text-slate-200 leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800">
              {finding.description}
            </p>
          </div>

          {/* Resource Details Grid */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Affected AWS Resource</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block">Service</span>
                <span className="font-semibold text-white uppercase text-xs">{finding.service}</span>
              </div>
              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block">Resource Type</span>
                <span className="font-semibold text-white text-xs truncate block">{finding.resource_type}</span>
              </div>
              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block">Region</span>
                <span className="font-semibold text-white text-xs">{finding.region || 'global'}</span>
              </div>
              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                <span className="text-xs text-slate-400 block">Account ID</span>
                <span className="font-mono text-white text-xs">{finding.account_id}</span>
              </div>
            </div>
            <div className="mt-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800 font-mono text-xs text-sky-300 break-all">
              Resource ID: {finding.resource_id}
            </div>
          </div>

          {/* Sanitized Evidence */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Sanitized Inspection Evidence</h3>
              <button
                type="button"
                onClick={handleCopyEvidence}
                className="text-xs text-slate-400 hover:text-sky-400 flex items-center gap-1 transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy Evidence'}
              </button>
            </div>
            <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto max-h-48">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          </div>

          {/* Remediation */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Recommended Remediation
            </h3>
            <div className="bg-emerald-950/20 border border-emerald-900/50 p-3.5 rounded-lg text-emerald-200 leading-relaxed">
              {finding.remediation}
            </div>
          </div>

          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <div>
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">AWS Documentation</h3>
              <ul className="space-y-1">
                {finding.references.map((ref, i) => (
                  <li key={i}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-sky-400 hover:underline flex items-center gap-1 truncate"
                    >
                      <ExternalLink className="w-3 h-3 flex-shrink-0" />
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Audit Verification Note */}
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg flex items-start gap-2 text-xs text-slate-400">
            <Info className="w-4 h-4 flex-shrink-0 text-sky-400 mt-0.5" />
            <span>
              <strong>Read-Only Audit Note:</strong> CloudSentinel operates strictly in read-only mode and does not alter AWS infrastructure. Remediation actions must be applied manually or via your Infrastructure-as-Code pipeline.
            </span>
          </div>

          {/* Status Update Control */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-medium">Audit Review Status:</span>
              <div className="flex flex-wrap gap-1.5">
                {statusOptions.map(st => (
                  <button
                    key={st}
                    disabled={updating}
                    onClick={() => handleStatusChange(st)}
                    className={`px-2.5 py-1 rounded text-xs font-bold uppercase transition border ${
                      finding.status === st
                        ? 'bg-sky-600 border-sky-400 text-white'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-white hover:border-slate-600'
                    }`}
                  >
                    {st.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
