import React, { useState } from 'react';
import { X, ShieldAlert, Play, CheckCircle2, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';

interface ScanConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanStarted: () => void;
}

export const ScanConfigModal: React.FC<ScanConfigModalProps> = ({ isOpen, onClose, onScanStarted }) => {
  const [mode, setMode] = useState<'demo' | 'real'>('demo');
  const [selectedRegions, setSelectedRegions] = useState<string[]>(['us-east-1']);
  const [selectedServices, setSelectedServices] = useState<string[]>(['s3', 'iam', 'ec2', 'rds', 'cloudtrail']);
  const [profile, setProfile] = useState<string>('');
  const [roleArn, setRoleArn] = useState<string>('');
  const [confirmReal, setConfirmReal] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const availableRegions = [
    'us-east-1',
    'us-east-2',
    'us-west-1',
    'us-west-2',
    'eu-west-1',
    'eu-central-1',
    'ap-south-1',
  ];

  const availableServices = [
    { id: 's3', label: 'Amazon S3', desc: 'Buckets, ACLs, public block, default SSE, versioning' },
    { id: 'iam', label: 'AWS IAM', desc: 'Admin wildcard policies, risky trusts, root MFA' },
    { id: 'ec2', label: 'Amazon EC2 & VPC', desc: 'Security groups, open SSH/RDP, unencrypted EBS' },
    { id: 'rds', label: 'Amazon RDS', desc: 'Public DB exposure, storage encryption, backups' },
    { id: 'cloudtrail', label: 'AWS CloudTrail', desc: 'Logging status, multi-region coverage, log integrity' },
  ];

  const handleToggleService = (srvId: string) => {
    setSelectedServices(prev =>
      prev.includes(srvId) ? prev.filter(s => s !== srvId) : [...prev, srvId]
    );
  };

  const handleToggleRegion = (reg: string) => {
    setSelectedRegions(prev =>
      prev.includes(reg) ? (prev.length > 1 ? prev.filter(r => r !== reg) : prev) : [...prev, reg]
    );
  };

  const handleLaunch = async () => {
    setError(null);
    if (selectedServices.length === 0) {
      setError('Please select at least one AWS service to inspect.');
      return;
    }
    if (mode === 'real' && !confirmReal) {
      setError('You must confirm real AWS account scanning before proceeding.');
      return;
    }

    setIsSubmitting(true);
    try {
      await api.startScan({
        mode,
        regions: selectedRegions,
        services: selectedServices,
        profile: profile.trim() || undefined,
        assume_role_arn: roleArn.trim() || undefined,
        confirm_real_scan: mode === 'real' ? confirmReal : undefined,
      });
      onScanStarted();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to trigger scan.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="glass-card w-full max-w-2xl border-slate-700 bg-slate-900/95 p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-6 h-6 text-sky-400" />
            <h2 className="text-xl font-bold text-white tracking-wide">Configure Security Audit Scan</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="mt-4 p-3 rounded-lg bg-red-950/80 border border-red-800/80 text-red-300 text-sm flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <div className="mt-6 space-y-6">
          {/* Mode Selector */}
          <div>
            <label className="text-sm font-semibold text-slate-200 block mb-2">Audit Execution Mode</label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setMode('demo')}
                className={`p-4 rounded-xl border text-left transition flex flex-col justify-between ${
                  mode === 'demo'
                    ? 'border-sky-500 bg-sky-950/30 text-white ring-1 ring-sky-500/50'
                    : 'border-slate-800 bg-slate-800/40 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="font-bold flex items-center justify-between mb-1">
                  <span>Demo Mode</span>
                  {mode === 'demo' && <CheckCircle2 className="w-4 h-4 text-sky-400" />}
                </div>
                <p className="text-xs text-slate-400">
                  Runs local deterministic simulation with sample findings. No AWS credentials needed.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setMode('real')}
                className={`p-4 rounded-xl border text-left transition flex flex-col justify-between ${
                  mode === 'real'
                    ? 'border-sky-500 bg-sky-950/30 text-white ring-1 ring-sky-500/50'
                    : 'border-slate-800 bg-slate-800/40 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="font-bold flex items-center justify-between mb-1">
                  <span>Real AWS Account</span>
                  {mode === 'real' && <CheckCircle2 className="w-4 h-4 text-sky-400" />}
                </div>
                <p className="text-xs text-slate-400">
                  Connects to AWS using read-only API calls. Never makes state changes or mutations.
                </p>
              </button>
            </div>
          </div>

          {/* Real AWS Configuration */}
          {mode === 'real' && (
            <div className="p-4 rounded-xl border border-sky-900/60 bg-sky-950/20 space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  AWS CLI Profile Name (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. security-audit, default"
                  value={profile}
                  onChange={e => setProfile(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Assume IAM Role ARN (Optional)
                </label>
                <input
                  type="text"
                  placeholder="arn:aws:iam::123456789012:role/CloudSentinelAuditRole"
                  value={roleArn}
                  onChange={e => setRoleArn(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="pt-2">
                <label className="flex items-start gap-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={confirmReal}
                    onChange={e => setConfirmReal(e.target.checked)}
                    className="mt-0.5 rounded border-slate-700 text-sky-500 focus:ring-sky-500"
                  />
                  <span className="text-xs text-slate-300">
                    I confirm this audit against my AWS account and acknowledge that CloudSentinel uses strictly <strong>read-only</strong> API calls.
                  </span>
                </label>
              </div>
            </div>
          )}

          {/* Services Scope */}
          <div>
            <label className="text-sm font-semibold text-slate-200 block mb-2">Target Services</label>
            <div className="space-y-2">
              {availableServices.map(srv => (
                <div
                  key={srv.id}
                  onClick={() => handleToggleService(srv.id)}
                  className={`p-3 rounded-lg border cursor-pointer flex items-center justify-between transition ${
                    selectedServices.includes(srv.id)
                      ? 'border-slate-600 bg-slate-800/80 text-white'
                      : 'border-slate-800 bg-slate-900/40 text-slate-500 hover:border-slate-700'
                  }`}
                >
                  <div>
                    <div className="font-semibold text-sm">{srv.label}</div>
                    <div className="text-xs text-slate-400">{srv.desc}</div>
                  </div>
                  <div
                    className={`w-5 h-5 rounded flex items-center justify-center border ${
                      selectedServices.includes(srv.id)
                        ? 'bg-sky-600 border-sky-500 text-white'
                        : 'border-slate-700'
                    }`}
                  >
                    {selectedServices.includes(srv.id) && <CheckCircle2 className="w-3.5 h-3.5" />}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Regions Scope */}
          <div>
            <label className="text-sm font-semibold text-slate-200 block mb-2">Regions to Audit</label>
            <div className="flex flex-wrap gap-2">
              {availableRegions.map(reg => (
                <button
                  key={reg}
                  type="button"
                  onClick={() => handleToggleRegion(reg)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                    selectedRegions.includes(reg)
                      ? 'border-sky-500 bg-sky-950/40 text-sky-300 font-semibold'
                      : 'border-slate-800 bg-slate-900 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  {reg}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="mt-8 pt-4 border-t border-slate-800 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-slate-300 hover:text-white hover:bg-slate-800 transition"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={isSubmitting}
            onClick={handleLaunch}
            className="px-5 py-2 rounded-lg text-sm font-bold bg-sky-500 hover:bg-sky-400 text-slate-950 flex items-center gap-2 shadow-lg shadow-sky-500/20 disabled:opacity-50 transition"
          >
            <Play className="w-4 h-4 fill-current" />
            {isSubmitting ? 'Launching...' : 'Run Security Audit'}
          </button>
        </div>
      </div>
    </div>
  );
};
