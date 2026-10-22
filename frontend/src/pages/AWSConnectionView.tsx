import React, { useState } from 'react';
import {
  Cloud,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  ShieldCheck,
  Lock,
  ExternalLink,
} from 'lucide-react';
import { AWSConnectionStatus, AWSIdentity } from '../types';

interface AWSConnectionViewProps {
  status: AWSConnectionStatus | null;
  identity: AWSIdentity | null;
  onRefresh: () => void;
  onOpenNewScan: () => void;
}

export const AWSConnectionView: React.FC<AWSConnectionViewProps> = ({
  status,
  identity,
  onRefresh,
  onOpenNewScan,
}) => {
  const [copiedPolicy, setCopiedPolicy] = useState<boolean>(false);

  const leastPrivilegePolicy = {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'CloudSentinelReadOnlyAuditPolicy',
        Effect: 'Allow',
        Action: [
          'sts:GetCallerIdentity',
          's3:ListAllMyBuckets',
          's3:GetBucketLocation',
          's3:GetBucketPolicy',
          's3:GetBucketAcl',
          's3:GetBucketPublicAccessBlock',
          's3:GetEncryptionConfiguration',
          's3:GetBucketVersioning',
          's3control:GetPublicAccessBlock',
          'iam:GetAccountSummary',
          'iam:ListRoles',
          'iam:GetRole',
          'iam:ListAttachedRolePolicies',
          'iam:ListRolePolicies',
          'iam:GetRolePolicy',
          'iam:ListPolicies',
          'iam:GetPolicy',
          'iam:GetPolicyVersion',
          'ec2:DescribeRegions',
          'ec2:DescribeSecurityGroups',
          'ec2:DescribeVolumes',
          'ec2:DescribeInstances',
          'rds:DescribeDBInstances',
          'cloudtrail:DescribeTrails',
          'cloudtrail:GetTrailStatus',
        ],
        Resource: '*',
      },
    ],
  };

  const policyJson = JSON.stringify(leastPrivilegePolicy, null, 2);

  const handleCopyPolicy = () => {
    navigator.clipboard.writeText(policyJson);
    setCopiedPolicy(true);
    setTimeout(() => setCopiedPolicy(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header Card */}
      <div className="glass-card p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
              <Cloud className="w-5 h-5 text-sky-400" />
              AWS Connection & Credential Posture
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Verify authenticated identity, read-only guarantees, and least-privilege IAM permissions.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onRefresh}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition"
            >
              Re-verify Connection
            </button>
            <button
              onClick={onOpenNewScan}
              className="px-4 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 text-xs font-bold transition shadow-md shadow-sky-500/20"
            >
              Start Scan
            </button>
          </div>
        </div>
      </div>

      {/* Identity Card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-1 glass-card p-6 flex flex-col justify-between">
          <div>
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-2">
              Connection Status
            </span>
            <div className="flex items-center gap-2.5">
              <div
                className={`w-3 h-3 rounded-full ${
                  status?.connected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                }`}
              />
              <span className="text-base font-bold text-white">
                {status?.connected ? 'Live AWS Authenticated' : 'Demo Sandbox Mode'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">{status?.message}</p>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-xs text-emerald-400">
              <Lock className="w-3.5 h-3.5" />
              <span className="font-semibold">Zero Credential Storage Guarantee</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-normal">
              CloudSentinel relies strictly on the native AWS SDK credential provider chain. No access keys or secrets are collected or saved.
            </p>
          </div>
        </div>

        {/* Identity Details */}
        <div className="md:col-span-2 glass-card p-6">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4">
            STS Caller Identity Details
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
              <span className="text-slate-400 block mb-0.5">Target Account ID</span>
              <span className="font-mono font-bold text-sky-400 text-sm">
                {identity?.account_id || 'N/A'}
              </span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
              <span className="text-slate-400 block mb-0.5">Authentication Method</span>
              <span className="font-semibold text-white">
                {identity?.auth_method || 'Default SDK Chain'}
              </span>
            </div>

            <div className="sm:col-span-2 bg-slate-950 p-3.5 rounded-lg border border-slate-800">
              <span className="text-slate-400 block mb-0.5">Authenticated Principal ARN</span>
              <span className="font-mono text-slate-200 text-xs break-all">
                {identity?.arn || 'Not Connected to Live AWS'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Least Privilege IAM Policy Document */}
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-2">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Least-Privilege Read-Only IAM Policy
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Attach this policy to your auditor IAM role or service user. Only read permissions are requested.
            </p>
          </div>
          <button
            onClick={handleCopyPolicy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition"
          >
            {copiedPolicy ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedPolicy ? 'Copied' : 'Copy Policy JSON'}</span>
          </button>
        </div>

        <pre className="mt-3 bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-sky-300/90 overflow-x-auto max-h-72">
          {policyJson}
        </pre>
      </div>
    </div>
  );
};
