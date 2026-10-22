import React, { useState, useMemo } from 'react';
import { Search, Filter, ShieldAlert, ArrowUpDown } from 'lucide-react';
import { Finding } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

interface FindingsViewProps {
  findings: Finding[];
  onOpenFinding: (finding: Finding) => void;
  initialFilters?: {
    severity?: string;
    service?: string;
  };
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  onOpenFinding,
  initialFilters,
}) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>(initialFilters?.severity || 'ALL');
  const [serviceFilter, setServiceFilter] = useState<string>(initialFilters?.service || 'ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      // Search term
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase();
        const matches =
          f.title.toLowerCase().includes(query) ||
          f.rule_id.toLowerCase().includes(query) ||
          f.resource_id.toLowerCase().includes(query) ||
          f.description.toLowerCase().includes(query);
        if (!matches) return false;
      }

      // Severity
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) {
        return false;
      }

      // Service
      if (serviceFilter !== 'ALL' && f.service.toLowerCase() !== serviceFilter.toLowerCase()) {
        return false;
      }

      // Status
      if (statusFilter !== 'ALL' && f.status !== statusFilter) {
        return false;
      }

      return true;
    });
  }, [findings, searchTerm, severityFilter, serviceFilter, statusFilter]);

  return (
    <div className="space-y-6 pb-12">
      {/* Header & Filter Controls */}
      <div className="glass-card p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h1 className="text-xl font-bold text-white tracking-wide">Findings Explorer</h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspecting {filteredFindings.length} of {findings.length} total discovered issues
            </p>
          </div>
        </div>

        {/* Filters Row */}
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search title, rule ID, resource..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          {/* Severity */}
          <div>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Informational</option>
            </select>
          </div>

          {/* Service */}
          <div>
            <select
              value={serviceFilter}
              onChange={e => setServiceFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All AWS Services</option>
              <option value="s3">Amazon S3</option>
              <option value="iam">AWS IAM</option>
              <option value="ec2">Amazon EC2 & VPC</option>
              <option value="rds">Amazon RDS</option>
              <option value="cloudtrail">AWS CloudTrail</option>
            </select>
          </div>

          {/* Status */}
          <div>
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
              <option value="ACCEPTED_RISK">Accepted Risk</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="glass-card overflow-hidden">
        {filteredFindings.length === 0 ? (
          <div className="py-16 text-center text-slate-400 space-y-2">
            <ShieldAlert className="w-10 h-10 mx-auto text-slate-600" />
            <div className="font-semibold text-slate-300">No matching findings identified</div>
            <div className="text-xs text-slate-500">Try adjusting your filters or search keywords.</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase font-semibold text-[10px] tracking-wider">
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Rule</th>
                  <th className="py-3 px-4">Finding Name</th>
                  <th className="py-3 px-4">Service</th>
                  <th className="py-3 px-4">Target Resource</th>
                  <th className="py-3 px-4">Region</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-medium text-slate-200">
                {filteredFindings.map(f => (
                  <tr
                    key={f.id}
                    onClick={() => onOpenFinding(f)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-3 px-4">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-sky-400">{f.rule_id}</td>
                    <td className="py-3 px-4 max-w-xs font-semibold text-white truncate">
                      {f.title}
                    </td>
                    <td className="py-3 px-4 uppercase text-slate-300">{f.service}</td>
                    <td className="py-3 px-4 font-mono max-w-xs truncate text-slate-300">
                      {f.resource_id}
                    </td>
                    <td className="py-3 px-4 text-slate-400">{f.region || 'global'}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300 border border-slate-700">
                        {f.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onOpenFinding(f);
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-300 font-semibold border border-slate-700 transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
