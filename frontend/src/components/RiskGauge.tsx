import React from 'react';

interface RiskGaugeProps {
  score: number;
  totalFindings: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, totalFindings }) => {
  const getColor = () => {
    if (score >= 70) return { text: 'text-red-500', stroke: '#ef4444', label: 'CRITICAL RISK', bg: 'bg-red-500/10' };
    if (score >= 40) return { text: 'text-amber-500', stroke: '#f59e0b', label: 'ELEVATED RISK', bg: 'bg-amber-500/10' };
    if (score > 0) return { text: 'text-sky-500', stroke: '#0ea5e9', label: 'MODERATE RISK', bg: 'bg-sky-500/10' };
    return { text: 'text-emerald-500', stroke: '#10b981', label: 'LOW RISK', bg: 'bg-emerald-500/10' };
  };

  const { text, stroke, label, bg } = getColor();
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center p-6 glass-card relative overflow-hidden">
      <div className="relative flex items-center justify-center">
        <svg className="w-40 h-40 transform -rotate-90">
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="#1e293b"
            strokeWidth="12"
            fill="transparent"
          />
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke={stroke}
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        <div className="absolute flex flex-col items-center">
          <span className={`text-4xl font-extrabold tracking-tight ${text}`}>
            {score.toFixed(1)}
          </span>
          <span className="text-xs uppercase text-slate-400 font-medium tracking-wider">
            / 100
          </span>
        </div>
      </div>

      <div className={`mt-4 px-3 py-1 rounded-full text-xs font-bold tracking-wider ${text} ${bg} border border-current/20`}>
        {label}
      </div>

      <p className="mt-2 text-xs text-slate-400 text-center max-w-[220px]">
        {score === 0
          ? 'No active security risk violations identified.'
          : `Calculated from ${totalFindings} observed findings and affected resources.`}
      </p>
    </div>
  );
};
