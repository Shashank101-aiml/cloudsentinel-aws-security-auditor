import React from 'react';
import {
  Shield,
  LayoutDashboard,
  Search,
  Cloud,
  History,
  BookOpen,
  RotateCcw,
  PlusCircle,
  Radio,
} from 'lucide-react';
import { AWSConnectionStatus, ScanSummary } from '../types';

interface NavbarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  activeScan: ScanSummary | null;
  awsStatus: AWSConnectionStatus | null;
  onOpenNewScan: () => void;
  onResetDemo: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  activeScan,
  awsStatus,
  onOpenNewScan,
  onResetDemo,
}) => {
  const isDemo = activeScan?.scan_mode === 'demo';

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'findings', label: 'Findings Explorer', icon: Search },
    { id: 'aws', label: 'AWS Connection', icon: Cloud },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'rules', label: 'Rules Catalog', icon: BookOpen },
  ];

  return (
    <header className="sticky top-0 z-40 bg-slate-900/90 backdrop-blur-md border-b border-slate-800">
      {/* Persistent Demo Warning Banner */}
      {isDemo && (
        <div className="bg-amber-500/10 border-b border-amber-500/20 px-4 py-1.5 text-xs text-amber-300 font-bold flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
            <span>DEMO DATA — NOT A LIVE AWS SCAN</span>
            <span className="text-amber-400/80 font-normal hidden sm:inline">
              (Deterministic simulation data for evaluation without AWS credentials)
            </span>
          </div>
          <button
            onClick={onResetDemo}
            className="flex items-center gap-1 text-[11px] bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 px-2 py-0.5 rounded transition"
            title="Reset demo data to deterministic baseline"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset Demo Baseline</span>
          </button>
        </div>
      )}

      {/* Main Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setCurrentTab('dashboard')}>
            <div className="p-2 rounded-xl bg-sky-500/10 border border-sky-500/30 text-sky-400 shadow-md shadow-sky-500/10">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <span className="font-extrabold text-lg text-white tracking-tight flex items-center gap-1.5">
                CloudSentinel
                <span className="text-[10px] font-bold uppercase tracking-wider bg-sky-950 border border-sky-800 text-sky-400 px-1.5 py-0.5 rounded">
                  v1.0
                </span>
              </span>
              <span className="text-[11px] text-slate-400 block -mt-1">AWS Security & Compliance Auditor</span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map(item => {
              const Icon = item.icon;
              const active = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setCurrentTab(item.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold transition ${
                    active
                      ? 'bg-slate-800 text-sky-400 border border-slate-700 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Right Actions */}
          <div className="flex items-center gap-3">
            {/* Connection Status Pill */}
            <div
              onClick={() => setCurrentTab('aws')}
              className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-950 border border-slate-800 text-xs cursor-pointer hover:border-slate-700 transition"
            >
              <div
                className={`w-2 h-2 rounded-full ${
                  awsStatus?.connected ? 'bg-emerald-400 shadow-sm shadow-emerald-400' : 'bg-sky-400'
                }`}
              />
              <span className="text-slate-300">
                {awsStatus?.connected ? `AWS: ${awsStatus.account_id}` : 'Demo Sandbox'}
              </span>
            </div>

            {/* Start Scan Button */}
            <button
              onClick={onOpenNewScan}
              className="flex items-center gap-1.5 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold px-4 py-2 rounded-lg text-sm shadow-md shadow-sky-500/20 transition active:scale-95"
            >
              <PlusCircle className="w-4 h-4" />
              <span>Start Scan</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
