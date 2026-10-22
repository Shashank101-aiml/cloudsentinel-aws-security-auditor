import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardView } from './pages/DashboardView';
import { FindingsView } from './pages/FindingsView';
import { AWSConnectionView } from './pages/AWSConnectionView';
import { HistoryView } from './pages/HistoryView';
import { RulesCatalogView } from './pages/RulesCatalogView';
import { ScanConfigModal } from './components/ScanConfigModal';
import { FindingDetailModal } from './components/FindingDetailModal';
import { ScanSummary, Finding, AWSConnectionStatus, AWSIdentity } from './types';
import { api } from './services/api';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [activeScan, setActiveScan] = useState<ScanSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scansList, setScansList] = useState<ScanSummary[]>([]);
  const [awsStatus, setAwsStatus] = useState<AWSConnectionStatus | null>(null);
  const [awsIdentity, setAwsIdentity] = useState<AWSIdentity | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isConfigOpen, setIsConfigOpen] = useState<boolean>(false);
  const [findingsFilter, setFindingsFilter] = useState<{ severity?: string; service?: string }>({});
  const [loading, setLoading] = useState<boolean>(true);

  // Load initial scans and active scan findings
  const loadData = useCallback(async () => {
    try {
      const scansRes = await api.listScans(20, 0);
      setScansList(scansRes.items);

      if (scansRes.items.length > 0) {
        const topScan = scansRes.items[0];
        setActiveScan(topScan);

        const findingsRes = await api.getScanFindings(topScan.id, { limit: 100 });
        setFindings(findingsRes.findings);
      }

      const conn = await api.getConnectionStatus();
      setAwsStatus(conn);

      if (conn.connected) {
        const idRes = await api.getIdentity();
        setAwsIdentity(idRes);
      }
    } catch (err) {
      console.error('Failed to load application data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Polling when active scan is running
  useEffect(() => {
    if (!activeScan || (activeScan.status !== 'QUEUED' && activeScan.status !== 'RUNNING')) {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const updated = await api.getScan(activeScan.id);
        setActiveScan(updated);
        setFindings(updated.findings);
        if (updated.status !== 'QUEUED' && updated.status !== 'RUNNING') {
          clearInterval(interval);
          const listRes = await api.listScans(20, 0);
          setScansList(listRes.items);
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeScan]);

  const handleSelectScan = async (scanId: string) => {
    setLoading(true);
    try {
      const scanDetail = await api.getScan(scanId);
      setActiveScan(scanDetail);
      setFindings(scanDetail.findings);
      setCurrentTab('dashboard');
    } catch (err) {
      console.error('Failed to load selected scan:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleResetDemo = async () => {
    try {
      const res = await api.resetDemoData();
      setActiveScan(res);
      const findingsRes = await api.getScanFindings(res.id, { limit: 100 });
      setFindings(findingsRes.findings);
      const scansRes = await api.listScans(20, 0);
      setScansList(scansRes.items);
      setCurrentTab('dashboard');
    } catch (err) {
      console.error('Failed to reset demo data:', err);
    }
  };

  const handleNavigateTab = (tab: string, filter?: { severity?: string; service?: string }) => {
    if (filter) {
      setFindingsFilter(filter);
    }
    setCurrentTab(tab);
  };

  const handleFindingStatusUpdated = (updated: Finding) => {
    setSelectedFinding(updated);
    setFindings(prev => prev.map(f => (f.id === updated.id ? updated : f)));
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col font-sans">
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        activeScan={activeScan}
        awsStatus={awsStatus}
        onOpenNewScan={() => setIsConfigOpen(true)}
        onResetDemo={handleResetDemo}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-6">
        {loading ? (
          <div className="flex flex-col items-center justify-center p-24 text-slate-400">
            <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin mb-3" />
            <div className="text-sm font-semibold tracking-wide">Initializing CloudSentinel...</div>
          </div>
        ) : (
          <>
            {currentTab === 'dashboard' && (
              <DashboardView
                scan={activeScan}
                findings={findings}
                onNavigateTab={handleNavigateTab}
                onOpenFinding={setSelectedFinding}
                onOpenNewScan={() => setIsConfigOpen(true)}
              />
            )}

            {currentTab === 'findings' && (
              <FindingsView
                findings={findings}
                onOpenFinding={setSelectedFinding}
                initialFilters={findingsFilter}
              />
            )}

            {currentTab === 'aws' && (
              <AWSConnectionView
                status={awsStatus}
                identity={awsIdentity}
                onRefresh={loadData}
                onOpenNewScan={() => setIsConfigOpen(true)}
              />
            )}

            {currentTab === 'history' && (
              <HistoryView
                scans={scansList}
                activeScanId={activeScan?.id || ''}
                onSelectScan={handleSelectScan}
              />
            )}

            {currentTab === 'rules' && <RulesCatalogView />}
          </>
        )}
      </main>

      {/* Scan Configuration Modal */}
      <ScanConfigModal
        isOpen={isConfigOpen}
        onClose={() => setIsConfigOpen(false)}
        onScanStarted={loadData}
      />

      {/* Finding Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onStatusUpdated={handleFindingStatusUpdated}
      />
    </div>
  );
};

export default App;
