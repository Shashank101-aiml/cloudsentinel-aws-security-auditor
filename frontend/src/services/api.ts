import {
  ScanSummary,
  ScanDetail,
  Finding,
  AWSIdentity,
  AWSConnectionStatus,
  ScanComparison,
  FindingStatus,
} from '../types';

const API_BASE = '/api/v1';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!res.ok) {
    let errorMsg = `API Error ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // fallback
    }
    throw new ApiError(res.status, errorMsg);
  }

  return res.json();
}

export const api = {
  // Health
  getHealth: () => request<{ status: string; app_name: string; version: string }>('/health'),

  // AWS
  getConnectionStatus: (profile?: string) =>
    request<AWSConnectionStatus>(`/aws/connection-status${profile ? `?profile=${profile}` : ''}`),
  getIdentity: (profile?: string, roleArn?: string) => {
    const params = new URLSearchParams();
    if (profile) params.append('profile', profile);
    if (roleArn) params.append('assume_role_arn', roleArn);
    const qs = params.toString() ? `?${params.toString()}` : '';
    return request<AWSIdentity>(`/aws/identity${qs}`);
  },
  getRegions: (profile?: string) =>
    request<{ regions: string[]; default_region: string }>(`/aws/regions${profile ? `?profile=${profile}` : ''}`),

  // Scans
  startScan: (payload: {
    mode: 'demo' | 'real';
    regions: string[];
    services: string[];
    profile?: string;
    assume_role_arn?: string;
    confirm_real_scan?: boolean;
  }) =>
    request<ScanSummary>('/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  listScans: (limit = 20, offset = 0) =>
    request<{ total: number; items: ScanSummary[] }>(`/scans?limit=${limit}&offset=${offset}`),

  getScan: (scanId: string) => request<ScanDetail>(`/scans/${scanId}`),

  getScanFindings: (
    scanId: string,
    params?: {
      severity?: string;
      service?: string;
      status?: string;
      region?: string;
      search?: string;
      limit?: number;
      offset?: number;
    }
  ) => {
    const qs = new URLSearchParams();
    if (params?.severity) qs.append('severity', params.severity);
    if (params?.service) qs.append('service', params.service);
    if (params?.status) qs.append('status', params.status);
    if (params?.region) qs.append('region', params.region);
    if (params?.search) qs.append('search', params.search);
    if (params?.limit) qs.append('limit', params.limit.toString());
    if (params?.offset) qs.append('offset', params.offset.toString());
    const query = qs.toString() ? `?${qs.toString()}` : '';
    return request<{ scan_id: string; total: number; findings: Finding[] }>(`/scans/${scanId}/findings${query}`);
  },

  cancelScan: (scanId: string) =>
    request<{ message: string; status: string }>(`/scans/${scanId}/cancel`, { method: 'POST' }),

  compareScans: (baselineId: string, comparisonId: string) =>
    request<ScanComparison>(`/scans/compare/${baselineId}/${comparisonId}`),

  // Findings
  getFinding: (findingId: string) => request<Finding>(`/findings/${findingId}`),
  updateFindingStatus: (findingId: string, status: FindingStatus) =>
    request<Finding>(`/findings/${findingId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),

  // Reports
  getReportJsonUrl: (scanId: string) => `${API_BASE}/scans/${scanId}/report.json`,
  getReportCsvUrl: (scanId: string) => `${API_BASE}/scans/${scanId}/report.csv`,
  getReportHtmlUrl: (scanId: string) => `${API_BASE}/scans/${scanId}/report.html`,

  // Demo
  resetDemoData: () => request<ScanSummary>('/demo/reset', { method: 'POST' }),
};
