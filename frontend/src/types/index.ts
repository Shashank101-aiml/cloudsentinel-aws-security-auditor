export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'ACCEPTED_RISK';
export type Confidence = 'CONFIRMED' | 'LIKELY' | 'UNKNOWN';
export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'PARTIAL' | 'FAILED' | 'CANCELLED';

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  service: string;
  resource_id: string;
  resource_type: string;
  region: string | null;
  account_id: string;
  evidence: Record<string, any>;
  remediation: string;
  references: string[];
  first_seen: string;
  last_seen: string;
  created_at?: string;
  updated_at?: string;
}

export interface ScanSummary {
  id: string;
  account_id: string;
  scan_mode: 'demo' | 'real';
  status: ScanStatus;
  risk_score: number;
  total_resources_inspected: number;
  checks_passed: number;
  checks_failed: number;
  checks_skipped: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message?: string | null;
  skipped_reasons: Record<string, string>;
  started_at: string;
  completed_at?: string | null;
}

export interface ScanDetail extends ScanSummary {
  regions: string[];
  services: string[];
  findings: Finding[];
}

export interface AWSIdentity {
  account_id: string;
  arn: string;
  user_id: string;
  auth_method: string;
  profile?: string | null;
  role_arn?: string | null;
  is_valid: boolean;
  error?: string | null;
}

export interface AWSConnectionStatus {
  connected: boolean;
  mode: string;
  account_id?: string | null;
  arn?: string | null;
  auth_method?: string | null;
  permissions_verified: boolean;
  message: string;
}

export interface ScanComparison {
  baseline_scan_id: string;
  comparison_scan_id: string;
  new_findings_count: number;
  persistent_findings_count: number;
  disappeared_findings_count: number;
  new_findings: string[];
  persistent_findings: string[];
  disappeared_findings: string[];
}
