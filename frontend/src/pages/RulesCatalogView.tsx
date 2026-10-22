import React from 'react';
import { BookOpen, ExternalLink, ShieldCheck } from 'lucide-react';
import { SeverityBadge } from '../components/SeverityBadge';
import { Severity } from '../types';

interface SecurityRuleInfo {
  id: string;
  service: string;
  title: string;
  severity: Severity;
  description: string;
  detection: string;
  remediation: string;
  docs: string;
}

export const RulesCatalogView: React.FC = () => {
  const rules: SecurityRuleInfo[] = [
    // S3
    {
      id: 'S3-001',
      service: 'Amazon S3',
      title: 'Public Bucket Exposure',
      severity: 'CRITICAL',
      description: 'Detects S3 buckets with public ACL grants (AllUsers, AuthenticatedUsers) or unconditioned wildcard bucket policies.',
      detection: 'Inspects bucket ACLs and policies against effective Block Public Access settings.',
      remediation: 'Enable S3 Block Public Access and remove public read/write grants.',
      docs: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
    },
    {
      id: 'S3-002',
      service: 'Amazon S3',
      title: 'Block Public Access Disabled',
      severity: 'HIGH',
      description: 'Flags buckets where any of the 4 S3 Block Public Access settings are missing or disabled.',
      detection: 'Inspects BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.',
      remediation: 'Enable all four S3 Block Public Access flags at the bucket or account level.',
      docs: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
    },
    {
      id: 'S3-003',
      service: 'Amazon S3',
      title: 'Server-Side Encryption Disabled',
      severity: 'HIGH',
      description: 'Detects buckets lacking default encryption (SSE-S3 or SSE-KMS).',
      detection: 'Checks GetBucketEncryption configuration for default encryption rules.',
      remediation: 'Configure default SSE-S3 or SSE-KMS on the bucket.',
      docs: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html',
    },
    {
      id: 'S3-004',
      service: 'Amazon S3',
      title: 'Versioning Disabled',
      severity: 'LOW',
      description: 'Flags buckets where object versioning is Suspended or None, increasing accidental deletion risk.',
      detection: 'Checks GetBucketVersioning status.',
      remediation: 'Enable versioning and establish lifecycle rules for noncurrent versions.',
      docs: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html',
    },
    {
      id: 'S3-005',
      service: 'Amazon S3',
      title: 'Insecure Transport (HTTP) Policy Missing',
      severity: 'MEDIUM',
      description: 'Checks if bucket policy lacks an explicit deny statement for non-HTTPS connections.',
      detection: 'Inspects policy statements for aws:SecureTransport: false deny conditions.',
      remediation: 'Add bucket policy denying s3:* requests when aws:SecureTransport is false.',
      docs: 'https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule-s3-bucket-ssl-requests-only/',
    },

    // IAM
    {
      id: 'IAM-001',
      service: 'AWS IAM',
      title: 'Administrator-Like Privileges',
      severity: 'CRITICAL',
      description: 'Detects policies allowing Action: * across Resource: *.',
      detection: 'Analyzes policy statements for unconstrained action and resource wildcards.',
      remediation: 'Scope down policies to only required service actions and resource ARNs.',
      docs: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege',
    },
    {
      id: 'IAM-002',
      service: 'AWS IAM',
      title: 'Wildcard Action Permissions',
      severity: 'MEDIUM',
      description: 'Detects broad wildcard action permissions within services (e.g. s3:*, iam:*).',
      detection: 'Identifies action elements containing wildcards.',
      remediation: 'Replace wildcard actions with discrete API calls.',
      docs: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html',
    },
    {
      id: 'IAM-003',
      service: 'AWS IAM',
      title: 'Risky Trust Relationships',
      severity: 'HIGH',
      description: 'Inspects role trust policies for unconstrained Principals (* or wildcard AWS accounts).',
      detection: 'Evaluates AssumeRolePolicyDocument for unconditioned external principals.',
      remediation: 'Restrict trust policy principals to explicit accounts and roles.',
      docs: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#trust-policy',
    },
    {
      id: 'IAM-005',
      service: 'AWS IAM',
      title: 'Root Account MFA Disabled',
      severity: 'CRITICAL',
      description: 'Verifies that Multi-Factor Authentication is enabled on the AWS root user account.',
      detection: 'Evaluates IAM GetAccountSummary AccountMFAEnabled field.',
      remediation: 'Enable hardware or virtual MFA on the AWS root account.',
      docs: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html',
    },

    // EC2
    {
      id: 'EC2-001',
      service: 'Amazon EC2',
      title: 'Public SSH Exposure (Port 22)',
      severity: 'CRITICAL',
      description: 'Detects security group ingress rules permitting TCP 22 from 0.0.0.0/0 or ::/0.',
      detection: 'Inspects IpPermissions for port 22 and public CIDR ranges.',
      remediation: 'Restrict SSH to corporate bastion CIDRs or use AWS Systems Manager Session Manager.',
      docs: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html#sg-rules-ssh',
    },
    {
      id: 'EC2-002',
      service: 'Amazon EC2',
      title: 'Public RDP Exposure (Port 3389)',
      severity: 'CRITICAL',
      description: 'Detects security group ingress rules permitting TCP 3389 from the public internet.',
      detection: 'Inspects IpPermissions for port 3389 and public CIDR ranges.',
      remediation: 'Restrict RDP access to trusted network gateways or VPN tunnels.',
      docs: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html#sg-rules-rdp',
    },
    {
      id: 'EC2-003',
      service: 'Amazon EC2',
      title: 'Broad Sensitive-Port Exposure',
      severity: 'HIGH',
      description: 'Identifies open public ingress on sensitive ports (FTP, Telnet, MySQL, Postgres, Redis, etc.).',
      detection: 'Matches ingress rules against high-risk service port catalog.',
      remediation: 'Close sensitive ports to 0.0.0.0/0 and place databases in private subnets.',
      docs: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    },
    {
      id: 'EC2-004',
      service: 'Amazon EC2',
      title: 'Unencrypted EBS Volumes',
      severity: 'HIGH',
      description: 'Detects EBS storage volumes that are not encrypted at rest.',
      detection: 'Inspects DescribeVolumes encrypted attribute.',
      remediation: 'Enable account EBS default encryption and migrate unencrypted volumes.',
      docs: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    },
    {
      id: 'EC2-005',
      service: 'Amazon EC2',
      title: 'Public IPv4 Exposure',
      severity: 'INFO',
      description: 'Contextual observation identifying instances with directly reachable public IPv4 addresses.',
      detection: 'Checks DescribeInstances PublicIpAddress presence.',
      remediation: 'Move backend instances to private subnets behind load balancers.',
      docs: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html',
    },

    // RDS
    {
      id: 'RDS-001',
      service: 'Amazon RDS',
      title: 'Publicly Accessible Database',
      severity: 'CRITICAL',
      description: 'Flags database instances configured with PubliclyAccessible = true.',
      detection: 'Inspects DescribeDBInstances PubliclyAccessible flag and endpoint configuration.',
      remediation: 'Modify database to disable PubliclyAccessible and route via private VPC subnets.',
      docs: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html',
    },
    {
      id: 'RDS-002',
      service: 'Amazon RDS',
      title: 'Storage Encryption Disabled',
      severity: 'HIGH',
      description: 'Detects RDS database instances with unencrypted storage.',
      detection: 'Checks StorageEncrypted boolean.',
      remediation: 'Encrypt by copying snapshot with KMS enabled and restoring.',
      docs: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    },
    {
      id: 'RDS-003',
      service: 'Amazon RDS',
      title: 'Insufficient Backup Retention',
      severity: 'MEDIUM',
      description: 'Flags databases with backup retention period set to 0 or below 7 days.',
      detection: 'Evaluates BackupRetentionPeriod against recommended 7-day minimum.',
      remediation: 'Increase automated backup retention to at least 7 days.',
      docs: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
    },

    // CloudTrail
    {
      id: 'LOG-001',
      service: 'AWS CloudTrail',
      title: 'CloudTrail Logging Not Configured',
      severity: 'CRITICAL',
      description: 'Identifies absence of an active CloudTrail trail in the account scope.',
      detection: 'Checks DescribeTrails results.',
      remediation: 'Create an organizational or multi-region trail logging all management events.',
      docs: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html',
    },
    {
      id: 'LOG-002',
      service: 'AWS CloudTrail',
      title: 'Trail Not Actively Logging',
      severity: 'CRITICAL',
      description: 'Detects trails where logging is currently paused or inactive.',
      detection: 'Calls GetTrailStatus to inspect IsLogging state.',
      remediation: 'Enable logging via the AWS Console or aws cloudtrail start-logging.',
      docs: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-turning-off-logging.html',
    },
    {
      id: 'LOG-003',
      service: 'AWS CloudTrail',
      title: 'Multi-Region Logging Disabled',
      severity: 'MEDIUM',
      description: 'Detects single-region trails leaving other AWS regions unmonitored.',
      detection: 'Checks IsMultiRegionTrail boolean.',
      remediation: 'Update trail configuration to apply to all regions.',
      docs: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html',
    },
    {
      id: 'LOG-004',
      service: 'AWS CloudTrail',
      title: 'Log File Validation Disabled',
      severity: 'MEDIUM',
      description: 'Flags trails without cryptographic log file integrity validation.',
      detection: 'Checks LogFileValidationEnabled boolean.',
      remediation: 'Enable log file validation to produce signed digest files.',
      docs: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html',
    },
  ];

  return (
    <div className="space-y-6 pb-12">
      <div className="glass-card p-6">
        <div className="flex items-center gap-2.5">
          <BookOpen className="w-5 h-5 text-sky-400" />
          <h1 className="text-xl font-bold text-white tracking-wide">Security Rules Catalog</h1>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          CloudSentinel implements deterministic, evidence-based security auditing rules across 5 core AWS services.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map(rule => (
          <div key={rule.id} className="glass-card p-5 space-y-3 flex flex-col justify-between">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-xs bg-slate-800 text-sky-400 px-2 py-0.5 rounded border border-slate-700">
                    {rule.id}
                  </span>
                  <span className="text-[11px] font-semibold uppercase text-slate-400">
                    {rule.service}
                  </span>
                </div>
                <SeverityBadge severity={rule.severity} />
              </div>

              <h2 className="text-sm font-bold text-white">{rule.title}</h2>
              <p className="text-xs text-slate-300 leading-relaxed">{rule.description}</p>
            </div>

            <div className="pt-3 border-t border-slate-800/80 space-y-2 text-xs">
              <div className="text-slate-400">
                <strong className="text-slate-300">Detection Logic:</strong> {rule.detection}
              </div>
              <div className="text-emerald-300/90 bg-emerald-950/20 p-2 rounded border border-emerald-900/40">
                <strong className="text-emerald-300">Remediation:</strong> {rule.remediation}
              </div>
              <a
                href={rule.docs}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:underline pt-1"
              >
                <ExternalLink className="w-3 h-3" />
                AWS Best Practices Documentation
              </a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
