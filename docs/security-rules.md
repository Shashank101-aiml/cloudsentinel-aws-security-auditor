# Security Rules Catalog & Specification

CloudSentinel evaluates deterministic, rule-based security checks across five core AWS services:

| Rule ID | Service | Title | Severity | Confidence | Detection Summary |
|---|---|---|---|---|---|
| **S3-001** | Amazon S3 | Public Bucket Exposure | CRITICAL | CONFIRMED | Detects unconstrained public ACL grants or open bucket policies where Block Public Access is disabled. |
| **S3-002** | Amazon S3 | Block Public Access Disabled | HIGH | CONFIRMED | Flags missing or disabled S3 Block Public Access configurations. |
| **S3-003** | Amazon S3 | Default Server-Side Encryption Missing | HIGH | CONFIRMED | Identifies buckets without default SSE-S3 or SSE-KMS encryption. |
| **S3-004** | Amazon S3 | Versioning Disabled | LOW | CONFIRMED | Identifies buckets where versioning is Suspended or None. |
| **S3-005** | Amazon S3 | Insecure Transport (HTTP) Policy Missing | MEDIUM | CONFIRMED | Flags absence of explicit `aws:SecureTransport: false` deny statements. |
| **IAM-001** | AWS IAM | Full Administrator-Like Privileges | CRITICAL | CONFIRMED | Identifies policies granting `Action: *` across `Resource: *`. |
| **IAM-002** | AWS IAM | Wildcard Action Permissions | MEDIUM | CONFIRMED | Identifies broad service wildcards (e.g. `s3:*`, `iam:*`). |
| **IAM-003** | AWS IAM | Risky Trust Relationships | HIGH | CONFIRMED | Detects IAM role trust policies permitting unconditioned external or wildcard principals. |
| **IAM-005** | AWS IAM | Root Account MFA Disabled | CRITICAL | CONFIRMED/UNKNOWN | Evaluates account summary for root MFA. Returns UNKNOWN if permission is missing. |
| **EC2-001** | Amazon EC2 | Public SSH Exposure (Port 22) | CRITICAL | CONFIRMED | Ingress rules allowing TCP 22 from `0.0.0.0/0` or `::/0`. |
| **EC2-002** | Amazon EC2 | Public RDP Exposure (Port 3389) | CRITICAL | CONFIRMED | Ingress rules allowing TCP 3389 from `0.0.0.0/0` or `::/0`. |
| **EC2-003** | Amazon EC2 | Sensitive Port Public Ingress | HIGH | CONFIRMED | Public ingress to databases or legacy protocols (FTP, Telnet, MySQL, Postgres, Redis). |
| **EC2-004** | Amazon EC2 | Unencrypted EBS Storage Volumes | HIGH | CONFIRMED | Inspects EBS volumes with `encrypted == False`. |
| **EC2-005** | Amazon EC2 | Public IPv4 Address Assigned | INFO | CONFIRMED | Identifies instances directly reachable via public IPv4 addresses. |
| **RDS-001** | Amazon RDS | Publicly Accessible Database Instance | CRITICAL | CONFIRMED | Flags RDS instances with `PubliclyAccessible = True`. |
| **RDS-002** | Amazon RDS | Database Storage Encryption Disabled | HIGH | CONFIRMED | Detects unencrypted database storage volumes. |
| **RDS-003** | Amazon RDS | Insufficient Backup Retention Period | MEDIUM/HIGH | CONFIRMED | Retention period set to 0 (High) or below 7 days (Medium). |
| **LOG-001** | AWS CloudTrail | CloudTrail Logging Not Configured | CRITICAL | CONFIRMED | Identifies absence of any CloudTrail trail in the account scope. |
| **LOG-002** | AWS CloudTrail | Trail Not Actively Logging | CRITICAL | CONFIRMED | Flags trails where `IsLogging == False`. |
| **LOG-003** | AWS CloudTrail | Multi-Region Coverage Disabled | MEDIUM | CONFIRMED | Flags single-region trails leaving other AWS regions unmonitored. |
| **LOG-004** | AWS CloudTrail | Log File Integrity Validation Disabled | MEDIUM | CONFIRMED | Flags trails without cryptographic log file integrity validation. |

---

## Risk Scoring Formula

The overall scan risk score ($0.0 - 100.0$) is calculated using an asymptotic saturation function:

$$\text{Weighted Sum} = 10 \cdot N_{\text{crit}} + 7 \cdot N_{\text{high}} + 4 \cdot N_{\text{med}} + 2 \cdot N_{\text{low}} + 0 \cdot N_{\text{info}}$$

$$\text{Risk Score} = \min\left(100.0, 100 \cdot \left(1 - e^{-\frac{\text{Weighted Sum}}{35}}\right)\right)$$

This formula ensures:
- A clean scan ($0$ findings) yields an exact score of **$0.0$**.
- A single critical vulnerability yields an elevated score of **$25.0$**.
- Multiple critical and high findings approach **$100.0$** smoothly without integer overflows.
- Scores are completely reproducible and deterministic.
