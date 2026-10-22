# CloudSentinel Threat Model & Risk Analysis

This threat model outlines the primary risks associated with running an automated AWS cloud security audit tool and documents the defensive controls implemented in CloudSentinel.

---

## 1. Threat Identification & Mitigation Matrix

| Threat Category | Potential Impact | Inherent Risk | Implemented Countermeasures |
|---|---|---|---|
| **Credential Theft / Leakage** | Unauthorized AWS account access | CRITICAL | • Zero credential storage in UI, database, or logs.<br>• Native reliance on AWS CLI profile and IAM role assumption.<br>• Sanitizing logger redacting access keys, tokens, and bearer credentials. |
| **Accidental State Modification** | Destruction or alteration of AWS resources | CRITICAL | • Strict read-only API actions (`Get*`, `List*`, `Describe*`).<br>• No write, delete, update, or create actions.<br>• Least-privilege IAM policy without mutation permissions. |
| **CSV Formula Injection (DDE)** | Remote code execution on analyst spreadsheet | HIGH | • `Sanitizer.sanitize_csv_cell` prepends a single quote `'` to any cell value starting with `=`, `+`, `-`, `@`, `\t`, or `\r`. |
| **Cross-Site Scripting (XSS)** | UI compromise via untrusted AWS tags or names | HIGH | • Safe HTML escaping in HTML report exports (`Sanitizer.escape_html`).<br>• React automatic JSX string escaping for all UI elements. |
| **Unauthorized Scanning** | Unintended cloud API quota exhaustion | MEDIUM | • Explicit user confirmation required (`confirm_real_scan=true`).<br>• Display of target account ID and principal ARN before scan trigger. |
| **Data Bleed Between Accounts** | Mixing demo and real scan findings | MEDIUM | • Strict isolation of demo findings.<br>• Scans table partitioned with discrete UUIDs and foreign key constraints. |
| **API Throttling & DoS** | AWS rate limits exceeded | MEDIUM | • Adaptive retry policy with bounded exponential backoff and jitter.<br>• Regional scoping and limit on concurrent requests. |

---

## 2. Trust Boundaries

1. **User Browser $\leftrightarrow$ CloudSentinel FastAPI Backend**:
   Protected by strict CORS origin policies. No AWS secrets traverse this boundary.
2. **FastAPI Backend $\leftrightarrow$ AWS STS / Cloud APIs**:
   Secured via TLS 1.3. Boto3 client verifies AWS CA certificates.
3. **Database Layer (SQLite / PostgreSQL)**:
   Stored locally or in an isolated private container volume. Only contains scan metadata and sanitized evidence.
