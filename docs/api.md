# CloudSentinel REST API Reference

The backend provides a versioned REST API mounted under `/api/v1`.

Interactive Swagger documentation is available locally at:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **OpenAPI Schema**: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

---

## Endpoints Summary

### Health
- `GET /api/v1/health`: Returns service health status, application version, and UTC timestamp.

### AWS Connection & Identity
- `GET /api/v1/aws/connection-status`: Returns connection mode (`live` or `demo_only`), target account ID, and verification message.
- `GET /api/v1/aws/identity`: Calls STS `GetCallerIdentity` to resolve authenticated principal ARN and account ID without exposing secrets.
- `GET /api/v1/aws/regions`: Returns list of available AWS regions.

### Scans Management
- `POST /api/v1/scans`: Initiates an audit scan.
  ```json
  {
    "mode": "demo",
    "regions": ["us-east-1"],
    "services": ["s3", "iam", "ec2", "rds", "cloudtrail"],
    "confirm_real_scan": false
  }
  ```
- `GET /api/v1/scans`: Lists past scans with pagination (`limit`, `offset`).
- `GET /api/v1/scans/{scan_id}`: Retrieves comprehensive details and findings for a scan.
- `GET /api/v1/scans/{scan_id}/summary`: Retrieves high-level risk score and severity counts.
- `GET /api/v1/scans/{scan_id}/findings`: Queries findings with filter parameters (`severity`, `service`, `status`, `region`, `search`, `limit`, `offset`).
- `POST /api/v1/scans/{scan_id}/cancel`: Safely cancels a queued or running scan.
- `GET /api/v1/scans/compare/{baseline_id}/{comparison_id}`: Calculates drift between two scans (new, persistent, resolved findings).

### Findings Review
- `GET /api/v1/findings/{finding_id}`: Retrieves discrete finding details and evidence.
- `PATCH /api/v1/findings/{finding_id}/status`: Updates finding status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `ACCEPTED_RISK`). Note: Only modifies local application records.

### Report Generation
- `GET /api/v1/scans/{scan_id}/report.json`: Download complete scan data as JSON.
- `GET /api/v1/scans/{scan_id}/report.csv`: Download CSV report sanitized against formula injection.
- `GET /api/v1/scans/{scan_id}/report.html`: Download standalone HTML security audit report.

### Demo
- `POST /api/v1/demo/reset`: Resets demo data back to deterministic baseline.
