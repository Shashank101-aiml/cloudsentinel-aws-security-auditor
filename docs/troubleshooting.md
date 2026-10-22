# Troubleshooting Guide

Common issues, diagnosis steps, and resolution paths for CloudSentinel.

---

## 1. AWS Authentication & Permission Issues

### `NoCredentialsError: Unable to locate credentials`
- **Cause**: No active AWS credentials found in the default AWS SDK chain.
- **Resolution**:
  - Run in **Demo Mode** to test the platform safely without AWS access.
  - Or configure your local AWS profile: `aws configure --profile <name>`.
  - Pass the profile name in the UI when launching a scan.

### `AccessDenied` / `ClientError` during resource collection
- **Cause**: The IAM principal lacks permission for a specific service inspection.
- **Resolution**:
  - Review `docs/aws-setup.md` and attach the least-privilege IAM policy.
  - CloudSentinel records skipped checks in the scan summary under `skipped_reasons` rather than aborting the entire scan.

---

## 2. Local Development & Port Conflicts

### Port 8000 or 5173 Already in Use
- Change `PORT=8001` in `.env`.
- In `frontend/vite.config.ts`, update the proxy target to `http://127.0.0.1:8001`.

### SQLite `database is locked`
- CloudSentinel uses SQLAlchemy with `check_same_thread=False` and standard connection timeouts. Ensure you are not locking the file with an external SQLite GUI tool in write mode.

---

## 3. Docker Issues

### Frontend cannot reach backend inside Docker
- In `docker-compose.yml`, the frontend service uses Nginx to proxy `/api/` requests to `http://backend:8000`. Ensure both containers are attached to the default bridge network.
