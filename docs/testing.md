# Testing & Quality Assurance Guide

CloudSentinel includes a multi-tiered automated test suite ensuring high reliability, test coverage, and security hygiene.

---

## 1. Running Backend Tests

Backend tests execute 100% offline using in-memory databases and deterministic rule evaluations without requiring AWS access or network connectivity.

```bash
# Activate virtual environment
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate

# Navigate to backend directory
cd backend

# Run all pytest suites with verbose output
pytest -v

# Run with test coverage report
pytest --cov=app --cov-report=term-missing
```

### Test Scope
- **`tests/test_rules/`**: Unit tests for all 18+ security rules across S3, IAM, EC2, RDS, and CloudTrail (both positive misconfiguration and negative compliant cases).
- **`tests/test_engine/`**: Verification of the risk scoring formula, zero-score edge cases, evidence sanitization, and CSV formula injection prevention.
- **`tests/test_api/`**: Integration tests across all FastAPI endpoints using Starlette `TestClient`.

---

## 2. Static Analysis & Linting

### Ruff Linter
```bash
cd backend
ruff check app/ tests/
```

### Bandit Security Linter
```bash
cd backend
bandit -r app/ -ll
```

---

## 3. Frontend Build & Typecheck

```bash
cd frontend

# Install dependencies
npm ci

# Run TypeScript compile & Vite build
npm run build
```
