# CloudSentinel — System Architecture

CloudSentinel is an enterprise-grade cloud security and compliance auditing platform built with Python (FastAPI) and React (TypeScript + Vite + Tailwind CSS).

The platform operates on a fundamental principle: **read-only auditing by default, evidence-based findings, zero credential storage, and no automatic mutations of AWS resources.**

---

## 1. High-Level Architecture Diagram

```mermaid
graph TD
    subgraph Frontend["Frontend Client (React + TypeScript + Vite)"]
        UI["SOC Dashboard UI"]
        FindingsExp["Findings Explorer & Detail Modals"]
        AuditControls["Scan Orchestration & Mode Selector"]
        ReportsUI["Multi-Format Report Generator (JSON/CSV/HTML)"]
        ApiClient["Typed REST API Client (Fetch)"]
        UI --> ApiClient
        FindingsExp --> ApiClient
        AuditControls --> ApiClient
        ReportsUI --> ApiClient
    end

    subgraph Backend["FastAPI REST Backend"]
        FastAPIApp["FastAPI Application (/api/v1)"]
        AuthMiddleware["CORS & Origin Filtering Middleware"]
        Lifespan["Lifecycle & Schema Initializer"]
        
        FastAPIApp --> AuthMiddleware
        FastAPIApp --> Lifespan

        subgraph Engine["Deterministic Security Engine"]
            CollectorMgr["AWS Read-Only Collectors Manager"]
            RuleRegistry["Rule Registry & Catalog (18+ Rules)"]
            Sanitizer["Evidence & Log Sanitizer (Secret Redaction)"]
            RiskScorer["Asymptotic Risk Scorer (0 - 100 Scale)"]
            Orchestrator["Scan Orchestrator (Pass / Fail / Skip Tracker)"]
            
            Orchestrator --> CollectorMgr
            Orchestrator --> RuleRegistry
            Orchestrator --> Sanitizer
            Orchestrator --> RiskScorer
        end

        subgraph Storage["Persistence Layer"]
            DB[(SQLite / PostgreSQL)]
            ORM["SQLAlchemy 2.x ORM Models (Scans, Findings)"]
            Migrations["Alembic Migrations"]
            DB --- ORM
        end

        FastAPIApp --> Orchestrator
        FastAPIApp --> ORM
    end

    subgraph AWS["AWS Cloud Target (Read-Only)"]
        STS["AWS STS (GetCallerIdentity)"]
        S3["Amazon S3 (Buckets, Policies, ACLs, SSE)"]
        IAM["AWS IAM (Policies, Roles, Trust, Root MFA)"]
        EC2["Amazon EC2 & VPC (Security Groups, EBS, Instances)"]
        RDS["Amazon RDS (Instances, Encryption, Backups)"]
        CloudTrail["AWS CloudTrail (Trails, Logging Status, Integrity)"]
        
        CollectorMgr -.->|Read-Only Boto3 API Calls| STS
        CollectorMgr -.->|Read-Only Boto3 API Calls| S3
        CollectorMgr -.->|Read-Only Boto3 API Calls| IAM
        CollectorMgr -.->|Read-Only Boto3 API Calls| EC2
        CollectorMgr -.->|Read-Only Boto3 API Calls| RDS
        CollectorMgr -.->|Read-Only Boto3 API Calls| CloudTrail
    end
```

---

## 2. Component Breakdown

### Frontend (React + TypeScript)
- **Vite Bundler**: Provides fast Hot Module Replacement during development and optimized static asset chunking for production.
- **Tailwind CSS**: Custom dark cybersecurity SOC styling with accessible contrast ratios and dynamic glowing status pills.
- **Typed API Client**: Handles REST communication with `/api/v1`, manages request error normalization, and supports report downloads.
- **Asynchronous Polling**: Tracks in-flight scans with automatic state synchronization.

### Backend (FastAPI + SQLAlchemy)
- **Asynchronous REST Handlers**: Stateless request handlers supporting background scan dispatching.
- **Deterministic Evaluation**: Rules are decoupled from AWS network communication, enabling 100% offline unit testability.
- **Sanitization Layer**: Recursively scans all evidence payloads and redacts secrets, keys, and tokens.
- **Formula Injection Prevention**: Prepends single quotes to dangerous spreadsheet formula characters (`=`, `+`, `-`, `@`) in CSV exports.

### AWS SDK Layer (Boto3)
- Strictly invokes read-only actions (`Describe*`, `Get*`, `List*`).
- Never requests write, mutate, delete, or create permissions.
- Bounded adaptive retry configuration with jitter for transient API throttling.
