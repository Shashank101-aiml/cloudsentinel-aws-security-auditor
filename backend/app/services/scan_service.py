import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models.scan import Scan
from app.models.finding import Finding
from app.schemas.scan import ScanCreateRequest
from app.schemas.finding import FindingFilterParams
from app.engine.orchestrator import ScanOrchestrator
from app.services.demo_service import DemoService
from app.aws.connection import AWSConnectionService
from app.core.logging import logger


class ScanService:
    """Orchestrates scan persistence, background execution, filtering, and comparison."""

    @staticmethod
    def create_scan(db: Session, request: ScanCreateRequest) -> Scan:
        """Initializes a new scan record."""
        account_id = "123456789012"
        if request.mode == "real":
            identity = AWSConnectionService.get_caller_identity(
                profile=request.profile,
                assume_role_arn=request.assume_role_arn,
            )
            if not identity.is_valid:
                raise ValueError(f"Cannot start real scan: {identity.error}")
            account_id = identity.account_id

        scan = Scan(
            id=str(uuid.uuid4()),
            account_id=account_id,
            scan_mode=request.mode,
            status="QUEUED",
            regions=request.regions,
            services=request.services,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def execute_scan(db: Session, scan_id: str, request: ScanCreateRequest) -> Scan:
        """Executes the audit scan synchronously or inside a background task."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return None

        scan.status = "RUNNING"
        db.commit()

        try:
            if request.mode == "demo":
                # Deterministic demo execution
                sample_findings = DemoService.get_sample_findings(scan_id=scan.id)
                from app.engine.risk_scorer import RiskScorer
                scorer = RiskScorer()
                score_res = scorer.calculate(sample_findings, total_resources=18)

                scan.status = "COMPLETED"
                scan.risk_score = score_res["risk_score"]
                scan.total_resources_inspected = 18
                scan.checks_passed = 11
                scan.checks_failed = len(sample_findings)
                scan.checks_skipped = 0
                scan.findings_count = len(sample_findings)
                scan.critical_count = score_res["counts"]["CRITICAL"]
                scan.high_count = score_res["counts"]["HIGH"]
                scan.medium_count = score_res["counts"]["MEDIUM"]
                scan.low_count = score_res["counts"]["LOW"]
                scan.info_count = score_res["counts"]["INFO"]
                scan.completed_at = datetime.now(timezone.utc)

                for f_data in sample_findings:
                    finding_item = dict(f_data)
                    finding_item["id"] = str(uuid.uuid4())
                    db.add(Finding(**finding_item))

                db.commit()
                db.refresh(scan)
                return scan
            else:
                # Real AWS execution
                orchestrator = ScanOrchestrator(
                    account_id=scan.account_id,
                    regions=scan.regions,
                    services=scan.services,
                    profile=request.profile,
                    assume_role_arn=request.assume_role_arn,
                )
                results = orchestrator.run_live_scan()

                scan.status = results["status"]
                scan.risk_score = results["risk_score"]
                scan.total_resources_inspected = results["total_resources_inspected"]
                scan.checks_passed = results["checks_passed"]
                scan.checks_failed = results["checks_failed"]
                scan.checks_skipped = results["checks_skipped"]
                scan.skipped_reasons = results["skipped_reasons"]
                scan.findings_count = len(results["findings"])
                scan.critical_count = results["counts"]["CRITICAL"]
                scan.high_count = results["counts"]["HIGH"]
                scan.medium_count = results["counts"]["MEDIUM"]
                scan.low_count = results["counts"]["LOW"]
                scan.info_count = results["counts"]["INFO"]
                scan.completed_at = datetime.now(timezone.utc)

                now = datetime.now(timezone.utc)
                for f in results["findings"]:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        scan_id=scan.id,
                        rule_id=f["rule_id"],
                        title=f["title"],
                        description=f["description"],
                        severity=f["severity"],
                        status="OPEN",
                        confidence=f.get("confidence", "CONFIRMED"),
                        service=f["service"],
                        resource_id=f["resource_id"],
                        resource_type=f["resource_type"],
                        region=f.get("region"),
                        account_id=f["account_id"],
                        evidence=f.get("evidence", {}),
                        remediation=f["remediation"],
                        references=f.get("references", []),
                        first_seen=now,
                        last_seen=now,
                    )
                    db.add(finding)

                db.commit()
                db.refresh(scan)
                return scan

        except Exception as e:
            logger.error(f"Error during scan {scan_id}: {str(e)}")
            scan.status = "FAILED"
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(scan)
            return scan

    @staticmethod
    def list_scans(db: Session, limit: int = 20, offset: int = 0) -> Tuple[int, List[Scan]]:
        """Lists scans ordered by most recent."""
        total = db.query(Scan).count()
        items = db.query(Scan).order_by(Scan.started_at.desc()).offset(offset).limit(limit).all()
        return total, items

    @staticmethod
    def get_scan(db: Session, scan_id: str) -> Optional[Scan]:
        return db.query(Scan).filter(Scan.id == scan_id).first()

    @staticmethod
    def get_findings_for_scan(
        db: Session,
        scan_id: str,
        filters: FindingFilterParams,
    ) -> Tuple[int, List[Finding]]:
        """Retrieves filterable findings for a specific scan."""
        query = db.query(Finding).filter(Finding.scan_id == scan_id)

        if filters.severity:
            query = query.filter(Finding.severity == filters.severity.upper())
        if filters.service:
            query = query.filter(Finding.service == filters.service.lower())
        if filters.status:
            query = query.filter(Finding.status == filters.status.upper())
        if filters.region:
            query = query.filter(Finding.region == filters.region)
        if filters.search:
            search_pattern = f"%{filters.search}%"
            query = query.filter(
                or_(
                    Finding.title.ilike(search_pattern),
                    Finding.description.ilike(search_pattern),
                    Finding.resource_id.ilike(search_pattern),
                    Finding.rule_id.ilike(search_pattern),
                )
            )

        total = query.count()
        items = query.order_by(Finding.severity.asc(), Finding.created_at.desc()).offset(filters.offset).limit(filters.limit).all()
        return total, items

    @staticmethod
    def update_finding_status(db: Session, finding_id: str, new_status: str) -> Optional[Finding]:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return None
        valid_statuses = {"OPEN", "ACKNOWLEDGED", "RESOLVED", "ACCEPTED_RISK"}
        if new_status.upper() not in valid_statuses:
            raise ValueError(f"Invalid status '{new_status}'. Allowed: {valid_statuses}")

        finding.status = new_status.upper()
        finding.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(finding)
        return finding

    @staticmethod
    def compare_scans(db: Session, baseline_scan_id: str, comparison_scan_id: str) -> Dict[str, Any]:
        """Compares two scans to detect new, persistent, and disappeared/resolved findings."""
        base_findings = db.query(Finding).filter(Finding.scan_id == baseline_scan_id).all()
        comp_findings = db.query(Finding).filter(Finding.scan_id == comparison_scan_id).all()

        base_keys = { (f.rule_id, f.resource_id, f.region): f for f in base_findings }
        comp_keys = { (f.rule_id, f.resource_id, f.region): f for f in comp_findings }

        new_keys = set(comp_keys.keys()) - set(base_keys.keys())
        persistent_keys = set(comp_keys.keys()) & set(base_keys.keys())
        disappeared_keys = set(base_keys.keys()) - set(comp_keys.keys())

        return {
            "baseline_scan_id": baseline_scan_id,
            "comparison_scan_id": comparison_scan_id,
            "new_findings_count": len(new_keys),
            "persistent_findings_count": len(persistent_keys),
            "disappeared_findings_count": len(disappeared_keys),
            "new_findings": [comp_keys[k].id for k in new_keys],
            "persistent_findings": [comp_keys[k].id for k in persistent_keys],
            "disappeared_findings": [base_keys[k].id for k in disappeared_keys],
        }
