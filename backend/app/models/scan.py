import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Integer, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class Scan(Base):
    """Represents a security audit scan execution."""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id = Column(String(32), nullable=False, index=True)
    scan_mode = Column(String(16), nullable=False, default="demo")  # "demo" or "real"
    status = Column(String(16), nullable=False, default="QUEUED", index=True)  # QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED

    # Scope metadata
    regions = Column(JSON, nullable=False, default=list)  # list of regions scanned
    services = Column(JSON, nullable=False, default=list)  # list of services scanned

    # Metrics
    risk_score = Column(Float, nullable=False, default=0.0)  # 0.0 - 100.0
    total_resources_inspected = Column(Integer, nullable=False, default=0)
    checks_passed = Column(Integer, nullable=False, default=0)
    checks_failed = Column(Integer, nullable=False, default=0)
    checks_skipped = Column(Integer, nullable=False, default=0)

    # Severity breakdown
    findings_count = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)

    # Diagnostic metadata
    error_message = Column(Text, nullable=True)
    skipped_reasons = Column(JSON, nullable=False, default=dict)  # {"service/region": "Reason"}

    # Timestamps (UTC)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan", order_by="Finding.created_at.desc()")
