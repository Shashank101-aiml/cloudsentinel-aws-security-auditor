import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


class Finding(Base):
    """Represents a discrete security finding detected during a scan."""
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(32), nullable=False, index=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)

    # Severity & Status
    severity = Column(String(16), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status = Column(String(24), nullable=False, default="OPEN", index=True)  # OPEN, ACKNOWLEDGED, RESOLVED, ACCEPTED_RISK
    confidence = Column(String(16), nullable=False, default="CONFIRMED")  # CONFIRMED, LIKELY, UNKNOWN

    # Target Resource Metadata
    service = Column(String(32), nullable=False, index=True)  # s3, iam, ec2, rds, cloudtrail
    resource_id = Column(String(255), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False)
    region = Column(String(32), nullable=True, index=True)
    account_id = Column(String(32), nullable=False)

    # Evidence & Guidance
    evidence = Column(JSON, nullable=False, default=dict)
    remediation = Column(Text, nullable=False)
    references = Column(JSON, nullable=False, default=list)

    # Timestamps (UTC)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    scan = relationship("Scan", back_populates="findings")
