from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FindingBase(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    status: str = Field(default="OPEN", description="OPEN, ACKNOWLEDGED, RESOLVED, or ACCEPTED_RISK")
    confidence: str = Field(default="CONFIRMED", description="CONFIRMED, LIKELY, or UNKNOWN")
    service: str
    resource_id: str
    resource_type: str
    region: Optional[str] = None
    account_id: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: str
    references: List[str] = Field(default_factory=list)


class FindingCreate(FindingBase):
    scan_id: str


class FindingStatusUpdate(BaseModel):
    status: str = Field(description="New status: OPEN, ACKNOWLEDGED, RESOLVED, or ACCEPTED_RISK")


class FindingResponse(FindingBase):
    id: str
    scan_id: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class FindingFilterParams(BaseModel):
    severity: Optional[str] = None
    service: Optional[str] = None
    status: Optional[str] = None
    region: Optional[str] = None
    search: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
