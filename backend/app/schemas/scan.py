from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.finding import FindingResponse


class ScanCreateRequest(BaseModel):
    mode: str = Field(default="demo", description="'demo' or 'real'")
    regions: List[str] = Field(default_factory=lambda: ["us-east-1"], description="List of regions to scan")
    services: List[str] = Field(
        default_factory=lambda: ["s3", "iam", "ec2", "rds", "cloudtrail"],
        description="List of AWS services to audit",
    )
    profile: Optional[str] = Field(default=None, description="AWS CLI profile name if using profile auth")
    assume_role_arn: Optional[str] = Field(default=None, description="IAM Role ARN to assume (optional)")
    confirm_real_scan: bool = Field(default=False, description="User confirmation required for real scans")


class ScanSummaryResponse(BaseModel):
    id: str
    account_id: str
    scan_mode: str
    status: str
    risk_score: float
    total_resources_inspected: int
    checks_passed: int
    checks_failed: int
    checks_skipped: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    error_message: Optional[str] = None
    skipped_reasons: Dict[str, str] = Field(default_factory=dict)
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanDetailResponse(ScanSummaryResponse):
    regions: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    findings: List[FindingResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    total: int
    items: List[ScanSummaryResponse]
