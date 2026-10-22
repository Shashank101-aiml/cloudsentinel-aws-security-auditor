from datetime import datetime
from typing import List
from pydantic import BaseModel
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanSummaryResponse


class ScanReportData(BaseModel):
    scan: ScanSummaryResponse
    findings: List[FindingResponse]
    generated_at: datetime
    disclaimer: str = (
        "CloudSentinel is an educational and portfolio security auditing aid. "
        "Findings represent heuristic configuration checks and do not guarantee "
        "compliance, absolute security, or an official AWS certification."
    )
