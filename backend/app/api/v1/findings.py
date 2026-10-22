from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingResponse, FindingStatusUpdate
from app.services.scan_service import ScanService

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("/{finding_id}", response_model=FindingResponse, summary="Get finding detail")
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse, summary="Update finding review status")
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
):
    """
    Updates the local finding status (OPEN, ACKNOWLEDGED, RESOLVED, ACCEPTED_RISK).
    Note: This only affects local application records and never modifies AWS resources.
    """
    try:
        updated = ScanService.update_finding_status(db, finding_id, payload.status)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
        return updated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
