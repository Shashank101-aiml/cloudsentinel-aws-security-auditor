from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.scan import (
    ScanCreateRequest,
    ScanSummaryResponse,
    ScanDetailResponse,
    ScanListResponse,
)
from app.schemas.finding import FindingResponse, FindingFilterParams
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanSummaryResponse, status_code=201, summary="Start a security scan")
def start_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Validates scan scope and triggers execution.
    If mode is 'real', requires explicit confirmation and verified AWS credentials.
    """
    if request.mode == "real" and not request.confirm_real_scan:
        raise HTTPException(
            status_code=400,
            detail="User confirmation (confirm_real_scan=true) is required to run a real AWS scan.",
        )

    try:
        scan = ScanService.create_scan(db, request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Run scan asynchronously in background
    def run_async(scan_id: str, req: ScanCreateRequest):
        from app.core.database import SessionLocal
        bg_db = SessionLocal()
        try:
            ScanService.execute_scan(bg_db, scan_id, req)
        finally:
            bg_db.close()

    background_tasks.add_task(run_async, scan.id, request)
    return scan


@router.get("", response_model=ScanListResponse, summary="List scan history")
def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    total, items = ScanService.list_scans(db, limit=limit, offset=offset)
    return ScanListResponse(total=total, items=items)


@router.get("/{scan_id}", response_model=ScanDetailResponse, summary="Get scan details")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@router.get("/{scan_id}/summary", response_model=ScanSummaryResponse, summary="Get scan summary metrics")
def get_scan_summary(scan_id: str, db: Session = Depends(get_db)):
    scan = ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@router.get("/{scan_id}/findings", summary="Get filterable findings for scan")
def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    scan = ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    filters = FindingFilterParams(
        severity=severity,
        service=service,
        status=status,
        region=region,
        search=search,
        limit=limit,
        offset=offset,
    )
    total, items = ScanService.get_findings_for_scan(db, scan_id, filters)
    return {
        "scan_id": scan_id,
        "total": total,
        "limit": limit,
        "offset": offset,
        "findings": [FindingResponse.model_validate(f) for f in items],
    }


@router.post("/{scan_id}/cancel", summary="Cancel a queued or running scan")
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if scan.status not in ["QUEUED", "RUNNING"]:
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in status {scan.status}")

    scan.status = "CANCELLED"
    db.commit()
    return {"message": f"Scan {scan_id} cancelled", "status": "CANCELLED"}


@router.get("/compare/{baseline_id}/{comparison_id}", summary="Compare two scans")
def compare_scans(baseline_id: str, comparison_id: str, db: Session = Depends(get_db)):
    base = ScanService.get_scan(db, baseline_id)
    comp = ScanService.get_scan(db, comparison_id)
    if not base or not comp:
        raise HTTPException(status_code=404, detail="One or both scans not found for comparison")
    return ScanService.compare_scans(db, baseline_id, comparison_id)
