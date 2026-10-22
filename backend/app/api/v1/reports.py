from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.report_service import ReportService

router = APIRouter(prefix="/scans", tags=["Reports"])


@router.get("/{scan_id}/report.json", summary="Download scan report as JSON")
def download_json_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    content = ReportService.generate_json(scan, findings)
    filename = f"cloudsentinel-report-{scan.account_id}-{scan_id[:8]}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/report.csv", summary="Download scan report as CSV")
def download_csv_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    content = ReportService.generate_csv(scan, findings)
    filename = f"cloudsentinel-report-{scan.account_id}-{scan_id[:8]}.csv"
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/report.html", response_class=HTMLResponse, summary="View/Download scan report as HTML")
def download_html_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    content = ReportService.generate_html(scan, findings)
    return HTMLResponse(content=content)
