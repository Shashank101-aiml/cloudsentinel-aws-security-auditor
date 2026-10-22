from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.services.demo_service import DemoService
from app.schemas.scan import ScanSummaryResponse

router = APIRouter(prefix="/demo", tags=["Demo"])


@router.post("/reset", response_model=ScanSummaryResponse, summary="Reset demo data to deterministic baseline")
def reset_demo_data(db: Session = Depends(get_db)):
    """Resets the demo scan and findings back to standard deterministic demo values."""
    scan = DemoService.seed_demo_data(db, force=True)
    return scan
