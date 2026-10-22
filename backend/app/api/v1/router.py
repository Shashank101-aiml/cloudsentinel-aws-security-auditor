from fastapi import APIRouter
from app.api.v1.health import router as health_router
from app.api.v1.aws import router as aws_router
from app.api.v1.scans import router as scans_router
from app.api.v1.findings import router as findings_router
from app.api.v1.reports import router as reports_router
from app.api.v1.demo import router as demo_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health_router)
api_router.include_router(aws_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
api_router.include_router(reports_router)
api_router.include_router(demo_router)
