from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.core.logging import logger
from app.api.v1.router import api_router
from app.services.demo_service import DemoService


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle handler."""
    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=engine)

    if settings.DEMO_MODE_DEFAULT:
        logger.info("Seeding initial deterministic demo data...")
        db = SessionLocal()
        try:
            DemoService.seed_demo_data(db, force=False)
        except Exception as e:
            logger.error(f"Error seeding demo data: {str(e)}")
        finally:
            db.close()

    logger.info("CloudSentinel startup complete.")
    yield
    logger.info("CloudSentinel shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "CloudSentinel is an enterprise-grade AWS Cloud Security and Compliance Auditor. "
        "It provides deterministic, read-only security misconfiguration scanning for S3, IAM, "
        "EC2, RDS, and CloudTrail, accompanied by transparent risk scoring and remediation guidance."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server error on {request.method} {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Check server logs."},
    )


# Mount versioned API
app.include_router(api_router)


@app.get("/", tags=["Root"])
def root_redirect():
    return {
        "message": "Welcome to CloudSentinel — AWS Security & Compliance Auditor API",
        "version": settings.APP_VERSION,
        "docs_url": "/docs",
        "api_v1_prefix": "/api/v1",
    }
