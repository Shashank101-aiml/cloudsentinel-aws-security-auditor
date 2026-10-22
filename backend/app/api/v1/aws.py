from typing import Optional
from fastapi import APIRouter, Query
from app.aws.connection import AWSConnectionService
from app.schemas.aws import (
    AWSIdentityResponse,
    AWSRegionsResponse,
    AWSConnectionStatusResponse,
)

router = APIRouter(prefix="/aws", tags=["AWS Connection"])


@router.get("/identity", response_model=AWSIdentityResponse, summary="Get verified AWS identity")
def get_identity(
    profile: Optional[str] = Query(None, description="AWS CLI profile name"),
    assume_role_arn: Optional[str] = Query(None, description="Role ARN to assume"),
):
    """Inspects credentials and calls STS GetCallerIdentity without leaking secrets."""
    return AWSConnectionService.get_caller_identity(profile=profile, assume_role_arn=assume_role_arn)


@router.get("/regions", response_model=AWSRegionsResponse, summary="Get supported AWS regions")
def get_regions(profile: Optional[str] = Query(None, description="AWS CLI profile name")):
    """Returns list of enabled AWS regions."""
    regions = AWSConnectionService.get_supported_regions(profile=profile)
    return AWSRegionsResponse(regions=regions, default_region="us-east-1")


@router.get("/connection-status", response_model=AWSConnectionStatusResponse, summary="Get AWS connection status")
def get_connection_status(profile: Optional[str] = Query(None, description="AWS CLI profile name")):
    """Validates connection and returns safe connection status for dashboard."""
    return AWSConnectionService.get_connection_status(profile=profile)
