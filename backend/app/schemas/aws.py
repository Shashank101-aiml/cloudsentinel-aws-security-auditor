from typing import List, Optional
from pydantic import BaseModel


class AWSIdentityResponse(BaseModel):
    account_id: str
    arn: str
    user_id: str
    auth_method: str
    profile: Optional[str] = None
    role_arn: Optional[str] = None
    is_valid: bool = True
    error: Optional[str] = None


class AWSRegionsResponse(BaseModel):
    regions: List[str]
    default_region: str


class AWSConnectionStatusResponse(BaseModel):
    connected: bool
    mode: str  # "live" or "demo_only"
    account_id: Optional[str] = None
    arn: Optional[str] = None
    auth_method: Optional[str] = None
    permissions_verified: bool = False
    message: str
