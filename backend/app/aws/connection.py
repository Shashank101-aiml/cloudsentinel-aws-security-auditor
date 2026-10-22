from typing import List, Optional
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from app.aws.client_factory import AWSClientFactory
from app.schemas.aws import AWSIdentityResponse, AWSConnectionStatusResponse
from app.core.logging import logger


class AWSConnectionService:
    """Handles credential validation, identity inspection via STS, and region discovery."""

    @staticmethod
    def get_caller_identity(
        profile: Optional[str] = None,
        assume_role_arn: Optional[str] = None,
    ) -> AWSIdentityResponse:
        """Calls STS GetCallerIdentity to verify credentials and return authenticated principal."""
        try:
            client = AWSClientFactory.get_client(
                "sts",
                region="us-east-1",
                profile=profile,
                assume_role_arn=assume_role_arn,
            )
            identity = client.get_caller_identity()
            account_id = identity.get("Account", "UNKNOWN")
            arn = identity.get("Arn", "UNKNOWN")
            user_id = identity.get("UserId", "UNKNOWN")

            auth_method = "Assumed Role" if assume_role_arn else ("Profile" if profile else "Default Credential Chain")

            logger.info(f"Verified AWS caller identity for account {account_id}")
            return AWSIdentityResponse(
                account_id=account_id,
                arn=arn,
                user_id=user_id,
                auth_method=auth_method,
                profile=profile,
                role_arn=assume_role_arn,
                is_valid=True,
            )
        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.warning(f"AWS credentials not configured or incomplete: {str(e)}")
            return AWSIdentityResponse(
                account_id="N/A",
                arn="N/A",
                user_id="N/A",
                auth_method="None",
                is_valid=False,
                error="AWS credentials not found. Configure AWS CLI, environment variables, or run in Demo Mode.",
            )
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "ClientError")
            err_msg = e.response.get("Error", {}).get("Message", str(e))
            logger.warning(f"STS verification failed: {err_code} - {err_msg}")
            return AWSIdentityResponse(
                account_id="N/A",
                arn="N/A",
                user_id="N/A",
                auth_method="Invalid",
                is_valid=False,
                error=f"STS error: {err_code} - {err_msg}",
            )
        except Exception as e:
            logger.error(f"Unexpected error validating AWS identity: {str(e)}")
            return AWSIdentityResponse(
                account_id="N/A",
                arn="N/A",
                user_id="N/A",
                auth_method="Error",
                is_valid=False,
                error=f"Error checking AWS identity: {str(e)}",
            )

    @staticmethod
    def get_supported_regions(profile: Optional[str] = None) -> List[str]:
        """Returns list of enabled AWS regions using EC2 DescribeRegions or fallback list."""
        default_regions = [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
            "ap-south-1",
            "ap-southeast-1",
            "ap-northeast-1",
        ]
        try:
            client = AWSClientFactory.get_client("ec2", region="us-east-1", profile=profile)
            resp = client.describe_regions(AllRegions=False)
            return [r["RegionName"] for r in resp.get("Regions", [])] or default_regions
        except Exception:
            return default_regions

    @staticmethod
    def get_connection_status(profile: Optional[str] = None) -> AWSConnectionStatusResponse:
        """Summarizes connection health for the UI."""
        identity = AWSConnectionService.get_caller_identity(profile=profile)
        if identity.is_valid:
            return AWSConnectionStatusResponse(
                connected=True,
                mode="live",
                account_id=identity.account_id,
                arn=identity.arn,
                auth_method=identity.auth_method,
                permissions_verified=True,
                message=f"Connected to AWS Account {identity.account_id} ({identity.arn})",
            )
        return AWSConnectionStatusResponse(
            connected=False,
            mode="demo_only",
            account_id=None,
            arn=None,
            auth_method="None",
            permissions_verified=False,
            message=identity.error or "No live AWS connection. Demo mode available.",
        )
