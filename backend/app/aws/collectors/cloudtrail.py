from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
from app.aws.client_factory import AWSClientFactory
from app.core.logging import logger


class CloudTrailCollector:
    """Collects CloudTrail trails, logging status, and configuration."""

    def __init__(self, profile: Optional[str] = None, assume_role_arn: Optional[str] = None):
        self.profile = profile
        self.assume_role_arn = assume_role_arn

    def collect(self, region: str = "us-east-1") -> Dict[str, Any]:
        """Inspects CloudTrail trails in a specific region."""
        client = AWSClientFactory.get_client("cloudtrail", region=region, profile=self.profile, assume_role_arn=self.assume_role_arn)
        results: Dict[str, Any] = {
            "region": region,
            "trails": [],
            "skipped": [],
        }

        try:
            resp = client.describe_trails(includeShadowTrails=False)
            for t in resp.get("trailList", []):
                name = t.get("Name")
                arn = t.get("TrailARN")
                is_multi_region = t.get("IsMultiRegionTrail", False)
                log_file_validation = t.get("LogFileValidationEnabled", False)
                s3_bucket_name = t.get("S3BucketName")

                # Check logging status
                is_logging = False
                status_error = None
                try:
                    status = client.get_trail_status(Name=name)
                    is_logging = status.get("IsLogging", False)
                except ClientError as e:
                    status_error = e.response.get("Error", {}).get("Code")

                results["trails"].append({
                    "name": name,
                    "arn": arn,
                    "home_region": t.get("HomeRegion"),
                    "is_multi_region": is_multi_region,
                    "log_file_validation": log_file_validation,
                    "s3_bucket_name": s3_bucket_name,
                    "is_logging": is_logging,
                    "status_error": status_error,
                })
        except ClientError as e:
            logger.warning(f"Failed to describe CloudTrail trails in {region}: {e.response['Error']['Code']}")
            results["skipped"].append({"service": "cloudtrail", "check": "describe_trails", "region": region, "reason": e.response['Error']['Code']})

        return results
