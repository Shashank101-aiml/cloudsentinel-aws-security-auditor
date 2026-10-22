from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
from app.aws.client_factory import AWSClientFactory
from app.core.logging import logger


class RDSCollector:
    """Collects RDS database instances and security configuration."""

    def __init__(self, profile: Optional[str] = None, assume_role_arn: Optional[str] = None):
        self.profile = profile
        self.assume_role_arn = assume_role_arn

    def collect_region(self, region: str) -> Dict[str, Any]:
        """Inspects RDS instances in a given region."""
        client = AWSClientFactory.get_client("rds", region=region, profile=self.profile, assume_role_arn=self.assume_role_arn)
        results: Dict[str, Any] = {
            "region": region,
            "instances": [],
            "skipped": [],
        }

        try:
            resp = client.describe_db_instances()
            for db in resp.get("DBInstances", []):
                results["instances"].append({
                    "db_instance_identifier": db["DBInstanceIdentifier"],
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "status": db.get("DBInstanceStatus"),
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                    "storage_encrypted": db.get("StorageEncrypted", False),
                    "kms_key_id": db.get("KmsKeyId"),
                    "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                    "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade", False),
                    "vpc_security_groups": [sg.get("VpcSecurityGroupId") for sg in db.get("VpcSecurityGroups", [])],
                    "endpoint": db.get("Endpoint", {}).get("Address"),
                    "port": db.get("Endpoint", {}).get("Port"),
                })
        except ClientError as e:
            logger.warning(f"Failed to describe RDS instances in {region}: {e.response['Error']['Code']}")
            results["skipped"].append({"service": "rds", "check": "describe_db_instances", "region": region, "reason": e.response['Error']['Code']})

        return results
