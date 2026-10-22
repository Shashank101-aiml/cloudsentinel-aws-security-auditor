from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
from app.aws.client_factory import AWSClientFactory
from app.core.logging import logger


class EC2Collector:
    """Collects EC2 security groups, EBS volumes, and instance networking configurations."""

    def __init__(self, profile: Optional[str] = None, assume_role_arn: Optional[str] = None):
        self.profile = profile
        self.assume_role_arn = assume_role_arn

    def collect_region(self, region: str) -> Dict[str, Any]:
        """Inspects EC2 resources in a single AWS region."""
        client = AWSClientFactory.get_client("ec2", region=region, profile=self.profile, assume_role_arn=self.assume_role_arn)
        results: Dict[str, Any] = {
            "region": region,
            "security_groups": [],
            "volumes": [],
            "instances": [],
            "skipped": [],
        }

        # 1. Security Groups
        try:
            sg_resp = client.describe_security_groups()
            for sg in sg_resp.get("SecurityGroups", []):
                results["security_groups"].append({
                    "group_id": sg["GroupId"],
                    "group_name": sg["GroupName"],
                    "description": sg.get("Description", ""),
                    "vpc_id": sg.get("VpcId"),
                    "ip_permissions": sg.get("IpPermissions", []),
                })
        except ClientError as e:
            logger.warning(f"Failed to describe security groups in {region}: {e.response['Error']['Code']}")
            results["skipped"].append({"service": "ec2", "check": "security_groups", "region": region, "reason": e.response['Error']['Code']})

        # 2. EBS Volumes
        try:
            vol_resp = client.describe_volumes()
            for v in vol_resp.get("Volumes", []):
                results["volumes"].append({
                    "volume_id": v["VolumeId"],
                    "size_gb": v.get("Size"),
                    "encrypted": v.get("Encrypted", False),
                    "kms_key_id": v.get("KmsKeyId"),
                    "state": v.get("State"),
                    "availability_zone": v.get("AvailabilityZone"),
                    "volume_type": v.get("VolumeType"),
                })
        except ClientError as e:
            results["skipped"].append({"service": "ec2", "check": "volumes", "region": region, "reason": e.response['Error']['Code']})

        # 3. EC2 Instances
        try:
            inst_resp = client.describe_instances()
            for res in inst_resp.get("Reservations", []):
                for inst in res.get("Instances", []):
                    results["instances"].append({
                        "instance_id": inst["InstanceId"],
                        "instance_type": inst.get("InstanceType"),
                        "state": inst.get("State", {}).get("Name"),
                        "public_ip": inst.get("PublicIpAddress"),
                        "private_ip": inst.get("PrivateIpAddress"),
                        "subnet_id": inst.get("SubnetId"),
                        "vpc_id": inst.get("VpcId"),
                        "security_groups": [g.get("GroupId") for g in inst.get("SecurityGroups", [])],
                    })
        except ClientError as e:
            results["skipped"].append({"service": "ec2", "check": "instances", "region": region, "reason": e.response['Error']['Code']})

        return results
