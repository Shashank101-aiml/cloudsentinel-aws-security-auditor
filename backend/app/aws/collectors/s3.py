import json
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
from app.aws.client_factory import AWSClientFactory
from app.core.logging import logger


class S3Collector:
    """Collects configuration evidence for S3 buckets across account/regions."""

    def __init__(self, profile: Optional[str] = None, assume_role_arn: Optional[str] = None):
        self.profile = profile
        self.assume_role_arn = assume_role_arn

    def collect_buckets(self) -> Dict[str, Any]:
        """Discovers buckets and inspects public access, encryption, versioning, policy, and ACLs."""
        client = AWSClientFactory.get_client("s3", region="us-east-1", profile=self.profile, assume_role_arn=self.assume_role_arn)
        results: Dict[str, Any] = {"buckets": [], "account_public_access_block": None, "skipped": []}

        # Try to get account-level S3 control public access block if permitted
        try:
            sts = AWSClientFactory.get_client("sts", region="us-east-1", profile=self.profile, assume_role_arn=self.assume_role_arn)
            account_id = sts.get_caller_identity()["Account"]
            s3control = AWSClientFactory.get_client("s3control", region="us-east-1", profile=self.profile, assume_role_arn=self.assume_role_arn)
            acct_pab = s3control.get_public_access_block(AccountId=account_id)
            results["account_public_access_block"] = acct_pab.get("PublicAccessBlockConfiguration")
        except Exception as e:
            logger.debug(f"Could not retrieve S3Control account-level block public access: {str(e)}")

        try:
            resp = client.list_buckets()
        except ClientError as e:
            logger.error(f"Failed to list S3 buckets: {str(e)}")
            results["skipped"].append({"service": "s3", "reason": f"list_buckets failed: {e.response['Error']['Code']}"})
            return results

        raw_buckets = resp.get("Buckets", [])
        for b in raw_buckets:
            name = b["Name"]
            bucket_data: Dict[str, Any] = {
                "name": name,
                "creation_date": b["CreationDate"].isoformat() if "CreationDate" in b else None,
                "region": "us-east-1",
                "public_access_block": None,
                "policy": None,
                "policy_error": None,
                "acl": None,
                "acl_error": None,
                "encryption": None,
                "encryption_error": None,
                "versioning": None,
                "versioning_error": None,
            }

            # Determine region
            try:
                loc = client.get_bucket_location(Bucket=name).get("LocationConstraint")
                bucket_data["region"] = loc or "us-east-1"
                if bucket_data["region"] == "EU":
                    bucket_data["region"] = "eu-west-1"
            except Exception:
                pass

            reg_client = AWSClientFactory.get_client("s3", region=bucket_data["region"], profile=self.profile, assume_role_arn=self.assume_role_arn)

            # Public Access Block
            try:
                pab = reg_client.get_public_access_block(Bucket=name)
                bucket_data["public_access_block"] = pab.get("PublicAccessBlockConfiguration")
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code != "NoSuchPublicAccessBlockConfiguration":
                    bucket_data["public_access_block_error"] = code

            # Bucket Policy
            try:
                pol = reg_client.get_bucket_policy(Bucket=name)
                policy_str = pol.get("Policy", "{}")
                bucket_data["policy"] = json.loads(policy_str)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code != "NoSuchBucketPolicy":
                    bucket_data["policy_error"] = code

            # Bucket ACL
            try:
                acl = reg_client.get_bucket_acl(Bucket=name)
                grants = []
                for g in acl.get("Grants", []):
                    grantee = g.get("Grantee", {})
                    grants.append({
                        "grantee_type": grantee.get("Type"),
                        "grantee_uri": grantee.get("URI"),
                        "permission": g.get("Permission"),
                    })
                bucket_data["acl"] = grants
            except ClientError as e:
                bucket_data["acl_error"] = e.response.get("Error", {}).get("Code")

            # Server-Side Encryption
            try:
                enc = reg_client.get_bucket_encryption(Bucket=name)
                bucket_data["encryption"] = enc.get("ServerSideEncryptionConfiguration")
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code != "ServerSideEncryptionConfigurationNotFoundError":
                    bucket_data["encryption_error"] = code

            # Versioning
            try:
                ver = reg_client.get_bucket_versioning(Bucket=name)
                bucket_data["versioning"] = ver.get("Status")
            except ClientError as e:
                bucket_data["versioning_error"] = e.response.get("Error", {}).get("Code")

            results["buckets"].append(bucket_data)

        return results
