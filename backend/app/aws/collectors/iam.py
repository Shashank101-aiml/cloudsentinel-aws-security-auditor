from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
from app.aws.client_factory import AWSClientFactory
from app.core.logging import logger


class IAMCollector:
    """Collects IAM policies, roles, trust policies, and root account MFA status."""

    def __init__(self, profile: Optional[str] = None, assume_role_arn: Optional[str] = None):
        self.profile = profile
        self.assume_role_arn = assume_role_arn

    def collect(self) -> Dict[str, Any]:
        """Collects IAM inventory."""
        client = AWSClientFactory.get_client("iam", region="us-east-1", profile=self.profile, assume_role_arn=self.assume_role_arn)
        results: Dict[str, Any] = {
            "account_summary": None,
            "roles": [],
            "policies": [],
            "skipped": [],
        }

        # 1. Account Summary (for Root MFA)
        try:
            summary = client.get_account_summary().get("SummaryMap", {})
            results["account_summary"] = summary
        except ClientError as e:
            logger.warning(f"Could not get IAM account summary: {e.response['Error']['Code']}")
            results["skipped"].append({"service": "iam", "check": "account_summary", "reason": e.response['Error']['Code']})

        # 2. Roles & Trust Relationships
        try:
            roles_resp = client.list_roles(MaxItems=100)
            for r in roles_resp.get("Roles", []):
                role_name = r["RoleName"]
                # Skip AWS service-linked roles for security rule noise reduction
                if r.get("Path", "").startswith("/aws-service-role/"):
                    continue

                role_data: Dict[str, Any] = {
                    "role_name": role_name,
                    "arn": r["Arn"],
                    "trust_policy": r.get("AssumeRolePolicyDocument"),
                    "attached_policies": [],
                    "inline_policies": [],
                }

                # Attached managed policies
                try:
                    att = client.list_attached_role_policies(RoleName=role_name)
                    role_data["attached_policies"] = [p["PolicyArn"] for p in att.get("AttachedPolicies", [])]
                except Exception:
                    pass

                # Inline policies
                try:
                    inline = client.list_role_policies(RoleName=role_name)
                    for pol_name in inline.get("PolicyNames", []):
                        pol_doc = client.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                        role_data["inline_policies"].append({
                            "name": pol_name,
                            "policy_document": pol_doc.get("PolicyDocument"),
                        })
                except Exception:
                    pass

                results["roles"].append(role_data)
        except ClientError as e:
            results["skipped"].append({"service": "iam", "check": "list_roles", "reason": e.response['Error']['Code']})

        # 3. Customer Managed Policies (Scope='Local')
        try:
            policies_resp = client.list_policies(Scope="Local", MaxItems=100)
            for p in policies_resp.get("Policies", []):
                arn = p["Arn"]
                default_version_id = p.get("DefaultVersionId")
                doc = None
                if default_version_id:
                    try:
                        v = client.get_policy_version(PolicyArn=arn, VersionId=default_version_id)
                        doc = v.get("PolicyVersion", {}).get("Document")
                    except Exception:
                        pass

                results["policies"].append({
                    "name": p["PolicyName"],
                    "arn": arn,
                    "document": doc,
                    "attachment_count": p.get("AttachmentCount", 0),
                })
        except ClientError as e:
            results["skipped"].append({"service": "iam", "check": "list_policies", "reason": e.response['Error']['Code']})

        return results
