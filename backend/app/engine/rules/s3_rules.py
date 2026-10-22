from typing import Any, Dict, Optional
from app.engine.base_rule import BaseRule


class S3PublicExposureRule(BaseRule):
    """S3-001: Detects buckets with demonstrably public ACLs or public bucket policies."""
    rule_id = "S3-001"
    title = "S3 Bucket Publicly Accessible"
    description = (
        "The S3 bucket has permissions allowing public access via an unconstrained "
        "bucket policy or public ACL grant (AllUsers/AuthenticatedUsers)."
    )
    severity = "CRITICAL"
    service = "s3"
    resource_type = "AWS::S3::Bucket"
    references = [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-iam-policies.html",
    ]
    remediation_guidance = (
        "Enable S3 Block Public Access at the bucket or account level. Review and restrict "
        "bucket policies and ACLs to only authorized IAM principals."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = resource.get("name")
        pab = resource.get("public_access_block") or {}
        acct_pab = context.get("account_public_access_block") or {}

        # If IgnorePublicAcls and RestrictPublicBuckets are active, public exposure is blocked
        acl_blocked = pab.get("IgnorePublicAcls", False) or acct_pab.get("IgnorePublicAcls", False)
        policy_blocked = pab.get("RestrictPublicBuckets", False) or acct_pab.get("RestrictPublicBuckets", False)

        public_acls = []
        if not acl_blocked:
            for grant in resource.get("acl") or []:
                uri = grant.get("grantee_uri", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    public_acls.append(grant)

        public_policy_stmts = []
        if not policy_blocked and resource.get("policy"):
            stmts = resource["policy"].get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal")
                    if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                        # Check if conditioned
                        cond = stmt.get("Condition")
                        if not cond:
                            public_policy_stmts.append(stmt)

        if public_acls or public_policy_stmts:
            evidence = {
                "bucket_name": name,
                "public_acl_grants": public_acls,
                "public_policy_statements": public_policy_stmts,
                "block_public_access_config": pab,
            }
            return self.build_finding(
                resource_id=name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class S3BlockPublicAccessRule(BaseRule):
    """S3-002: Detects missing or disabled S3 Block Public Access configuration."""
    rule_id = "S3-002"
    title = "S3 Block Public Access Disabled"
    description = (
        "S3 Block Public Access is disabled or partially disabled on the bucket, "
        "increasing risk of unintended public data exposure."
    )
    severity = "HIGH"
    service = "s3"
    resource_type = "AWS::S3::Bucket"
    references = [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
    ]
    remediation_guidance = (
        "Enable all four S3 Block Public Access settings: BlockPublicAcls, IgnorePublicAcls, "
        "BlockPublicPolicy, and RestrictPublicBuckets."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = resource.get("name")
        pab = resource.get("public_access_block")

        if not pab:
            evidence = {"bucket_name": name, "has_public_access_block": False}
            return self.build_finding(
                resource_id=name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )

        disabled_flags = [
            flag for flag in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            if not pab.get(flag, False)
        ]

        if disabled_flags:
            evidence = {"bucket_name": name, "disabled_flags": disabled_flags, "current_config": pab}
            return self.build_finding(
                resource_id=name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class S3ServerSideEncryptionRule(BaseRule):
    """S3-003: Detects buckets without default server-side encryption."""
    rule_id = "S3-003"
    title = "S3 Bucket Default Encryption Not Configured"
    description = "The S3 bucket lacks default server-side encryption (SSE-S3 or SSE-KMS)."
    severity = "HIGH"
    service = "s3"
    resource_type = "AWS::S3::Bucket"
    references = [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
    ]
    remediation_guidance = (
        "Configure default server-side encryption with AWS KMS (SSE-KMS) or Amazon S3-managed keys (SSE-S3)."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = resource.get("name")
        enc = resource.get("encryption")
        if not enc or not enc.get("Rules"):
            evidence = {"bucket_name": name, "encryption_configuration": enc}
            return self.build_finding(
                resource_id=name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class S3VersioningRule(BaseRule):
    """S3-004: Detects buckets without object versioning enabled."""
    rule_id = "S3-004"
    title = "S3 Bucket Versioning Disabled"
    description = (
        "Object versioning is disabled or suspended, which increases the risk of "
        "accidental deletion, ransomware tampering, or unrecoverable overwrites."
    )
    severity = "LOW"
    service = "s3"
    resource_type = "AWS::S3::Bucket"
    references = [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
    ]
    remediation_guidance = (
        "Enable S3 Versioning on the bucket and configure appropriate lifecycle policies "
        "to manage non-current object versions."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = resource.get("name")
        status = resource.get("versioning")
        if status != "Enabled":
            evidence = {"bucket_name": name, "versioning_status": status or "Disabled/None"}
            return self.build_finding(
                resource_id=name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class S3SecureTransportRule(BaseRule):
    """S3-005: Detects bucket policies that lack an explicit aws:SecureTransport deny."""
    rule_id = "S3-005"
    title = "S3 Bucket Allows Insecure (HTTP) Transport"
    description = (
        "The bucket policy does not explicitly enforce HTTPS via an 'aws:SecureTransport: false' "
        "deny condition, allowing unencrypted HTTP transmission."
    )
    severity = "MEDIUM"
    service = "s3"
    resource_type = "AWS::S3::Bucket"
    references = [
        "https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule-s3-bucket-ssl-requests-only/"
    ]
    remediation_guidance = (
        "Attach a bucket policy that denies all s3:* actions when 'aws:SecureTransport' condition is false."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = resource.get("name")
        policy = resource.get("policy")
        has_secure_transport_deny = False

        if policy:
            stmts = policy.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for s in stmts:
                if s.get("Effect") == "Deny":
                    cond = s.get("Condition", {})
                    bool_cond = cond.get("Bool", {})
                    if str(bool_cond.get("aws:SecureTransport")).lower() == "false":
                        has_secure_transport_deny = True
                        break

        if not has_secure_transport_deny:
            evidence = {"bucket_name": name, "has_secure_transport_policy": False}
            return self.build_finding(
                resource_id=name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None
