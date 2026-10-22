from typing import Any, Dict, Optional
from app.engine.base_rule import BaseRule


class RDSPublicAccessRule(BaseRule):
    """RDS-001: Detects RDS database instances with PubliclyAccessible flag enabled."""
    rule_id = "RDS-001"
    title = "RDS Database Instance Publicly Accessible"
    description = (
        "The RDS database instance has 'PubliclyAccessible' set to true, making its DNS endpoint "
        "resolvable to a public IP address and directly accessible from the internet."
    )
    severity = "CRITICAL"
    service = "rds"
    resource_type = "AWS::RDS::DBInstance"
    references = [
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"
    ]
    remediation_guidance = (
        "Modify the RDS instance to disable 'PubliclyAccessible' and ensure it resides in "
        "private subnets without internet gateway routing."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        is_public = resource.get("publicly_accessible", False)
        if is_public:
            evidence = {
                "db_instance_identifier": resource.get("db_instance_identifier"),
                "engine": resource.get("engine"),
                "endpoint": resource.get("endpoint"),
                "port": resource.get("port"),
                "vpc_security_groups": resource.get("vpc_security_groups", []),
            }
            return self.build_finding(
                resource_id=resource.get("db_instance_identifier"),
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class RDSStorageEncryptionRule(BaseRule):
    """RDS-002: Detects unencrypted database storage volumes."""
    rule_id = "RDS-002"
    title = "RDS Storage Encryption Disabled"
    description = (
        "The RDS database instance storage is not encrypted at rest using AWS KMS, "
        "leaving database snapshots and automated backups unencrypted."
    )
    severity = "HIGH"
    service = "rds"
    resource_type = "AWS::RDS::DBInstance"
    references = [
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
    ]
    remediation_guidance = (
        "Enable encryption by snapshotting the unencrypted database, copying the snapshot with "
        "an AWS KMS encryption key enabled, and restoring a new encrypted instance."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        is_encrypted = resource.get("storage_encrypted", False)
        if not is_encrypted:
            evidence = {
                "db_instance_identifier": resource.get("db_instance_identifier"),
                "engine": resource.get("engine"),
                "storage_encrypted": False,
            }
            return self.build_finding(
                resource_id=resource.get("db_instance_identifier"),
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class RDSBackupRetentionRule(BaseRule):
    """RDS-003: Detects RDS instances with insufficient or disabled automated backup retention."""
    rule_id = "RDS-003"
    title = "RDS Automated Backup Retention Insufficient"
    description = (
        "Automated backups are disabled (retention period is 0) or configured below the "
        "recommended minimum of 7 days, hindering disaster recovery and point-in-time restore."
    )
    severity = "MEDIUM"
    service = "rds"
    resource_type = "AWS::RDS::DBInstance"
    references = [
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"
    ]
    remediation_guidance = (
        "Set the automated backup retention period on the RDS instance to at least 7 days (or 30+ for production)."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        retention = resource.get("backup_retention_period", 0)
        if retention < 7:
            sev = "HIGH" if retention == 0 else "MEDIUM"
            evidence = {
                "db_instance_identifier": resource.get("db_instance_identifier"),
                "backup_retention_period_days": retention,
                "minimum_recommended_days": 7,
            }
            return self.build_finding(
                resource_id=resource.get("db_instance_identifier"),
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
                custom_severity=sev,
            )
        return None
