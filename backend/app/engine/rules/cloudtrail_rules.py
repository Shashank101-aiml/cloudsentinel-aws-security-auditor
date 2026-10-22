from typing import Any, Dict, Optional
from app.engine.base_rule import BaseRule


class CloudTrailMissingRule(BaseRule):
    """LOG-001: Detects the absence of any CloudTrail trail in the account."""
    rule_id = "LOG-001"
    title = "CloudTrail Logging Not Configured"
    description = (
        "No active CloudTrail trail was discovered in the AWS account or region scope, "
        "leaving API calls and management actions unrecorded for security forensics."
    )
    severity = "CRITICAL"
    service = "cloudtrail"
    resource_type = "AWS::CloudTrail::Trail"
    references = [
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
    ]
    remediation_guidance = (
        "Create an organizational or multi-region CloudTrail trail logging all management and data events to an encrypted S3 bucket."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Evaluated when trails list is empty
        trails = resource.get("trails", [])
        if not trails:
            evidence = {"trails_found_count": 0, "region_checked": context.get("region", "us-east-1")}
            return self.build_finding(
                resource_id=f"cloudtrail-{context.get('account_id', 'unknown')}",
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class CloudTrailNotLoggingRule(BaseRule):
    """LOG-002: Detects trails that are not actively logging."""
    rule_id = "LOG-002"
    title = "CloudTrail Trail Is Not Actively Logging"
    description = (
        "The CloudTrail trail exists but its logging state is paused or disabled (IsLogging = False), "
        "preventing new security events from being stored."
    )
    severity = "CRITICAL"
    service = "cloudtrail"
    resource_type = "AWS::CloudTrail::Trail"
    references = [
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-turning-off-logging.html"
    ]
    remediation_guidance = (
        "Start logging on the CloudTrail trail using the AWS Console or the aws cloudtrail start-logging command."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = resource.get("name")
        is_logging = resource.get("is_logging", False)
        status_error = resource.get("status_error")

        if status_error:
            # Cannot verify status due to permissions
            return None

        if not is_logging:
            evidence = {
                "trail_name": name,
                "trail_arn": resource.get("arn"),
                "is_logging": False,
            }
            return self.build_finding(
                resource_id=resource.get("arn") or name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("home_region") or context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class CloudTrailMultiRegionRule(BaseRule):
    """LOG-003: Detects trails that do not capture multi-region events."""
    rule_id = "LOG-003"
    title = "CloudTrail Multi-Region Logging Disabled"
    description = (
        "The CloudTrail trail records events in only a single region rather than all AWS regions, "
        "creating visibility blind spots for unauthorized activity in unmonitored regions."
    )
    severity = "MEDIUM"
    service = "cloudtrail"
    resource_type = "AWS::CloudTrail::Trail"
    references = [
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html"
    ]
    remediation_guidance = (
        "Update the trail to apply to all regions (IsMultiRegionTrail = true)."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = resource.get("name")
        is_multi_region = resource.get("is_multi_region", False)

        if not is_multi_region:
            evidence = {
                "trail_name": name,
                "home_region": resource.get("home_region"),
                "is_multi_region": False,
            }
            return self.build_finding(
                resource_id=resource.get("arn") or name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("home_region") or context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class CloudTrailLogFileValidationRule(BaseRule):
    """LOG-004: Detects trails with log file validation disabled."""
    rule_id = "LOG-004"
    title = "CloudTrail Log File Validation Disabled"
    description = (
        "Log file validation is disabled. Without log file integrity validation, tampering or "
        "deletion of CloudTrail audit logs cannot be cryptographically proven."
    )
    severity = "MEDIUM"
    service = "cloudtrail"
    resource_type = "AWS::CloudTrail::Trail"
    references = [
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
    ]
    remediation_guidance = (
        "Enable log file validation on the trail to produce digest files with cryptographic signatures."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = resource.get("name")
        val_enabled = resource.get("log_file_validation", False)

        if not val_enabled:
            evidence = {
                "trail_name": name,
                "log_file_validation_enabled": False,
            }
            return self.build_finding(
                resource_id=resource.get("arn") or name,
                account_id=context.get("account_id", "UNKNOWN"),
                region=resource.get("home_region") or context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None
