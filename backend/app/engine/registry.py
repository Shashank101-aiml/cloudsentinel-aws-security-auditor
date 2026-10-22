from typing import Dict, List
from app.engine.base_rule import BaseRule
from app.engine.rules.s3_rules import (
    S3PublicExposureRule,
    S3BlockPublicAccessRule,
    S3ServerSideEncryptionRule,
    S3VersioningRule,
    S3SecureTransportRule,
)
from app.engine.rules.iam_rules import (
    IAMAdminPolicyRule,
    IAMWildcardActionRule,
    IAMRiskyTrustRelationshipRule,
    IAMRootMFARule,
)
from app.engine.rules.ec2_rules import (
    EC2PublicSSHRule,
    EC2PublicRDPRule,
    EC2SensitivePortsRule,
    EC2UnencryptedEBSVolumeRule,
    EC2PublicIPv4Rule,
)
from app.engine.rules.rds_rules import (
    RDSPublicAccessRule,
    RDSStorageEncryptionRule,
    RDSBackupRetentionRule,
)
from app.engine.rules.cloudtrail_rules import (
    CloudTrailMissingRule,
    CloudTrailNotLoggingRule,
    CloudTrailMultiRegionRule,
    CloudTrailLogFileValidationRule,
)


class RuleRegistry:
    """Central registry and dispatcher for all CloudSentinel security rules."""

    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}
        self._register_default_rules()

    def register(self, rule: BaseRule):
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> BaseRule:
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[BaseRule]:
        return list(self._rules.values())

    def get_rules_by_service(self, service: str) -> List[BaseRule]:
        return [r for r in self._rules.values() if r.service.lower() == service.lower()]

    def _register_default_rules(self):
        # S3 Rules
        self.register(S3PublicExposureRule())
        self.register(S3BlockPublicAccessRule())
        self.register(S3ServerSideEncryptionRule())
        self.register(S3VersioningRule())
        self.register(S3SecureTransportRule())

        # IAM Rules
        self.register(IAMAdminPolicyRule())
        self.register(IAMWildcardActionRule())
        self.register(IAMRiskyTrustRelationshipRule())
        self.register(IAMRootMFARule())

        # EC2 Rules
        self.register(EC2PublicSSHRule())
        self.register(EC2PublicRDPRule())
        self.register(EC2SensitivePortsRule())
        self.register(EC2UnencryptedEBSVolumeRule())
        self.register(EC2PublicIPv4Rule())

        # RDS Rules
        self.register(RDSPublicAccessRule())
        self.register(RDSStorageEncryptionRule())
        self.register(RDSBackupRetentionRule())

        # CloudTrail Rules
        self.register(CloudTrailMissingRule())
        self.register(CloudTrailNotLoggingRule())
        self.register(CloudTrailMultiRegionRule())
        self.register(CloudTrailLogFileValidationRule())


registry = RuleRegistry()
