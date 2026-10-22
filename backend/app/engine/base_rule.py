from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseRule(ABC):
    """Abstract base class for all deterministic AWS security rules."""

    rule_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    service: str  # s3, iam, ec2, rds, cloudtrail
    resource_type: str
    remediation_guidance: str
    references: List[str] = []

    @abstractmethod
    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates a single collected resource.
        Returns:
            Dict containing finding details if misconfigured, or None if compliant/skipped.
        """
        pass

    def build_finding(
        self,
        resource_id: str,
        account_id: str,
        region: Optional[str],
        evidence: Dict[str, Any],
        confidence: str = "CONFIRMED",
        custom_title: Optional[str] = None,
        custom_description: Optional[str] = None,
        custom_severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Helper to construct a validated finding dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": custom_title or self.title,
            "description": custom_description or self.description,
            "severity": custom_severity or self.severity,
            "confidence": confidence,
            "service": self.service,
            "resource_id": resource_id,
            "resource_type": self.resource_type,
            "region": region,
            "account_id": account_id,
            "evidence": evidence,
            "remediation": self.remediation_guidance,
            "references": self.references,
        }
