from typing import Any, Dict, Optional
from app.engine.base_rule import BaseRule


class IAMAdminPolicyRule(BaseRule):
    """IAM-001: Detects policies with full administrative privileges (Action: * and Resource: *)."""
    rule_id = "IAM-001"
    title = "IAM Policy Grants Full Administrative Privileges"
    description = (
        "The IAM policy contains a statement allowing 'Action: *' across 'Resource: *', "
        "violating least-privilege principles and allowing complete account takeover."
    )
    severity = "CRITICAL"
    service = "iam"
    resource_type = "AWS::IAM::Policy"
    references = [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
    ]
    remediation_guidance = (
        "Replace full wildcard access with specific service actions and bounded resources."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        doc = resource.get("document")
        if not doc:
            return None

        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]

        admin_stmts = []
        for s in stmts:
            if s.get("Effect") == "Allow":
                actions = s.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                resources = s.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                if "*" in actions and "*" in resources:
                    admin_stmts.append(s)

        if admin_stmts:
            evidence = {
                "policy_name": resource.get("name"),
                "policy_arn": resource.get("arn"),
                "admin_statements": admin_stmts,
            }
            return self.build_finding(
                resource_id=resource.get("arn") or resource.get("name", "unknown-policy"),
                account_id=context.get("account_id", "UNKNOWN"),
                region="global",
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class IAMWildcardActionRule(BaseRule):
    """IAM-002: Detects overly broad wildcard action permissions (e.g. s3:*, iam:*)."""
    rule_id = "IAM-002"
    title = "IAM Policy Uses Wildcard Service Actions"
    description = (
        "The IAM policy statement allows wildcard actions within a service prefix (e.g., s3:*, iam:*), "
        "granting unneeded permissions beyond what the role requires."
    )
    severity = "MEDIUM"
    service = "iam"
    resource_type = "AWS::IAM::Policy"
    references = [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html"
    ]
    remediation_guidance = (
        "Enumerate only the specific API actions needed rather than using wildcard service permissions."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        doc = resource.get("document")
        if not doc:
            return None

        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]

        wildcard_actions = []
        for s in stmts:
            if s.get("Effect") == "Allow":
                actions = s.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                for act in actions:
                    # Ignore full * since IAM-001 covers it
                    if act != "*" and ("*" in act or ":*" in act):
                        wildcard_actions.append(act)

        if wildcard_actions:
            evidence = {
                "policy_name": resource.get("name"),
                "wildcard_actions": list(set(wildcard_actions)),
            }
            return self.build_finding(
                resource_id=resource.get("arn") or resource.get("name", "unknown-policy"),
                account_id=context.get("account_id", "UNKNOWN"),
                region="global",
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class IAMRiskyTrustRelationshipRule(BaseRule):
    """IAM-003: Detects dangerous trust policies permitting arbitrary principals or wildcard accounts."""
    rule_id = "IAM-003"
    title = "IAM Role Trust Policy Has Overly Permissive Principal"
    description = (
        "The IAM role trust policy allows external principals or wildcard ('*') entities "
        "to assume the role without conditions, opening the account to unauthorized assumption."
    )
    severity = "HIGH"
    service = "iam"
    resource_type = "AWS::IAM::Role"
    references = [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#trust-policy"
    ]
    remediation_guidance = (
        "Constrain the trust policy principal to explicitly identified AWS accounts, roles, "
        "or federated identities with an ExternalId condition where appropriate."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        trust_doc = resource.get("trust_policy")
        if not trust_doc:
            return None

        stmts = trust_doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]

        risky_stmts = []
        for s in stmts:
            if s.get("Effect") == "Allow" and s.get("Action") in ["sts:AssumeRole", ["sts:AssumeRole"]]:
                princ = s.get("Principal", {})
                if princ == "*" or princ.get("AWS") == "*":
                    # Check if conditioned
                    if not s.get("Condition"):
                        risky_stmts.append(s)

        if risky_stmts:
            evidence = {
                "role_name": resource.get("role_name"),
                "risky_statements": risky_stmts,
            }
            return self.build_finding(
                resource_id=resource.get("arn") or resource.get("role_name", "unknown-role"),
                account_id=context.get("account_id", "UNKNOWN"),
                region="global",
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class IAMRootMFARule(BaseRule):
    """IAM-005: Verifies that root account MFA is enabled."""
    rule_id = "IAM-005"
    title = "Root Account MFA Disabled"
    description = (
        "Multi-Factor Authentication (MFA) is not enabled on the AWS root user account, "
        "leaving the most privileged account vulnerable to credential compromise."
    )
    severity = "CRITICAL"
    service = "iam"
    resource_type = "AWS::IAM::AccountSummary"
    references = [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"
    ]
    remediation_guidance = (
        "Log in as the root user and configure hardware or virtual MFA immediately."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # resource is the summary map
        if resource is None:
            # Cannot verify - prompt specifically says: "If the state cannot be retrieved, return UNKNOWN rather than silently treating it as disabled."
            return self.build_finding(
                resource_id=f"root-account-{context.get('account_id', 'unknown')}",
                account_id=context.get("account_id", "UNKNOWN"),
                region="global",
                evidence={"reason": "IAM AccountSummary permission missing or state unavailable"},
                confidence="UNKNOWN",
                custom_title="Root Account MFA State Unverifiable",
                custom_description="Could not verify root MFA status due to missing permissions.",
                custom_severity="LOW",
            )

        mfa_enabled = resource.get("AccountMFAEnabled", 0)
        if mfa_enabled == 0:
            evidence = {
                "account_mfa_enabled": 0,
                "account_summary": resource,
            }
            return self.build_finding(
                resource_id=f"root-account-{context.get('account_id', 'unknown')}",
                account_id=context.get("account_id", "UNKNOWN"),
                region="global",
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None
