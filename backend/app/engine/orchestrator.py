from typing import Any, Dict, List, Optional
from app.aws.collectors.s3 import S3Collector
from app.aws.collectors.iam import IAMCollector
from app.aws.collectors.ec2 import EC2Collector
from app.aws.collectors.rds import RDSCollector
from app.aws.collectors.cloudtrail import CloudTrailCollector
from app.engine.registry import registry
from app.engine.risk_scorer import RiskScorer
from app.engine.sanitizer import Sanitizer
from app.core.logging import logger


class ScanOrchestrator:
    """Orchestrates resource discovery, rule evaluation, deduplication, and risk scoring."""

    def __init__(
        self,
        account_id: str,
        regions: List[str],
        services: List[str],
        profile: Optional[str] = None,
        assume_role_arn: Optional[str] = None,
    ):
        self.account_id = account_id
        self.regions = regions or ["us-east-1"]
        self.services = [s.lower() for s in services]
        self.profile = profile
        self.assume_role_arn = assume_role_arn
        self.risk_scorer = RiskScorer()

    def run_live_scan(self) -> Dict[str, Any]:
        """Performs a live read-only AWS security inspection."""
        findings: List[Dict[str, Any]] = []
        skipped_reasons: Dict[str, str] = {}
        total_resources = 0
        checks_passed = 0
        checks_failed = 0
        checks_skipped = 0

        # 1. S3 Audit
        if "s3" in self.services:
            logger.info("Starting S3 resource collection and evaluation...")
            try:
                collector = S3Collector(profile=self.profile, assume_role_arn=self.assume_role_arn)
                s3_data = collector.collect_buckets()
                for skip in s3_data.get("skipped", []):
                    skipped_reasons[f"s3/{skip.get('check', 'list')}"] = skip.get("reason", "unknown")
                    checks_skipped += 1

                buckets = s3_data.get("buckets", [])
                total_resources += len(buckets)
                s3_rules = registry.get_rules_by_service("s3")

                for bucket in buckets:
                    context = {
                        "account_id": self.account_id,
                        "account_public_access_block": s3_data.get("account_public_access_block"),
                    }
                    for rule in s3_rules:
                        finding = rule.evaluate(bucket, context)
                        if finding:
                            checks_failed += 1
                            findings.append(finding)
                        else:
                            checks_passed += 1
            except Exception as e:
                logger.error(f"S3 audit failure: {str(e)}")
                skipped_reasons["s3/global"] = f"Error: {str(e)}"
                checks_skipped += 1

        # 2. IAM Audit
        if "iam" in self.services:
            logger.info("Starting IAM resource collection and evaluation...")
            try:
                collector = IAMCollector(profile=self.profile, assume_role_arn=self.assume_role_arn)
                iam_data = collector.collect()
                for skip in iam_data.get("skipped", []):
                    skipped_reasons[f"iam/{skip.get('check')}"] = skip.get("reason", "unknown")
                    checks_skipped += 1

                context = {"account_id": self.account_id}

                # Evaluate root MFA
                root_mfa_rule = registry.get_rule("IAM-005")
                if root_mfa_rule:
                    mfa_finding = root_mfa_rule.evaluate(iam_data.get("account_summary"), context)
                    if mfa_finding:
                        checks_failed += 1
                        findings.append(mfa_finding)
                    else:
                        checks_passed += 1

                # Evaluate customer-managed policies
                policies = iam_data.get("policies", [])
                total_resources += len(policies)
                for pol in policies:
                    for rule_id in ["IAM-001", "IAM-002"]:
                        rule = registry.get_rule(rule_id)
                        if rule:
                            finding = rule.evaluate(pol, context)
                            if finding:
                                checks_failed += 1
                                findings.append(finding)
                            else:
                                checks_passed += 1

                # Evaluate roles & trust relationships
                roles = iam_data.get("roles", [])
                total_resources += len(roles)
                trust_rule = registry.get_rule("IAM-003")
                if trust_rule:
                    for r in roles:
                        finding = trust_rule.evaluate(r, context)
                        if finding:
                            checks_failed += 1
                            findings.append(finding)
                        else:
                            checks_passed += 1
            except Exception as e:
                logger.error(f"IAM audit failure: {str(e)}")
                skipped_reasons["iam/global"] = f"Error: {str(e)}"
                checks_skipped += 1

        # 3. EC2 Audit across requested regions
        if "ec2" in self.services:
            for region in self.regions:
                logger.info(f"Starting EC2 collection in {region}...")
                try:
                    collector = EC2Collector(profile=self.profile, assume_role_arn=self.assume_role_arn)
                    ec2_data = collector.collect_region(region)
                    for skip in ec2_data.get("skipped", []):
                        skipped_reasons[f"ec2/{region}/{skip.get('check')}"] = skip.get("reason", "unknown")
                        checks_skipped += 1

                    context = {"account_id": self.account_id, "region": region}

                    # Security groups
                    sgs = ec2_data.get("security_groups", [])
                    total_resources += len(sgs)
                    for sg in sgs:
                        for rule_id in ["EC2-001", "EC2-002", "EC2-003"]:
                            rule = registry.get_rule(rule_id)
                            if rule:
                                f = rule.evaluate(sg, context)
                                if f:
                                    checks_failed += 1
                                    findings.append(f)
                                else:
                                    checks_passed += 1

                    # Volumes
                    vols = ec2_data.get("volumes", [])
                    total_resources += len(vols)
                    vol_rule = registry.get_rule("EC2-004")
                    if vol_rule:
                        for v in vols:
                            f = vol_rule.evaluate(v, context)
                            if f:
                                checks_failed += 1
                                findings.append(f)
                            else:
                                checks_passed += 1

                    # Instances
                    instances = ec2_data.get("instances", [])
                    total_resources += len(instances)
                    inst_rule = registry.get_rule("EC2-005")
                    if inst_rule:
                        for inst in instances:
                            f = inst_rule.evaluate(inst, context)
                            if f:
                                checks_failed += 1
                                findings.append(f)
                            else:
                                checks_passed += 1
                except Exception as e:
                    logger.error(f"EC2 audit failure in {region}: {str(e)}")
                    skipped_reasons[f"ec2/{region}"] = f"Error: {str(e)}"
                    checks_skipped += 1

        # 4. RDS Audit across requested regions
        if "rds" in self.services:
            for region in self.regions:
                logger.info(f"Starting RDS collection in {region}...")
                try:
                    collector = RDSCollector(profile=self.profile, assume_role_arn=self.assume_role_arn)
                    rds_data = collector.collect_region(region)
                    for skip in rds_data.get("skipped", []):
                        skipped_reasons[f"rds/{region}/{skip.get('check')}"] = skip.get("reason", "unknown")
                        checks_skipped += 1

                    context = {"account_id": self.account_id, "region": region}
                    instances = rds_data.get("instances", [])
                    total_resources += len(instances)

                    for inst in instances:
                        for rule_id in ["RDS-001", "RDS-002", "RDS-003"]:
                            rule = registry.get_rule(rule_id)
                            if rule:
                                f = rule.evaluate(inst, context)
                                if f:
                                    checks_failed += 1
                                    findings.append(f)
                                else:
                                    checks_passed += 1
                except Exception as e:
                    logger.error(f"RDS audit failure in {region}: {str(e)}")
                    skipped_reasons[f"rds/{region}"] = f"Error: {str(e)}"
                    checks_skipped += 1

        # 5. CloudTrail Audit
        if "cloudtrail" in self.services:
            logger.info("Starting CloudTrail collection...")
            try:
                collector = CloudTrailCollector(profile=self.profile, assume_role_arn=self.assume_role_arn)
                ct_data = collector.collect(region=self.regions[0] if self.regions else "us-east-1")
                for skip in ct_data.get("skipped", []):
                    skipped_reasons[f"cloudtrail/{skip.get('check')}"] = skip.get("reason", "unknown")
                    checks_skipped += 1

                context = {"account_id": self.account_id, "region": self.regions[0] if self.regions else "us-east-1"}
                trails = ct_data.get("trails", [])
                total_resources += len(trails)

                # Check if no trails found
                missing_rule = registry.get_rule("LOG-001")
                if not trails and missing_rule:
                    f = missing_rule.evaluate(ct_data, context)
                    if f:
                        checks_failed += 1
                        findings.append(f)
                else:
                    checks_passed += 1

                for t in trails:
                    for rule_id in ["LOG-002", "LOG-003", "LOG-004"]:
                        rule = registry.get_rule(rule_id)
                        if rule:
                            f = rule.evaluate(t, context)
                            if f:
                                checks_failed += 1
                                findings.append(f)
                            else:
                                checks_passed += 1
            except Exception as e:
                logger.error(f"CloudTrail audit failure: {str(e)}")
                skipped_reasons["cloudtrail/global"] = f"Error: {str(e)}"
                checks_skipped += 1

        # Deduplicate and sanitize findings
        deduped_findings: List[Dict[str, Any]] = []
        seen_keys = set()
        for f in findings:
            key = (f["rule_id"], f["resource_id"], f.get("region"))
            if key not in seen_keys:
                seen_keys.add(key)
                f["evidence"] = Sanitizer.sanitize_dict(f.get("evidence", {}))
                deduped_findings.append(f)

        score_res = self.risk_scorer.calculate(deduped_findings, total_resources=max(1, total_resources))

        status = "COMPLETED"
        if skipped_reasons and deduped_findings:
            status = "PARTIAL"
        elif skipped_reasons and not deduped_findings and total_resources == 0:
            status = "FAILED"

        return {
            "status": status,
            "risk_score": score_res["risk_score"],
            "total_resources_inspected": total_resources,
            "checks_passed": checks_passed,
            "checks_failed": checks_failed,
            "checks_skipped": checks_skipped,
            "findings": deduped_findings,
            "counts": score_res["counts"],
            "skipped_reasons": skipped_reasons,
        }
