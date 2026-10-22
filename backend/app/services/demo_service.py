from datetime import datetime, timezone
from typing import Dict, List, Any
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.models.finding import Finding
from app.engine.risk_scorer import RiskScorer

DEMO_ACCOUNT_ID = "123456789012"
DEMO_SCAN_ID = "demo-scan-default-000000000001"


class DemoService:
    """Manages deterministic demo datasets demonstrating real security evaluations."""

    @staticmethod
    def get_sample_findings(scan_id: str = DEMO_SCAN_ID) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        return [
            {
                "id": "demo-finding-s3-001",
                "scan_id": scan_id,
                "rule_id": "S3-001",
                "title": "S3 Bucket Publicly Accessible",
                "description": "Bucket 'customer-invoices-backup-prod' has an AllUsers grant allowing unauthenticated public read.",
                "severity": "CRITICAL",
                "status": "OPEN",
                "confidence": "CONFIRMED",
                "service": "s3",
                "resource_id": "customer-invoices-backup-prod",
                "resource_type": "AWS::S3::Bucket",
                "region": "us-east-1",
                "account_id": DEMO_ACCOUNT_ID,
                "evidence": {
                    "bucket_name": "customer-invoices-backup-prod",
                    "public_acl_grants": [
                        {
                            "grantee_type": "Group",
                            "grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                            "permission": "READ",
                        }
                    ],
                    "block_public_access": {"BlockPublicAcls": False, "IgnorePublicAcls": False},
                },
                "remediation": "Enable S3 Block Public Access and remove the AllUsers READ ACL grant.",
                "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
                "first_seen": now,
                "last_seen": now,
            },
            {
                "id": "demo-finding-ec2-001",
                "scan_id": scan_id,
                "rule_id": "EC2-001",
                "title": "Security Group Allows Public SSH (Port 22)",
                "description": "Security group 'launch-wizard-1' exposes port 22 directly to 0.0.0.0/0.",
                "severity": "CRITICAL",
                "status": "OPEN",
                "confidence": "CONFIRMED",
                "service": "ec2",
                "resource_id": "sg-01ab23cd45ef67890",
                "resource_type": "AWS::EC2::SecurityGroup",
                "region": "us-east-1",
                "account_id": DEMO_ACCOUNT_ID,
                "evidence": {
                    "group_id": "sg-01ab23cd45ef67890",
                    "group_name": "launch-wizard-1",
                    "violating_ingress_rules": [
                        {"protocol": "tcp", "port_range": "22-22", "source": "0.0.0.0/0"}
                    ],
                },
                "remediation": "Remove the 0.0.0.0/0 ingress rule. Restrict SSH to your corporate IP range or use AWS Systems Manager.",
                "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html#sg-rules-ssh"],
                "first_seen": now,
                "last_seen": now,
            },
            {
                "id": "demo-finding-iam-001",
                "scan_id": scan_id,
                "rule_id": "IAM-001",
                "title": "IAM Policy Grants Full Administrative Privileges",
                "description": "Policy 'DeveloperWildcardAdminPolicy' allows Action: * on Resource: * without condition constraints.",
                "severity": "CRITICAL",
                "status": "OPEN",
                "confidence": "CONFIRMED",
                "service": "iam",
                "resource_id": "arn:aws:iam::123456789012:policy/DeveloperWildcardAdminPolicy",
                "resource_type": "AWS::IAM::Policy",
                "region": "global",
                "account_id": DEMO_ACCOUNT_ID,
                "evidence": {
                    "policy_name": "DeveloperWildcardAdminPolicy",
                    "admin_statements": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                },
                "remediation": "Restrict policy statements to specific required service actions and bounded resource ARNs.",
                "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"],
                "first_seen": now,
                "last_seen": now,
            },
            {
                "id": "demo-finding-rds-001",
                "scan_id": scan_id,
                "rule_id": "RDS-001",
                "title": "RDS Database Instance Publicly Accessible",
                "description": "PostgreSQL instance 'prod-analytics-db' is set to PubliclyAccessible=True with a public IP endpoint.",
                "severity": "CRITICAL",
                "status": "OPEN",
                "confidence": "CONFIRMED",
                "service": "rds",
                "resource_id": "prod-analytics-db",
                "resource_type": "AWS::RDS::DBInstance",
                "region": "us-east-1",
                "account_id": DEMO_ACCOUNT_ID,
                "evidence": {
                    "db_instance_identifier": "prod-analytics-db",
                    "engine": "postgres",
                    "endpoint": "prod-analytics-db.c7x89q.us-east-1.rds.amazonaws.com",
                    "port": 5432,
                },
                "remediation": "Modify DB instance to disable PubliclyAccessible and route through private VPC subnets.",
                "references": ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"],
                "first_seen": now,
                "last_seen": now,
            },
            {
                "id": "demo-finding-ec2-004",
                "scan_id": scan_id,
                "rule_id": "EC2-004",
                "title": "EBS Volume Encryption Disabled",
                "description": "Volume 'vol-087a6b5c4d3e2f1a0' (100GB gp3) is unencrypted at rest.",
                "severity": "HIGH",
                "status": "OPEN",
                "confidence": "CONFIRMED",
                "service": "ec2",
                "resource_id": "vol-087a6b5c4d3e2f1a0",
                "resource_type": "AWS::EC2::Volume",
                "region": "us-east-1",
                "account_id": DEMO_ACCOUNT_ID,
                "evidence": {
                    "volume_id": "vol-087a6b5c4d3e2f1a0",
                    "size_gb": 100,
                    "availability_zone": "us-east-1a",
                    "encrypted": False,
                },
                "remediation": "Enable account-level EBS encryption by default and migrate unencrypted volumes via snapshot copy.",
                "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"],
                "first_seen": now,
                "last_seen": now,
            },
            {
                "id": "demo-finding-cloudtrail-002",
                "scan_id": scan_id,
                "rule_id": "LOG-002",
                "title": "CloudTrail Trail Is Not Actively Logging",
                "description": "Trail 'security-audit-trail-prod' is currently paused (IsLogging=False).",
                "severity": "CRITICAL",
                "status": "OPEN",
                "confidence": "CONFIRMED",
                "service": "cloudtrail",
                "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/security-audit-trail-prod",
                "resource_type": "AWS::CloudTrail::Trail",
                "region": "us-east-1",
                "account_id": DEMO_ACCOUNT_ID,
                "evidence": {
                    "trail_name": "security-audit-trail-prod",
                    "is_logging": False,
                },
                "remediation": "Start logging on the CloudTrail trail via the AWS Console or CLI.",
                "references": ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-turning-off-logging.html"],
                "first_seen": now,
                "last_seen": now,
            },
            {
                "id": "demo-finding-s3-005",
                "scan_id": scan_id,
                "rule_id": "S3-005",
                "title": "S3 Bucket Allows Insecure (HTTP) Transport",
                "description": "Bucket 'app-static-assets-cdn' lacks an aws:SecureTransport deny policy statement.",
                "severity": "MEDIUM",
                "status": "OPEN",
                "confidence": "CONFIRMED",
                "service": "s3",
                "resource_id": "app-static-assets-cdn",
                "resource_type": "AWS::S3::Bucket",
                "region": "us-east-1",
                "account_id": DEMO_ACCOUNT_ID,
                "evidence": {
                    "bucket_name": "app-static-assets-cdn",
                    "has_secure_transport_policy": False,
                },
                "remediation": "Add a bucket policy denying s3:* actions when 'aws:SecureTransport' equals false.",
                "references": ["https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule-s3-bucket-ssl-requests-only/"],
                "first_seen": now,
                "last_seen": now,
            },
            {
                "id": "demo-finding-ec2-005",
                "scan_id": scan_id,
                "rule_id": "EC2-005",
                "title": "EC2 Instance Assigned Public IPv4 Address",
                "description": "Instance 'i-0987654321fedcba0' has a public IP (54.210.12.34). Contextual observation.",
                "severity": "INFO",
                "status": "OPEN",
                "confidence": "CONFIRMED",
                "service": "ec2",
                "resource_id": "i-0987654321fedcba0",
                "resource_type": "AWS::EC2::Instance",
                "region": "us-east-1",
                "account_id": DEMO_ACCOUNT_ID,
                "evidence": {
                    "instance_id": "i-0987654321fedcba0",
                    "public_ip": "54.210.12.34",
                    "private_ip": "10.0.1.55",
                    "subnet_id": "subnet-0123456789abcdef0",
                },
                "remediation": "Verify whether direct public IP assignment is required or if a load balancer should be used.",
                "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html"],
                "first_seen": now,
                "last_seen": now,
            },
        ]

    @classmethod
    def seed_demo_data(cls, db: Session, force: bool = False) -> Scan:
        """Seeds the standard deterministic demo scan and findings if not already present."""
        existing = db.query(Scan).filter(Scan.id == DEMO_SCAN_ID).first()
        if existing and not force:
            return existing

        if existing and force:
            db.delete(existing)
            db.commit()

        findings_data = cls.get_sample_findings(DEMO_SCAN_ID)
        scorer = RiskScorer()
        score_res = scorer.calculate(findings_data, total_resources=18)

        now = datetime.now(timezone.utc)
        scan = Scan(
            id=DEMO_SCAN_ID,
            account_id=DEMO_ACCOUNT_ID,
            scan_mode="demo",
            status="COMPLETED",
            regions=["us-east-1", "us-west-2"],
            services=["s3", "iam", "ec2", "rds", "cloudtrail"],
            risk_score=score_res["risk_score"],
            total_resources_inspected=18,
            checks_passed=11,
            checks_failed=len(findings_data),
            checks_skipped=0,
            findings_count=len(findings_data),
            critical_count=score_res["counts"]["CRITICAL"],
            high_count=score_res["counts"]["HIGH"],
            medium_count=score_res["counts"]["MEDIUM"],
            low_count=score_res["counts"]["LOW"],
            info_count=score_res["counts"]["INFO"],
            error_message=None,
            skipped_reasons={},
            started_at=now,
            completed_at=now,
        )
        db.add(scan)
        db.flush()

        for f_data in findings_data:
            finding = Finding(**f_data)
            db.add(finding)

        db.commit()
        db.refresh(scan)
        return scan
