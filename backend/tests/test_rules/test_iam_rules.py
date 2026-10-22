from app.engine.rules.iam_rules import (
    IAMAdminPolicyRule,
    IAMWildcardActionRule,
    IAMRiskyTrustRelationshipRule,
    IAMRootMFARule,
)


def test_iam_001_admin_policy():
    rule = IAMAdminPolicyRule()
    admin_doc = {
        "name": "SuperAdmin",
        "arn": "arn:aws:iam::123:policy/SuperAdmin",
        "document": {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        },
    }
    f = rule.evaluate(admin_doc, {"account_id": "123"})
    assert f is not None
    assert f["rule_id"] == "IAM-001"
    assert f["severity"] == "CRITICAL"

    least_priv_doc = {
        "name": "S3Reader",
        "arn": "arn:aws:iam::123:policy/S3Reader",
        "document": {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bkt/*"}]
        },
    }
    assert rule.evaluate(least_priv_doc, {"account_id": "123"}) is None


def test_iam_002_wildcard_actions():
    rule = IAMWildcardActionRule()
    doc = {
        "name": "WildcardS3",
        "arn": "arn:aws:iam::123:policy/WildcardS3",
        "document": {
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::test/*"}]
        },
    }
    f = rule.evaluate(doc, {"account_id": "123"})
    assert f is not None
    assert f["rule_id"] == "IAM-002"


def test_iam_003_risky_trust():
    rule = IAMRiskyTrustRelationshipRule()
    risky_role = {
        "role_name": "OpenRole",
        "arn": "arn:aws:iam::123:role/OpenRole",
        "trust_policy": {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        },
    }
    f = rule.evaluate(risky_role, {"account_id": "123"})
    assert f is not None
    assert f["rule_id"] == "IAM-003"


def test_iam_005_root_mfa():
    rule = IAMRootMFARule()
    # MFA disabled
    summary_disabled = {"AccountMFAEnabled": 0}
    f1 = rule.evaluate(summary_disabled, {"account_id": "123"})
    assert f1 is not None
    assert f1["severity"] == "CRITICAL"
    assert f1["confidence"] == "CONFIRMED"

    # MFA enabled
    summary_enabled = {"AccountMFAEnabled": 1}
    assert rule.evaluate(summary_enabled, {"account_id": "123"}) is None

    # Missing / unavailable state returns UNKNOWN
    f_unknown = rule.evaluate(None, {"account_id": "123"})
    assert f_unknown is not None
    assert f_unknown["confidence"] == "UNKNOWN"
