from app.engine.rules.s3_rules import (
    S3PublicExposureRule,
    S3BlockPublicAccessRule,
    S3ServerSideEncryptionRule,
    S3VersioningRule,
    S3SecureTransportRule,
)


def test_s3_001_public_acl_detected():
    rule = S3PublicExposureRule()
    resource = {
        "name": "public-bucket-test",
        "region": "us-east-1",
        "acl": [{"grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"}],
        "public_access_block": {"IgnorePublicAcls": False, "RestrictPublicBuckets": False},
    }
    context = {"account_id": "111122223333"}
    finding = rule.evaluate(resource, context)
    assert finding is not None
    assert finding["rule_id"] == "S3-001"
    assert finding["severity"] == "CRITICAL"
    assert "public-bucket-test" in finding["resource_id"]


def test_s3_001_compliant_when_blocked_by_pab():
    rule = S3PublicExposureRule()
    resource = {
        "name": "blocked-bucket-test",
        "region": "us-east-1",
        "acl": [{"grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ"}],
        "public_access_block": {"IgnorePublicAcls": True, "RestrictPublicBuckets": True},
    }
    context = {"account_id": "111122223333"}
    finding = rule.evaluate(resource, context)
    assert finding is None


def test_s3_002_block_public_access_disabled():
    rule = S3BlockPublicAccessRule()
    resource = {
        "name": "unprotected-bucket",
        "region": "us-east-1",
        "public_access_block": None,
    }
    finding = rule.evaluate(resource, {"account_id": "111122223333"})
    assert finding is not None
    assert finding["rule_id"] == "S3-002"
    assert finding["severity"] == "HIGH"


def test_s3_002_compliant():
    rule = S3BlockPublicAccessRule()
    resource = {
        "name": "protected-bucket",
        "region": "us-east-1",
        "public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    }
    assert rule.evaluate(resource, {"account_id": "111122223333"}) is None


def test_s3_003_encryption():
    rule = S3ServerSideEncryptionRule()
    unenc = {"name": "unenc-bucket", "region": "us-east-1", "encryption": None}
    assert rule.evaluate(unenc, {"account_id": "111122223333"}) is not None

    enc = {
        "name": "enc-bucket",
        "region": "us-east-1",
        "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
    }
    assert rule.evaluate(enc, {"account_id": "111122223333"}) is None


def test_s3_004_versioning():
    rule = S3VersioningRule()
    disabled = {"name": "unver-bucket", "region": "us-east-1", "versioning": "Suspended"}
    assert rule.evaluate(disabled, {"account_id": "111122223333"}) is not None

    enabled = {"name": "ver-bucket", "region": "us-east-1", "versioning": "Enabled"}
    assert rule.evaluate(enabled, {"account_id": "111122223333"}) is None


def test_s3_005_secure_transport():
    rule = S3SecureTransportRule()
    insecure = {"name": "insecure-bucket", "region": "us-east-1", "policy": None}
    assert rule.evaluate(insecure, {"account_id": "111122223333"}) is not None

    secure = {
        "name": "secure-bucket",
        "region": "us-east-1",
        "policy": {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ]
        },
    }
    assert rule.evaluate(secure, {"account_id": "111122223333"}) is None
