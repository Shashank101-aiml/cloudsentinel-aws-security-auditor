from app.engine.rules.cloudtrail_rules import (
    CloudTrailMissingRule,
    CloudTrailNotLoggingRule,
    CloudTrailMultiRegionRule,
    CloudTrailLogFileValidationRule,
)


def test_log_001_missing_trail():
    rule = CloudTrailMissingRule()
    empty_ct = {"trails": []}
    f = rule.evaluate(empty_ct, {"account_id": "123", "region": "us-east-1"})
    assert f is not None
    assert f["severity"] == "CRITICAL"


def test_log_002_not_logging():
    rule = CloudTrailNotLoggingRule()
    paused_trail = {"name": "test-trail", "arn": "arn:123", "is_logging": False}
    f = rule.evaluate(paused_trail, {"account_id": "123", "region": "us-east-1"})
    assert f is not None
    assert f["severity"] == "CRITICAL"


def test_log_003_multi_region():
    rule = CloudTrailMultiRegionRule()
    single_region = {"name": "single-trail", "arn": "arn:123", "is_multi_region": False}
    f = rule.evaluate(single_region, {"account_id": "123", "region": "us-east-1"})
    assert f is not None
    assert f["severity"] == "MEDIUM"


def test_log_004_log_file_validation():
    rule = CloudTrailLogFileValidationRule()
    no_val = {"name": "noval-trail", "arn": "arn:123", "log_file_validation": False}
    f = rule.evaluate(no_val, {"account_id": "123", "region": "us-east-1"})
    assert f is not None
    assert f["severity"] == "MEDIUM"
