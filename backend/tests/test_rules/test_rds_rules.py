from app.engine.rules.rds_rules import (
    RDSPublicAccessRule,
    RDSStorageEncryptionRule,
    RDSBackupRetentionRule,
)


def test_rds_001_public_access():
    rule = RDSPublicAccessRule()
    pub_db = {"db_instance_identifier": "analytics-db", "publicly_accessible": True, "engine": "postgres"}
    f = rule.evaluate(pub_db, {"account_id": "123", "region": "us-east-1"})
    assert f is not None
    assert f["severity"] == "CRITICAL"

    priv_db = {"db_instance_identifier": "private-db", "publicly_accessible": False}
    assert rule.evaluate(priv_db, {"account_id": "123", "region": "us-east-1"}) is None


def test_rds_002_storage_encryption():
    rule = RDSStorageEncryptionRule()
    unenc = {"db_instance_identifier": "unenc-db", "storage_encrypted": False}
    assert rule.evaluate(unenc, {"account_id": "123", "region": "us-east-1"}) is not None

    enc = {"db_instance_identifier": "enc-db", "storage_encrypted": True}
    assert rule.evaluate(enc, {"account_id": "123", "region": "us-east-1"}) is None


def test_rds_003_backup_retention():
    rule = RDSBackupRetentionRule()
    zero_backup = {"db_instance_identifier": "nobackup-db", "backup_retention_period": 0}
    f = rule.evaluate(zero_backup, {"account_id": "123", "region": "us-east-1"})
    assert f is not None
    assert f["severity"] == "HIGH"

    good_backup = {"db_instance_identifier": "safe-db", "backup_retention_period": 14}
    assert rule.evaluate(good_backup, {"account_id": "123", "region": "us-east-1"}) is None
