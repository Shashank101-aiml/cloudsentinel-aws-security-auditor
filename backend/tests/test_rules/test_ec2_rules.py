from app.engine.rules.ec2_rules import (
    EC2PublicSSHRule,
    EC2PublicRDPRule,
    EC2SensitivePortsRule,
    EC2UnencryptedEBSVolumeRule,
    EC2PublicIPv4Rule,
)


def test_ec2_001_ssh():
    rule = EC2PublicSSHRule()
    open_sg = {
        "group_id": "sg-123",
        "group_name": "ssh-open",
        "ip_permissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    }
    assert rule.evaluate(open_sg, {"account_id": "123", "region": "us-east-1"}) is not None

    closed_sg = {
        "group_id": "sg-456",
        "group_name": "ssh-restricted",
        "ip_permissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}
        ],
    }
    assert rule.evaluate(closed_sg, {"account_id": "123", "region": "us-east-1"}) is None


def test_ec2_002_rdp():
    rule = EC2PublicRDPRule()
    rdp_sg = {
        "group_id": "sg-rdp",
        "ip_permissions": [
            {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
        ],
    }
    assert rule.evaluate(rdp_sg, {"account_id": "123", "region": "us-east-1"}) is not None


def test_ec2_003_sensitive_ports():
    rule = EC2SensitivePortsRule()
    mysql_sg = {
        "group_id": "sg-db",
        "ip_permissions": [
            {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    }
    f = rule.evaluate(mysql_sg, {"account_id": "123", "region": "us-east-1"})
    assert f is not None
    assert f["severity"] == "HIGH"


def test_ec2_004_ebs_unencrypted():
    rule = EC2UnencryptedEBSVolumeRule()
    unenc = {"volume_id": "vol-123", "encrypted": False, "size_gb": 50}
    assert rule.evaluate(unenc, {"account_id": "123", "region": "us-east-1"}) is not None

    enc = {"volume_id": "vol-456", "encrypted": True, "size_gb": 50}
    assert rule.evaluate(enc, {"account_id": "123", "region": "us-east-1"}) is None


def test_ec2_005_public_ipv4():
    rule = EC2PublicIPv4Rule()
    pub = {"instance_id": "i-123", "public_ip": "54.210.1.2"}
    f = rule.evaluate(pub, {"account_id": "123", "region": "us-east-1"})
    assert f is not None
    assert f["severity"] == "INFO"

    priv = {"instance_id": "i-456", "public_ip": None, "private_ip": "10.0.1.5"}
    assert rule.evaluate(priv, {"account_id": "123", "region": "us-east-1"}) is None
