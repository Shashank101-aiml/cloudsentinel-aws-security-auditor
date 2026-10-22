from typing import Any, Dict, List, Optional
from app.engine.base_rule import BaseRule

SENSITIVE_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _is_public_cidr(cidr: str) -> bool:
    return cidr in ["0.0.0.0/0", "::/0"]


def _allows_port_publicly(ip_permissions: List[Dict[str, Any]], target_port: int) -> List[Dict[str, Any]]:
    violating_rules = []
    for perm in ip_permissions:
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        ip_protocol = perm.get("IpProtocol")

        # Check if port matches or is all traffic (-1)
        port_matches = False
        if ip_protocol == "-1":
            port_matches = True
        elif from_port is not None and to_port is not None:
            if from_port <= target_port <= to_port:
                port_matches = True

        if port_matches:
            for ip_range in perm.get("IpRanges", []):
                if _is_public_cidr(ip_range.get("CidrIp", "")):
                    violating_rules.append({"protocol": ip_protocol, "port_range": f"{from_port}-{to_port}", "source": ip_range.get("CidrIp")})
            for ipv6_range in perm.get("Ipv6Ranges", []):
                if _is_public_cidr(ipv6_range.get("CidrIpv6", "")):
                    violating_rules.append({"protocol": ip_protocol, "port_range": f"{from_port}-{to_port}", "source": ipv6_range.get("CidrIpv6")})
    return violating_rules


class EC2PublicSSHRule(BaseRule):
    """EC2-001: Detects security groups allowing unrestricted ingress on port 22."""
    rule_id = "EC2-001"
    title = "Security Group Allows Public SSH (Port 22)"
    description = (
        "Security group ingress rules allow inbound SSH (TCP port 22) from the public internet "
        "(0.0.0.0/0 or ::/0), exposing servers to brute-force attacks."
    )
    severity = "CRITICAL"
    service = "ec2"
    resource_type = "AWS::EC2::SecurityGroup"
    references = [
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html#sg-rules-ssh"
    ]
    remediation_guidance = (
        "Restrict SSH access to specific trusted corporate IP addresses, a VPN, or use "
        "AWS Systems Manager Session Manager instead of public ingress."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ip_perms = resource.get("ip_permissions", [])
        violating = _allows_port_publicly(ip_perms, 22)
        if violating:
            evidence = {
                "group_id": resource.get("group_id"),
                "group_name": resource.get("group_name"),
                "vpc_id": resource.get("vpc_id"),
                "violating_ingress_rules": violating,
            }
            return self.build_finding(
                resource_id=resource.get("group_id"),
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class EC2PublicRDPRule(BaseRule):
    """EC2-002: Detects security groups allowing unrestricted ingress on port 3389."""
    rule_id = "EC2-002"
    title = "Security Group Allows Public RDP (Port 3389)"
    description = (
        "Security group ingress rules allow inbound Remote Desktop Protocol (TCP port 3389) "
        "from the public internet (0.0.0.0/0 or ::/0)."
    )
    severity = "CRITICAL"
    service = "ec2"
    resource_type = "AWS::EC2::SecurityGroup"
    references = [
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html#sg-rules-rdp"
    ]
    remediation_guidance = (
        "Restrict port 3389 access to known bastion IPs or establish a VPN/Direct Connect channel."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ip_perms = resource.get("ip_permissions", [])
        violating = _allows_port_publicly(ip_perms, 3389)
        if violating:
            evidence = {
                "group_id": resource.get("group_id"),
                "group_name": resource.get("group_name"),
                "vpc_id": resource.get("vpc_id"),
                "violating_ingress_rules": violating,
            }
            return self.build_finding(
                resource_id=resource.get("group_id"),
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class EC2SensitivePortsRule(BaseRule):
    """EC2-003: Detects security groups exposing sensitive backend or database ports to 0.0.0.0/0."""
    rule_id = "EC2-003"
    title = "Security Group Exposes Sensitive Port to Public Internet"
    description = (
        "Security group allows public internet access to sensitive services like databases, "
        "message brokers, or administration ports (e.g. MySQL, Postgres, Redis, Telnet)."
    )
    severity = "HIGH"
    service = "ec2"
    resource_type = "AWS::EC2::SecurityGroup"
    references = [
        "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"
    ]
    remediation_guidance = (
        "Remove 0.0.0.0/0 ingress on internal service ports and place instances in private subnets."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ip_perms = resource.get("ip_permissions", [])
        exposed_services = []

        for port, srv_name in SENSITIVE_PORTS.items():
            violating = _allows_port_publicly(ip_perms, port)
            if violating:
                exposed_services.append({"port": port, "service": srv_name, "rules": violating})

        if exposed_services:
            evidence = {
                "group_id": resource.get("group_id"),
                "group_name": resource.get("group_name"),
                "exposed_sensitive_services": exposed_services,
            }
            return self.build_finding(
                resource_id=resource.get("group_id"),
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class EC2UnencryptedEBSVolumeRule(BaseRule):
    """EC2-004: Detects unencrypted EBS storage volumes."""
    rule_id = "EC2-004"
    title = "EBS Volume Encryption Disabled"
    description = (
        "The EBS volume is not encrypted at rest, risking data exposure if snapshots or "
        "storage volumes are intercepted."
    )
    severity = "HIGH"
    service = "ec2"
    resource_type = "AWS::EC2::Volume"
    references = [
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
    ]
    remediation_guidance = (
        "Enable default EBS encryption on the AWS account/region. Migrate existing volumes "
        "by creating an encrypted snapshot and copying data."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        is_encrypted = resource.get("encrypted", False)
        if not is_encrypted:
            evidence = {
                "volume_id": resource.get("volume_id"),
                "availability_zone": resource.get("availability_zone"),
                "size_gb": resource.get("size_gb"),
                "encrypted": False,
            }
            return self.build_finding(
                resource_id=resource.get("volume_id"),
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None


class EC2PublicIPv4Rule(BaseRule):
    """EC2-005: Identifies EC2 instances with assigned public IPv4 addresses."""
    rule_id = "EC2-005"
    title = "EC2 Instance Assigned Public IPv4 Address"
    description = (
        "The EC2 instance is assigned a public IPv4 address, making it directly reachable from "
        "the internet. This is an informational/contextual finding to verify exposure."
    )
    severity = "INFO"
    service = "ec2"
    resource_type = "AWS::EC2::Instance"
    references = [
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html"
    ]
    remediation_guidance = (
        "If the instance does not require direct public ingress, place it in a private subnet "
        "behind an Application Load Balancer or NAT Gateway."
    )

    def evaluate(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pub_ip = resource.get("public_ip")
        if pub_ip:
            evidence = {
                "instance_id": resource.get("instance_id"),
                "public_ip": pub_ip,
                "private_ip": resource.get("private_ip"),
                "subnet_id": resource.get("subnet_id"),
                "vpc_id": resource.get("vpc_id"),
                "security_groups": resource.get("security_groups", []),
            }
            return self.build_finding(
                resource_id=resource.get("instance_id"),
                account_id=context.get("account_id", "UNKNOWN"),
                region=context.get("region"),
                evidence=evidence,
                confidence="CONFIRMED",
            )
        return None
