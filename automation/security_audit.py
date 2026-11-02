"""Audit ingress in one managed VPC; optional rule-ID based remediation."""
import ipaddress
import json
import logging
import os

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
DEFAULT_PORTS = (22, 3389, 3306, 5432, 6379, 27017)


def exposed_ports(rule, ports=DEFAULT_PORTS):
    """Only unrestricted IPv4/IPv6 ingress to protected TCP/UDP ports."""
    if rule.get("IsEgress"):
        return []
    cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
    if not cidr or ipaddress.ip_network(cidr).prefixlen != 0:
        return []
    protocol = str(rule.get("IpProtocol"))
    if protocol == "-1":
        return list(ports)
    if protocol not in ("tcp", "udp", "6", "17"):
        return []
    return [p for p in ports if rule.get("FromPort", 65536) <= p <= rule.get("ToPort", -1)]


def audit(ec2, vpc_id, remediate=False, ports=DEFAULT_PORTS):
    findings = []
    groups = ec2.get_paginator("describe_security_groups")
    for page in groups.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        for group in page["SecurityGroups"]:
            rules = ec2.get_paginator("describe_security_group_rules")
            for batch in rules.paginate(Filters=[{"Name": "group-id", "Values": [group["GroupId"]]}]):
                for rule in batch["SecurityGroupRules"]:
                    exposed = exposed_ports(rule, ports)
                    if not exposed:
                        continue
                    finding = {
                        "group_id": group["GroupId"],
                        "rule_id": rule["SecurityGroupRuleId"],
                        "cidr": rule.get("CidrIpv4") or rule.get("CidrIpv6"),
                        "ports": exposed,
                        "status": "detected",
                    }
                    if remediate:
                        try:
                            ec2.revoke_security_group_ingress(
                                GroupId=group["GroupId"],
                                SecurityGroupRuleIds=[rule["SecurityGroupRuleId"]],
                            )
                            finding["status"] = "revoked"
                        except Exception as exc:
                            # A concurrent deletion is safe; other failures must retry.
                            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
                            if code not in ("InvalidSecurityGroupRuleId.NotFound", "InvalidPermission.NotFound"):
                                raise
                            finding["status"] = "already_removed"
                    LOG.warning(json.dumps(finding, sort_keys=True))
                    findings.append(finding)
    return findings


def handler(event, context):
    import boto3

    ports = tuple(int(p) for p in os.environ.get("PROTECTED_PORTS", "22,3389,3306,5432,6379,27017").split(","))
    findings = audit(
        boto3.client("ec2"), os.environ["VPC_ID"],
        os.environ.get("REMEDIATE", "false").lower() == "true", ports,
    )
    # One message per finding stays below SNS message limits even for large VPCs.
    sns = boto3.client("sns")
    for finding in findings:
        sns.publish(TopicArn=os.environ["TOPIC_ARN"], Subject="VPC security finding", Message=json.dumps(finding))
    result = {"vpc_id": os.environ["VPC_ID"], "finding_count": len(findings)}
    LOG.info(json.dumps(result))
    return result
