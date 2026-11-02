import unittest
from unittest.mock import Mock
from automation.security_audit import audit, exposed_ports


def rule(**changes):
    value = dict(IsEgress=False, CidrIpv4="0.0.0.0/0", IpProtocol="tcp", FromPort=22, ToPort=22, SecurityGroupRuleId="sgr-123")
    value.update(changes)
    return value


class DetectionTests(unittest.TestCase):
    def test_public_ssh(self):
        self.assertEqual(exposed_ports(rule()), [22])

    def test_ipv6_rdp(self):
        self.assertEqual(exposed_ports(rule(CidrIpv4=None, CidrIpv6="::/0", FromPort=3389, ToPort=3389)), [3389])

    def test_all_protocols(self):
        self.assertIn(5432, exposed_ports(rule(IpProtocol="-1")))

    def test_range_and_udp(self):
        self.assertEqual(exposed_ports(rule(IpProtocol="17", FromPort=20, ToPort=23)), [22])

    def test_safe_rules(self):
        for changes in [dict(IsEgress=True), dict(CidrIpv4="10.0.0.0/8"), dict(FromPort=443, ToPort=443), dict(IpProtocol="icmp"), dict(CidrIpv4=None)]:
            with self.subTest(changes=changes):
                self.assertEqual(exposed_ports(rule(**changes)), [])

    def test_custom_ports(self):
        self.assertEqual(exposed_ports(rule(FromPort=8443, ToPort=8443), [8443]), [8443])


class AuditTests(unittest.TestCase):
    def client(self):
        ec2 = Mock()
        groups, rules = Mock(), Mock()
        groups.paginate.return_value = [{"SecurityGroups": [{"GroupId": "sg-123"}]}, {"SecurityGroups": []}]
        rules.paginate.return_value = [{"SecurityGroupRules": [rule()]}, {"SecurityGroupRules": [rule(FromPort=443, ToPort=443)]}]
        ec2.get_paginator.side_effect = lambda operation: groups if operation == "describe_security_groups" else rules
        return ec2, groups

    def test_detect_only_and_scope(self):
        ec2, groups = self.client()
        findings = audit(ec2, "vpc-123")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "detected")
        ec2.revoke_security_group_ingress.assert_not_called()
        groups.paginate.assert_called_once_with(Filters=[{"Name": "vpc-id", "Values": ["vpc-123"]}])

    def test_remediation_uses_rule_id(self):
        ec2, _ = self.client()
        self.assertEqual(audit(ec2, "vpc-123", True)[0]["status"], "revoked")
        ec2.revoke_security_group_ingress.assert_called_once_with(GroupId="sg-123", SecurityGroupRuleIds=["sgr-123"])

    def test_concurrent_deletion(self):
        ec2, _ = self.client()
        error = Exception("removed")
        error.response = {"Error": {"Code": "InvalidSecurityGroupRuleId.NotFound"}}
        ec2.revoke_security_group_ingress.side_effect = error
        self.assertEqual(audit(ec2, "vpc-123", True)[0]["status"], "already_removed")

    def test_permission_failure_propagates(self):
        ec2, _ = self.client()
        ec2.revoke_security_group_ingress.side_effect = RuntimeError("access denied")
        with self.assertRaises(RuntimeError):
            audit(ec2, "vpc-123", True)

class HandlerTests(unittest.TestCase):
    def test_notification_and_environment(self):
        import os
        import sys
        from unittest.mock import patch
        from automation.security_audit import handler

        sdk = Mock()
        sns = Mock()
        sdk.client.side_effect = lambda service: sns if service == "sns" else Mock()
        finding = {"rule_id": "sgr-123", "status": "detected"}
        env = {"VPC_ID": "vpc-123", "TOPIC_ARN": "arn:example", "PROTECTED_PORTS": "22,3389", "REMEDIATE": "false"}
        with patch.dict(sys.modules, {"boto3": sdk}), patch.dict(os.environ, env), patch("automation.security_audit.audit", return_value=[finding]) as scan:
            self.assertEqual(handler({}, None)["finding_count"], 1)
            self.assertFalse(scan.call_args.args[2])
            self.assertEqual(scan.call_args.args[3], (22, 3389))
            sns.publish.assert_called_once()
            self.assertEqual(sns.publish.call_args.kwargs["TopicArn"], "arn:example")

    def test_clean_scan_does_not_publish(self):
        import os
        import sys
        from unittest.mock import patch
        from automation.security_audit import handler

        sdk = Mock()
        with patch.dict(sys.modules, {"boto3": sdk}), patch.dict(os.environ, {"VPC_ID": "vpc-123", "TOPIC_ARN": "arn:example"}), patch("automation.security_audit.audit", return_value=[]):
            self.assertEqual(handler({}, None)["finding_count"], 0)
            sdk.client.return_value.publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
