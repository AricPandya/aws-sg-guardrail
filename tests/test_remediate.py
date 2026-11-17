"""Unit tests: run with  `python -m pytest -q`  (no AWS account needed)."""
import os
import sys
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ["ALERT_TOPIC_ARN"] = "arn:aws:sns:us-east-1:111122223333:alerts"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import remediate  # noqa: E402


def rule(rule_id, proto="tcp", low=22, high=22, v4="0.0.0.0/0", v6=None, egress=False):
    r = {"SecurityGroupRuleId": rule_id, "IpProtocol": proto, "FromPort": low,
         "ToPort": high, "IsEgress": egress}
    if v4:
        r["CidrIpv4"] = v4
    if v6:
        r["CidrIpv6"] = v6
    return r


@pytest.fixture
def fake_ec2(monkeypatch):
    ec2, sns = MagicMock(), MagicMock()
    monkeypatch.setattr(remediate, "ec2", ec2)
    monkeypatch.setattr(remediate, "sns", sns)
    monkeypatch.setattr(remediate, "DRY_RUN", False)
    ec2.describe_security_groups.return_value = {"SecurityGroups": [{"Tags": []}]}

    def set_rules(rules):
        ec2.get_paginator.return_value.paginate.return_value = [{"SecurityGroupRules": rules}]

    ec2.set_rules = set_rules
    ec2.sns = sns
    return ec2


def event(group_id="sg-123", **extra):
    detail = {"eventName": "AuthorizeSecurityGroupIngress",
              "requestParameters": {"groupId": group_id},
              "userIdentity": {"arn": "arn:aws:iam::111122223333:user/dev"}}
    detail.update(extra)
    return {"detail": detail}


# --- pure logic ---------------------------------------------------------
@pytest.mark.parametrize("r,expected", [
    (rule("a"), True),                                   # SSH to world
    (rule("b", low=3389, high=3389), True),              # RDP
    (rule("c", low=443, high=443), False),               # HTTPS is fine
    (rule("d", low=0, high=65535), True),                # range includes 22
    (rule("e", proto="-1", low=-1, high=-1), True),      # all traffic
    (rule("f", v4="10.0.0.0/8"), False),                 # private CIDR
    (rule("g", v4=None, v6="::/0"), True),               # IPv6 world
    (rule("h", egress=True), False),                     # egress ignored
    (rule("i", proto="icmp", low=-1, high=-1), False),   # ICMP out of scope
])
def test_is_risky(r, expected):
    assert remediate.is_risky(r) is expected


def test_group_id_from_modify_and_response():
    detail = {
        "requestParameters": {"ModifySecurityGroupRulesRequest": {"GroupId": "sg-mod"}},
        "responseElements": {"securityGroupRuleSet": {"items": [{"groupId": "sg-resp"}]}},
    }
    assert remediate.group_ids_from_event(detail) == {"sg-mod", "sg-resp"}


# --- handler ------------------------------------------------------------
def test_revokes_only_risky_rules(fake_ec2):
    fake_ec2.set_rules([rule("sgr-ssh"), rule("sgr-https", low=443, high=443)])
    out = remediate.handler(event(), None)
    fake_ec2.revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-123", SecurityGroupRuleIds=["sgr-ssh"])
    assert out["results"][0]["action"] == "revoked"
    fake_ec2.sns.publish.assert_called_once()


def test_exempt_group_untouched(fake_ec2):
    fake_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [{"Tags": [{"Key": "SecurityException", "Value": "approved"}]}]}
    fake_ec2.set_rules([rule("sgr-ssh")])
    out = remediate.handler(event(), None)
    fake_ec2.revoke_security_group_ingress.assert_not_called()
    assert out["results"][0]["action"] == "exempt"


def test_dry_run_does_not_revoke(fake_ec2, monkeypatch):
    monkeypatch.setattr(remediate, "DRY_RUN", True)
    fake_ec2.set_rules([rule("sgr-ssh")])
    out = remediate.handler(event(), None)
    fake_ec2.revoke_security_group_ingress.assert_not_called()
    assert out["results"][0]["action"] == "would-revoke"


def test_failed_api_call_ignored(fake_ec2):
    out = remediate.handler(event(errorCode="UnauthorizedOperation"), None)
    assert out == {"results": []}
    fake_ec2.describe_security_groups.assert_not_called()


def test_deleted_group_is_not_an_error(fake_ec2):
    from botocore.exceptions import ClientError
    fake_ec2.describe_security_groups.side_effect = ClientError(
        {"Error": {"Code": "InvalidGroup.NotFound", "Message": "gone"}}, "DescribeSecurityGroups")
    out = remediate.handler(event(), None)
    assert out["results"][0]["action"] == "gone"
