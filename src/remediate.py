"""
Security group guardrail.

Triggered by EventBridge when CloudTrail records an
AuthorizeSecurityGroupIngress or ModifySecurityGroupRules call.
Revokes any ingress rule that opens a sensitive port (or all traffic)
to 0.0.0.0/0 or ::/0, then sends an SNS alert saying who did it.
"""
import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    int(p)
    for p in os.environ.get(
        "SENSITIVE_PORTS", "22,3389,3306,5432,1433,6379,9200,27017"
    ).split(",")
    if p.strip()
}
EXEMPT_TAG_KEY = os.environ.get("EXEMPT_TAG_KEY", "SecurityException")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"


# ---------------------------------------------------------------- helpers
def group_ids_from_event(detail: dict) -> set:
    """Pull every security group ID out of a CloudTrail event.

    The ID can be in different places depending on the API and on how it
    was called (by ID, by name in a default VPC, or via ModifySecurityGroupRules).
    """
    ids = set()
    params = detail.get("requestParameters") or {}
    if params.get("groupId"):
        ids.add(params["groupId"])

    modify = params.get("ModifySecurityGroupRulesRequest") or {}
    if modify.get("GroupId"):
        ids.add(modify["GroupId"])

    # Fallback: the response lists the rules that were actually created.
    response = detail.get("responseElements") or {}
    for item in (response.get("securityGroupRuleSet") or {}).get("items") or []:
        if item.get("groupId"):
            ids.add(item["groupId"])
    return ids


def is_world_open(rule: dict) -> bool:
    return rule.get("CidrIpv4") in OPEN_CIDRS or rule.get("CidrIpv6") in OPEN_CIDRS


def covers_sensitive_port(rule: dict) -> bool:
    protocol = str(rule.get("IpProtocol"))
    if protocol == "-1":  # "All traffic"
        return True
    if protocol not in ("tcp", "udp", "6", "17"):
        return False  # ICMP etc. is out of scope for this guardrail
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if low is None or high is None or low == -1:
        return True
    return any(low <= port <= high for port in SENSITIVE_PORTS)


def is_risky(rule: dict) -> bool:
    return (
        not rule.get("IsEgress", False)
        and is_world_open(rule)
        and covers_sensitive_port(rule)
    )


def is_exempt(group_id: str) -> bool:
    groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    tags = {t["Key"]: t["Value"] for t in groups[0].get("Tags", [])}
    return tags.get(EXEMPT_TAG_KEY, "").lower() == "approved"


def find_risky_rules(group_id: str) -> list:
    risky = []
    paginator = ec2.get_paginator("describe_security_group_rules")
    for page in paginator.paginate(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    ):
        risky.extend(r for r in page["SecurityGroupRules"] if is_risky(r))
    return risky


def describe_rule(rule: dict) -> str:
    cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
    proto = "all" if str(rule.get("IpProtocol")) == "-1" else rule.get("IpProtocol")
    return f"{rule['SecurityGroupRuleId']}: {proto} {rule.get('FromPort')}-{rule.get('ToPort')} from {cidr}"


def notify(subject: str, body: dict) -> None:
    if not ALERT_TOPIC_ARN:
        return
    sns.publish(
        TopicArn=ALERT_TOPIC_ARN,
        Subject=subject[:100],  # SNS subject limit
        Message=json.dumps(body, indent=2, default=str),
    )


# ------------------------------------------------------------ remediation
def remediate_group(group_id: str, detail: dict) -> dict:
    actor = (detail.get("userIdentity") or {}).get("arn", "unknown")

    if is_exempt(group_id):
        LOG.info("Skipping %s: tagged %s=approved", group_id, EXEMPT_TAG_KEY)
        return {"groupId": group_id, "action": "exempt"}

    risky = find_risky_rules(group_id)
    if not risky:
        return {"groupId": group_id, "action": "none"}

    rule_ids = [r["SecurityGroupRuleId"] for r in risky]
    summary = [describe_rule(r) for r in risky]

    if DRY_RUN:
        action = "would-revoke"
    else:
        ec2.revoke_security_group_ingress(
            GroupId=group_id, SecurityGroupRuleIds=rule_ids
        )
        action = "revoked"

    LOG.info(json.dumps({"groupId": group_id, "action": action, "rules": summary, "actor": actor}))
    notify(
        f"[SG Guardrail] {action} {len(rule_ids)} rule(s) on {group_id}",
        {
            "action": action,
            "groupId": group_id,
            "region": detail.get("awsRegion"),
            "account": detail.get("recipientAccountId"),
            "changedBy": actor,
            "sourceIp": detail.get("sourceIPAddress"),
            "eventName": detail.get("eventName"),
            "eventTime": detail.get("eventTime"),
            "rules": summary,
            "howToGetAnException": f"Tag the group {EXEMPT_TAG_KEY}=approved (restricted by SCP)",
        },
    )
    return {"groupId": group_id, "action": action, "rules": rule_ids}


def handler(event, context):
    detail = event.get("detail") or {}

    # A failed API call created nothing, so there is nothing to fix.
    if detail.get("errorCode"):
        LOG.info("Ignoring failed call: %s", detail.get("errorCode"))
        return {"results": []}

    results = []
    for group_id in sorted(group_ids_from_event(detail)):
        try:
            results.append(remediate_group(group_id, detail))
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("InvalidGroup.NotFound", "InvalidSecurityGroupRuleId.NotFound"):
                # Group or rule already deleted: the state we wanted.
                LOG.info("%s already gone (%s)", group_id, code)
                results.append({"groupId": group_id, "action": "gone"})
            else:
                raise  # Let Lambda retry, then the DLQ catches it.
    return {"results": results}
