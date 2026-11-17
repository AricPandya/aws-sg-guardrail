#!/usr/bin/env bash
# End-to-end test: open SSH to the world on a throwaway security group,
# then time how long the guardrail takes to close it.
#   ./scripts/test-open-ssh.sh            (uses the default VPC)
#   VPC_ID=vpc-0abc ./scripts/test-open-ssh.sh
set -euo pipefail

REGION="${AWS_REGION:-$(aws configure get region)}"
VPC_ID="${VPC_ID:-$(aws ec2 describe-vpcs --region "$REGION" \
  --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)}"
TIMEOUT="${TIMEOUT:-300}"

SG_ID=$(aws ec2 create-security-group --region "$REGION" --vpc-id "$VPC_ID" \
  --group-name "sg-guardrail-test-$(date +%s)" \
  --description "Temporary group for SG Guardrail test" \
  --query GroupId --output text)
trap 'aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID" && echo "Deleted $SG_ID"' EXIT
echo "Created $SG_ID in $VPC_ID ($REGION)"

aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
# A safe rule that must survive, to prove we only remove what is risky.
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
START=$(date +%s)
echo "Opened 22/tcp and 443/tcp to 0.0.0.0/0 - waiting for the guardrail..."

while true; do
  OPEN=$(aws ec2 describe-security-group-rules --region "$REGION" \
    --filters Name=group-id,Values="$SG_ID" \
    --query "SecurityGroupRules[?!IsEgress && FromPort==\`22\`] | length(@)" --output text)
  ELAPSED=$(( $(date +%s) - START ))
  if [[ "$OPEN" == "0" ]]; then
    echo "PASS: port 22 rule revoked after ${ELAPSED}s"
    break
  fi
  if (( ELAPSED > TIMEOUT )); then
    echo "FAIL: port 22 still open after ${TIMEOUT}s - check the Lambda logs and DLQ"
    exit 1
  fi
  sleep 2
done

aws ec2 describe-security-group-rules --region "$REGION" \
  --filters Name=group-id,Values="$SG_ID" \
  --query "SecurityGroupRules[?!IsEgress].[FromPort,CidrIpv4]" --output text \
  | sed 's/^/Remaining ingress rule: /'
