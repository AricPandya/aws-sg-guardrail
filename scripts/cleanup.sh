#!/usr/bin/env bash
# Removes everything the stack created.
#   STACK=sg-guardrail ./scripts/cleanup.sh
set -euo pipefail
STACK="${STACK:-sg-guardrail}"
REGION="${AWS_REGION:-$(aws configure get region)}"

# CloudFormation cannot delete a non-empty bucket, so empty the trail bucket first.
BUCKET=$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='TrailBucketName'].OutputValue" --output text 2>/dev/null || true)
if [[ -n "$BUCKET" && "$BUCKET" != "None" ]]; then
  echo "Emptying $BUCKET"
  aws s3 rm "s3://$BUCKET" --recursive --region "$REGION"
fi

sam delete --stack-name "$STACK" --region "$REGION" --no-prompts
echo "Done. The KMS key is scheduled for deletion (default 30-day wait), which is expected."
