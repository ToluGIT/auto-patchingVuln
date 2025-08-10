#!/bin/bash
set -e

echo "🔍 Simulating Inspector2 Finding..."

# Get a test instance ID
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=VulnTestInstance" "Name=instance-state-name,Values=running" \
  --query "Reservations[0].Instances[0].InstanceId" \
  --output text)

if [ "$INSTANCE_ID" = "None" ] || [ -z "$INSTANCE_ID" ]; then
    echo "❌ No test instance found. Please create one first."
    exit 1
fi

echo "📝 Using test instance: $INSTANCE_ID"

# Create test Inspector2 event
TEST_EVENT=$(cat <<EOF
{
    "Entries": [{
        "Source": "aws.inspector2",
        "DetailType": "Inspector2 Finding",
        "Detail": "{\"resources\":[{\"id\":\"arn:aws:ec2:us-east-1:$(aws sts get-caller-identity --query Account --output text):instance/$INSTANCE_ID\"}],\"severity\":\"HIGH\",\"status\":\"ACTIVE\",\"type\":\"PACKAGE_VULNERABILITY\",\"findingArn\":\"arn:aws:inspector2:us-east-1:$(aws sts get-caller-identity --query Account --output text):finding/test-$(date +%s)\",\"title\":\"Test Critical Vulnerability - Apache HTTP Server\",\"packageVulnerabilityDetails\":{\"vulnerablePackages\":[{\"name\":\"httpd\"}],\"cveId\":\"CVE-2023-TEST\"},\"remediation\":{\"recommendation\":{\"text\":\"Update httpd package to latest version\"}}}"
    }]
}
EOF
)

# Send the event
echo "📤 Sending test event to EventBridge..."
aws events put-events --cli-input-json "$TEST_EVENT"

echo "✅ Test event sent successfully!"
echo "📊 Monitor the following:"
echo "   - CloudWatch Logs: /aws/lambda/patch-deduplication-function"
echo "   - DynamoDB Table: PatchExecutionState"
echo "   - Email notifications from SNS"

# Wait a moment and check DynamoDB
echo "⏳ Waiting 30 seconds for processing..."
sleep 30

echo "🔍 Checking DynamoDB for instance state..."
aws dynamodb get-item \
  --table-name PatchExecutionState \
  --key "{\"instance_id\":{\"S\":\"$INSTANCE_ID\"}}" \
  --query "Item" || echo "No item found in DynamoDB (expected if outside maintenance window)"

echo "📝 Check Lambda logs:"
echo "aws logs tail /aws/lambda/patch-deduplication-function --follow"