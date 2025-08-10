#!/bin/bash
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧪 Scheduled Maintenance Testing Script${NC}"
echo "============================================================="

# Function to print step headers
print_step() {
    echo -e "\n${YELLOW}📋 Step $1: $2${NC}"
    echo "----------------------------------------"
}

# Function to check command exit status
check_status() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ $1${NC}"
    else
        echo -e "${RED}❌ $1 failed${NC}"
        return 1
    fi
}

# Function to create test scheduled patch entry
create_test_scheduled_patch() {
    print_step "1" "Creating Test Scheduled Patch Entry"
    
    # Use a test instance ID (you'll need to replace with actual instance)
    INSTANCE_ID=${1:-"i-test123456789abcdef"}
    echo "Using test instance ID: $INSTANCE_ID"
    
    # Calculate scheduled time (5 minutes from now for testing)
    SCHEDULED_TIME=$(date -u -d '+5 minutes' '+%Y-%m-%dT%H:%M:%S.000Z')
    echo "Scheduling patch for: $SCHEDULED_TIME"
    
    # Create DynamoDB entry
    aws dynamodb put-item \
        --table-name PatchExecutionState \
        --item '{
            "instance_id": {"S": "'$INSTANCE_ID'"},
            "status": {"S": "SCHEDULED"},
            "scheduled_for": {"S": "'$SCHEDULED_TIME'"},
            "vulnerabilities": {
                "L": [{
                    "M": {
                        "finding_id": {"S": "test-scheduled-finding-001"},
                        "severity": {"S": "HIGH"},
                        "title": {"S": "Test Scheduled Vulnerability"},
                        "package": {"S": "test-package"},
                        "cve": {"S": "CVE-2024-TEST"},
                        "timestamp": {"S": "'$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')'"}
                    }
                }]
            },
            "expiration_time": {"N": "'$(($(date +%s) + 86400))'"}
        }' \
        --region us-east-1
    
    check_status "Test scheduled patch entry created"
}

# Function to manually invoke maintenance scheduler
test_maintenance_scheduler() {
    print_step "2" "Testing Maintenance Scheduler Function"
    
    echo "Invoking maintenance scheduler Lambda function..."
    
    # Create test event
    TEST_EVENT='{
        "source": "aws.events",
        "detail-type": "Scheduled Event",
        "detail": {}
    }'
    
    # Invoke the function
    RESULT=$(aws lambda invoke \
        --function-name patch-maintenance-scheduler \
        --payload "$TEST_EVENT" \
        --region us-east-1 \
        /tmp/scheduler-test-response.json)
    
    echo "Lambda invocation result:"
    echo "$RESULT"
    
    echo -e "\nFunction response:"
    cat /tmp/scheduler-test-response.json | jq .
    
    check_status "Maintenance scheduler function invoked"
}

# Function to check DynamoDB for status changes
check_database_status() {
    print_step "3" "Checking Database Status Changes"
    
    INSTANCE_ID=${1:-"i-test123456789abcdef"}
    
    echo "Checking DynamoDB for instance: $INSTANCE_ID"
    
    ITEM=$(aws dynamodb get-item \
        --table-name PatchExecutionState \
        --key '{"instance_id": {"S": "'$INSTANCE_ID'"}}' \
        --region us-east-1 \
        --output json)
    
    if [ "$ITEM" = "null" ] || [ -z "$ITEM" ] || [ "$ITEM" = "{}" ]; then
        echo -e "${YELLOW}⚠️  No item found for instance $INSTANCE_ID${NC}"
        return 1
    fi
    
    echo "Current database entry:"
    echo "$ITEM" | jq '.Item'
    
    # Extract status
    STATUS=$(echo "$ITEM" | jq -r '.Item.status.S // "NOT_FOUND"')
    echo -e "\nCurrent status: ${BLUE}$STATUS${NC}"
    
    case "$STATUS" in
        "SCHEDULED")
            echo -e "${YELLOW}Status is still SCHEDULED - scheduler may not have processed yet${NC}"
            ;;
        "PROCESSING_SCHEDULED")
            echo -e "${BLUE}Status is PROCESSING_SCHEDULED - scheduler is working${NC}"
            ;;
        "IN_PROGRESS")
            echo -e "${GREEN}Status is IN_PROGRESS - patch automation has started${NC}"
            ;;
        "COMPLETED")
            echo -e "${GREEN}Status is COMPLETED - patch was successful${NC}"
            ;;
        "FAILED")
            echo -e "${RED}Status is FAILED - patch failed${NC}"
            ;;
        *)
            echo -e "${YELLOW}Unknown status: $STATUS${NC}"
            ;;
    esac
    
    check_status "Database status checked"
}

# Function to check CloudWatch logs
check_logs() {
    print_step "4" "Checking CloudWatch Logs"
    
    echo "Checking maintenance scheduler logs..."
    
    # Get recent logs from maintenance scheduler
    SCHEDULER_LOGS=$(aws logs filter-log-events \
        --log-group-name "/aws/lambda/patch-maintenance-scheduler" \
        --start-time "$(($(date +%s) - 3600))000" \
        --region us-east-1 \
        --output json 2>/dev/null || echo '{"events": []}')
    
    EVENTS_COUNT=$(echo "$SCHEDULER_LOGS" | jq '.events | length')
    echo "Found $EVENTS_COUNT recent log events"
    
    if [ "$EVENTS_COUNT" -gt 0 ]; then
        echo -e "\nRecent scheduler log messages:"
        echo "$SCHEDULER_LOGS" | jq -r '.events[] | "\(.timestamp | strftime("%Y-%m-%d %H:%M:%S")): \(.message)"' | tail -10
    fi
    
    # Check deduplication function logs too
    echo -e "\nChecking deduplication function logs..."
    
    DEDUP_LOGS=$(aws logs filter-log-events \
        --log-group-name "/aws/lambda/patch-deduplication-function" \
        --start-time "$(($(date +%s) - 3600))000" \
        --region us-east-1 \
        --output json 2>/dev/null || echo '{"events": []}')
    
    DEDUP_EVENTS_COUNT=$(echo "$DEDUP_LOGS" | jq '.events | length')
    echo "Found $DEDUP_EVENTS_COUNT recent deduplication log events"
    
    if [ "$DEDUP_EVENTS_COUNT" -gt 0 ]; then
        echo -e "\nRecent deduplication log messages:"
        echo "$DEDUP_LOGS" | jq -r '.events[] | "\(.timestamp | strftime("%Y-%m-%d %H:%M:%S")): \(.message)"' | tail -5
    fi
    
    check_status "CloudWatch logs checked"
}

# Function to test EventBridge rule
test_eventbridge_rule() {
    print_step "5" "Testing EventBridge Scheduler Rule"
    
    echo "Checking EventBridge rule status..."
    
    RULE_INFO=$(aws events describe-rule \
        --name patch-maintenance-scheduler \
        --region us-east-1 \
        --output json)
    
    echo "Rule information:"
    echo "$RULE_INFO" | jq .
    
    STATE=$(echo "$RULE_INFO" | jq -r '.State')
    echo -e "\nRule state: ${BLUE}$STATE${NC}"
    
    if [ "$STATE" = "ENABLED" ]; then
        echo -e "${GREEN}✅ EventBridge rule is enabled${NC}"
    else
        echo -e "${RED}❌ EventBridge rule is not enabled${NC}"
        return 1
    fi
    
    # Check targets
    echo -e "\nChecking rule targets..."
    TARGETS=$(aws events list-targets-by-rule \
        --rule patch-maintenance-scheduler \
        --region us-east-1 \
        --output json)
    
    echo "Targets:"
    echo "$TARGETS" | jq .
    
    TARGET_COUNT=$(echo "$TARGETS" | jq '.Targets | length')
    
    if [ "$TARGET_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✅ Rule has $TARGET_COUNT target(s)${NC}"
    else
        echo -e "${RED}❌ Rule has no targets${NC}"
        return 1
    fi
    
    check_status "EventBridge rule tested"
}

# Function to cleanup test data
cleanup_test_data() {
    print_step "6" "Cleaning Up Test Data"
    
    INSTANCE_ID=${1:-"i-test123456789abcdef"}
    
    echo "Removing test database entry for instance: $INSTANCE_ID"
    
    aws dynamodb delete-item \
        --table-name PatchExecutionState \
        --key '{"instance_id": {"S": "'$INSTANCE_ID'"}}' \
        --region us-east-1 2>/dev/null || true
    
    echo "Cleaning up temp files..."
    rm -f /tmp/scheduler-test-response.json
    
    check_status "Test data cleaned up"
}

# Function to show comprehensive test summary
show_test_summary() {
    echo -e "\n${GREEN}🎉 SCHEDULED MAINTENANCE TEST COMPLETED!${NC}"
    echo "============================================================="
    echo ""
    echo "Test Summary:"
    echo "• ✅ Test scheduled patch entry created"
    echo "• ✅ Maintenance scheduler function invoked"
    echo "• ✅ Database status changes monitored"
    echo "• ✅ CloudWatch logs examined"
    echo "• ✅ EventBridge rule validated"
    echo "• ✅ Test data cleaned up"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Monitor the system during actual maintenance window (2-7 AM UTC)"
    echo "2. Check CloudWatch dashboard for scheduled patch processing"
    echo "3. Verify that scheduled patches are processed automatically"
    echo ""
    echo "To test with a real instance:"
    echo "  ./scripts/test-scheduled-maintenance.sh i-your-real-instance-id"
}

# Main execution function
main() {
    local instance_id="${1:-i-test123456789abcdef}"
    
    echo "Testing scheduled maintenance system..."
    echo "Instance ID: $instance_id"
    echo ""
    
    # Check prerequisites
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}❌ AWS CLI is not installed${NC}"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}❌ jq is not installed${NC}"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}❌ AWS credentials not configured${NC}"
        exit 1
    fi
    
    # Run tests
    create_test_scheduled_patch "$instance_id"
    test_maintenance_scheduler
    sleep 5  # Wait a bit for processing
    check_database_status "$instance_id"
    check_logs
    test_eventbridge_rule
    cleanup_test_data "$instance_id"
    show_test_summary
}

# Handle script interruption
cleanup_on_exit() {
    echo -e "\n${RED}Test interrupted. Cleaning up...${NC}"
    cleanup_test_data "${1:-i-test123456789abcdef}" 2>/dev/null || true
    exit 1
}

trap 'cleanup_on_exit' INT TERM

# Check if running with appropriate warnings
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly
    main "$@"
else
    # Script is being sourced
    echo -e "${YELLOW}⚠️  This script should be executed directly, not sourced.${NC}"
    echo "Run: ./scripts/test-scheduled-maintenance.sh [instance-id]"
fi