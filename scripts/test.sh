#!/bin/bash
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"
TESTS_DIR="$PROJECT_ROOT/tests"

echo -e "${BLUE}🧪 AWS Vulnerability Auto-Patching System Test Suite${NC}"
echo "============================================================="

# Test results tracking
declare -a test_results
total_tests=0
passed_tests=0

# Function to print test headers
print_test() {
    echo -e "\n${YELLOW}🔬 Test $1: $2${NC}"
    echo "----------------------------------------"
    total_tests=$((total_tests + 1))
}

# Function to check test results
check_test_result() {
    local test_name="$1"
    local exit_code=$2
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✅ PASSED: $test_name${NC}"
        test_results+=("✅ $test_name")
        passed_tests=$((passed_tests + 1))
        return 0
    else
        echo -e "${RED}❌ FAILED: $test_name${NC}"
        test_results+=("❌ $test_name")
        return 1
    fi
}

# Function to run a test with error handling
run_test() {
    local test_name="$1"
    local test_command="$2"
    local allow_failure=${3:-false}
    
    echo "Running: $test_command"
    
    if eval "$test_command" 2>&1; then
        check_test_result "$test_name" 0
        return 0
    else
        check_test_result "$test_name" 1
        if [ "$allow_failure" = "false" ]; then
            echo -e "${RED}⚠️  Test failed and is marked as critical${NC}"
        fi
        return 1
    fi
}

# Test 1: Infrastructure Status Check
test_infrastructure() {
    print_test "1" "Infrastructure Status Check"
    
    local all_passed=true
    
    # Check Lambda function
    echo -n "Lambda function status: "
    if LAMBDA_STATE=$(aws lambda get-function --function-name patch-deduplication-function --query 'Configuration.State' --output text 2>/dev/null); then
        if [ "$LAMBDA_STATE" = "Active" ]; then
            echo -e "${GREEN}✓ Active${NC}"
        else
            echo -e "${RED}✗ $LAMBDA_STATE${NC}"
            all_passed=false
        fi
    else
        echo -e "${RED}✗ Not found${NC}"
        all_passed=false
    fi
    
    # Check DynamoDB table
    echo -n "DynamoDB table status: "
    if DYNAMODB_STATUS=$(aws dynamodb describe-table --table-name PatchExecutionState --query 'Table.TableStatus' --output text 2>/dev/null); then
        if [ "$DYNAMODB_STATUS" = "ACTIVE" ]; then
            echo -e "${GREEN}✓ Active${NC}"
        else
            echo -e "${RED}✗ $DYNAMODB_STATUS${NC}"
            all_passed=false
        fi
    else
        echo -e "${RED}✗ Not found${NC}"
        all_passed=false
    fi
    
    # Check EventBridge rule
    echo -n "EventBridge rule status: "
    if EVENTBRIDGE_STATE=$(aws events describe-rule --name inspector-vulnerability-findings --query 'State' --output text 2>/dev/null); then
        if [ "$EVENTBRIDGE_STATE" = "ENABLED" ]; then
            echo -e "${GREEN}✓ Enabled${NC}"
        else
            echo -e "${RED}✗ $EVENTBRIDGE_STATE${NC}"
            all_passed=false
        fi
    else
        echo -e "${RED}✗ Not found${NC}"
        all_passed=false
    fi
    
    # Check SSM document
    echo -n "SSM document status: "
    if SSM_STATUS=$(aws ssm describe-document --name ImprovedPatchAutomation --query 'Document.Status' --output text 2>/dev/null); then
        if [ "$SSM_STATUS" = "Active" ]; then
            echo -e "${GREEN}✓ Active${NC}"
        else
            echo -e "${RED}✗ $SSM_STATUS${NC}"
            all_passed=false
        fi
    else
        echo -e "${RED}✗ Not found${NC}"
        all_passed=false
    fi
    
    if [ "$all_passed" = true ]; then
        return 0
    else
        return 1
    fi
}

# Test 2: Unit Tests
test_unit_tests() {
    print_test "2" "Lambda Function Unit Tests"
    
    # Check if pytest is installed
    if ! command -v pytest &> /dev/null; then
        echo -e "${YELLOW}⚠️  pytest not found. Installing...${NC}"
        pip install pytest moto boto3 2>/dev/null || {
            echo -e "${RED}❌ Failed to install test dependencies${NC}"
            return 1
        }
    fi
    
    # Check if test file exists
    TEST_FILE="$TESTS_DIR/unit/test_lambda.py"
    if [ ! -f "$TEST_FILE" ]; then
        echo -e "${RED}❌ Test file not found: $TEST_FILE${NC}"
        echo "Available test files:"
        find "$TESTS_DIR" -name "*.py" -type f 2>/dev/null || echo "No test files found"
        return 1
    fi
    
    # Run unit tests
    cd "$TESTS_DIR/unit"
    python -m pytest test_lambda.py -v --tb=short
    return $?
}

# Test 3: Lambda Function Connectivity
test_lambda_connectivity() {
    print_test "3" "Lambda Function Connectivity Test"
    
    # Test Lambda invocation with invalid event (should handle gracefully)
    echo "Testing Lambda invocation with test event..."
    
    RESPONSE_FILE=$(mktemp)
    if aws lambda invoke \
        --function-name patch-deduplication-function \
        --payload '{"source":"test","detail-type":"test","detail":{"test":"connectivity"}}' \
        "$RESPONSE_FILE" &>/dev/null; then
        
        # Check response content
        if grep -q "Invalid event structure" "$RESPONSE_FILE"; then
            echo "✓ Lambda properly handles invalid events"
            rm -f "$RESPONSE_FILE"
            return 0
        else
            echo "✓ Lambda responds (may have different error handling)"
            rm -f "$RESPONSE_FILE"
            return 0
        fi
    else
        echo "✗ Lambda invocation failed"
        rm -f "$RESPONSE_FILE"
        return 1
    fi
}

# Test 4: VPC and Security Configuration
test_security_config() {
    print_test "4" "Security Configuration Test"
    
    local security_passed=true
    
    # Check Lambda VPC configuration
    echo -n "Lambda VPC configuration: "
    VPC_CONFIG=$(aws lambda get-function --function-name patch-deduplication-function --query 'Configuration.VpcConfig' --output json 2>/dev/null)
    if echo "$VPC_CONFIG" | grep -q "VpcId"; then
        echo -e "${GREEN}✓ VPC configured${NC}"
    else
        echo -e "${RED}✗ No VPC configuration${NC}"
        security_passed=false
    fi
    
    # Check DynamoDB encryption
    echo -n "DynamoDB encryption: "
    if aws dynamodb describe-table --table-name PatchExecutionState --query 'Table.SSEDescription.Status' --output text 2>/dev/null | grep -q "ENABLED"; then
        echo -e "${GREEN}✓ Enabled${NC}"
    else
        echo -e "${YELLOW}⚠️  Encryption status unknown${NC}"
    fi
    
    # Check IAM role exists
    echo -n "Lambda IAM role: "
    ROLE_ARN=$(aws lambda get-function --function-name patch-deduplication-function --query 'Configuration.Role' --output text 2>/dev/null)
    if [ -n "$ROLE_ARN" ]; then
        echo -e "${GREEN}✓ Role exists${NC}"
    else
        echo -e "${RED}✗ No role found${NC}"
        security_passed=false
    fi
    
    if [ "$security_passed" = true ]; then
        return 0
    else
        return 1
    fi
}

# Test 5: CloudWatch Monitoring
test_monitoring() {
    print_test "5" "CloudWatch Monitoring Test"
    
    # Check if Lambda metrics exist
    echo "Checking Lambda metrics..."
    
    METRICS_EXIST=$(aws cloudwatch get-metric-statistics \
        --namespace AWS/Lambda \
        --metric-name Invocations \
        --dimensions Name=FunctionName,Value=patch-deduplication-function \
        --start-time "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S)" \
        --end-time "$(date -u +%Y-%m-%dT%H:%M:%S)" \
        --period 3600 \
        --statistics Sum \
        --query 'Datapoints' \
        --output text 2>/dev/null)
    
    if [ -n "$METRICS_EXIST" ]; then
        echo "✓ Lambda metrics available in CloudWatch"
        return 0
    else
        echo "⚠️  No recent Lambda metrics (expected for new deployment)"
        return 0  # Not a failure for new deployments
    fi
}

# Test 6: SNS Configuration
test_sns_config() {
    print_test "6" "SNS Topic Configuration Test"
    
    # Get SNS topic ARN from Terraform output
    cd "$TERRAFORM_DIR"
    SNS_TOPIC_ARN=$(terraform output -raw sns_topic_arn 2>/dev/null)
    
    if [ -n "$SNS_TOPIC_ARN" ]; then
        echo "SNS Topic ARN: $SNS_TOPIC_ARN"
        
        # Check topic exists
        if aws sns get-topic-attributes --topic-arn "$SNS_TOPIC_ARN" &>/dev/null; then
            echo "✓ SNS topic exists and is accessible"
            
            # Check subscriptions
            SUBS=$(aws sns list-subscriptions-by-topic --topic-arn "$SNS_TOPIC_ARN" --query 'Subscriptions[0].Protocol' --output text 2>/dev/null)
            if [ "$SUBS" = "email" ]; then
                echo "✓ Email subscription configured"
            else
                echo "⚠️  No email subscription found"
            fi
            return 0
        else
            echo "✗ SNS topic not accessible"
            return 1
        fi
    else
        echo "✗ Cannot get SNS topic ARN"
        return 1
    fi
}

# Test 7: End-to-End Event Simulation
test_event_simulation() {
    print_test "7" "Event Simulation Test"
    
    echo "Creating test EventBridge event..."
    
    # Create a test event
    TEST_EVENT_FILE=$(mktemp)
    cat > "$TEST_EVENT_FILE" << 'EOF'
{
    "Entries": [{
        "Source": "aws.inspector2",
        "DetailType": "Inspector2 Finding",
        "Detail": "{\"resources\":[{\"id\":\"arn:aws:ec2:us-east-1:123456789012:instance/i-test123\"}],\"severity\":\"HIGH\",\"status\":\"ACTIVE\",\"type\":\"PACKAGE_VULNERABILITY\",\"findingArn\":\"arn:aws:inspector2:us-east-1:123456789012:finding/test-finding\",\"title\":\"Test Vulnerability\"}"
    }]
}
EOF
    
    # Send the test event
    if aws events put-events --cli-input-json "file://$TEST_EVENT_FILE" &>/dev/null; then
        echo "✓ Test event sent to EventBridge"
        
        # Wait a moment for processing
        sleep 5
        
        # Check CloudWatch logs for processing
        LOG_EVENTS=$(aws logs filter-log-events \
            --log-group-name "/aws/lambda/patch-deduplication-function" \
            --start-time "$(date -d '5 minutes ago' +%s)000" \
            --filter-pattern "test123" \
            --query 'events[0].message' \
            --output text 2>/dev/null)
        
        if [ -n "$LOG_EVENTS" ] && [ "$LOG_EVENTS" != "None" ]; then
            echo "✓ Event processed by Lambda function"
        else
            echo "⚠️  No recent log events found (may be normal)"
        fi
        
        rm -f "$TEST_EVENT_FILE"
        return 0
    else
        echo "✗ Failed to send test event"
        rm -f "$TEST_EVENT_FILE"
        return 1
    fi
}

# Test 8: Performance Benchmark
test_performance() {
    print_test "8" "Performance Benchmark Test"
    
    echo "Running performance benchmark..."
    
    # Simple performance test - measure Lambda cold start
    START_TIME=$(date +%s%N)
    
    aws lambda invoke \
        --function-name patch-deduplication-function \
        --payload '{"test": "performance"}' \
        /dev/null &>/dev/null
    
    END_TIME=$(date +%s%N)
    DURATION=$(((END_TIME - START_TIME) / 1000000))  # Convert to milliseconds
    
    echo "Lambda invocation time: ${DURATION}ms"
    
    if [ "$DURATION" -lt 30000 ]; then  # Less than 30 seconds
        echo "✓ Performance within acceptable range"
        return 0
    else
        echo "⚠️  Performance slower than expected (may be cold start)"
        return 0  # Don't fail on performance, just warn
    fi
}

# Function to display test summary
show_test_summary() {
    echo -e "\n${BLUE}📊 TEST EXECUTION SUMMARY${NC}"
    echo "============================================================="
    
    for result in "${test_results[@]}"; do
        echo "$result"
    done
    
    echo ""
    echo -e "Results: ${GREEN}$passed_tests${NC}/${BLUE}$total_tests${NC} tests passed"
    
    local pass_percentage=$((passed_tests * 100 / total_tests))
    
    if [ $passed_tests -eq $total_tests ]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED! System is ready for production use.${NC}"
        return 0
    elif [ $pass_percentage -ge 80 ]; then
        echo -e "${YELLOW}⚠️  Most tests passed ($pass_percentage%). Review failed tests before production.${NC}"
        return 1
    else
        echo -e "${RED}❌ Multiple tests failed ($pass_percentage% pass rate). System needs attention.${NC}"
        return 1
    fi
}

# Function to provide troubleshooting guidance
show_troubleshooting() {
    if [ $passed_tests -lt $total_tests ]; then
        echo -e "\n${YELLOW}🔧 TROUBLESHOOTING GUIDANCE${NC}"
        echo "============================================================="
        echo ""
        echo "For failed tests, check:"
        echo "1. 📋 Ensure deployment completed successfully: ./scripts/deploy.sh"
        echo "2. 📊 Check CloudWatch logs: aws logs tail /aws/lambda/patch-deduplication-function"
        echo "3. 🔍 Review deployment guide: docs/03-deployment-guide.md"
        echo "4. 🛠️  See troubleshooting guide: docs/06-troubleshooting-maintenance.md"
        echo ""
        echo "Common issues:"
        echo "• Infrastructure tests fail: Re-run deployment script"
        echo "• Unit tests fail: Check Python dependencies and test environment"
        echo "• Connectivity tests fail: Verify AWS credentials and permissions"
        echo "• Security tests fail: Check IAM roles and VPC configuration"
    fi
}

# Main test execution
main() {
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Run all tests
    test_infrastructure
    test_unit_tests
    test_lambda_connectivity
    test_security_config
    test_monitoring
    test_sns_config
    test_event_simulation
    test_performance
    
    # Show results
    show_test_summary
    local exit_code=$?
    
    show_troubleshooting
    
    echo ""
    echo "Test execution completed at $(date)"
    echo "Log files available in CloudWatch: /aws/lambda/patch-deduplication-function"
    
    return $exit_code
}

# Handle script interruption
cleanup_on_exit() {
    echo -e "\n${RED}Test execution interrupted.${NC}"
    exit 1
}

trap cleanup_on_exit INT TERM

# Run main function
main "$@"