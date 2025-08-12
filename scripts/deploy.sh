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

echo -e "${BLUE}AWS Vulnerability Auto-Patching System Deployment${NC}"
echo "============================================================="

# Function to print step headers
print_step() {
    echo -e "\n${YELLOW}Step $1: $2${NC}"
    echo "----------------------------------------"
}

# Function to check command exit status
check_status() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}PASS: $1${NC}"
    else
        echo -e "${RED}FAIL: $1 failed${NC}"
        exit 1
    fi
}

# Function to validate prerequisites
validate_prerequisites() {
    print_step "1" "Validating Prerequisites"
    
    # Check if AWS CLI is installed
    if command -v aws &> /dev/null; then
        echo "OK: AWS CLI is installed"
    else
        echo -e "${RED}ERROR: AWS CLI is not installed. Please install it first.${NC}"
        exit 1
    fi
    
    # Check if Terraform is installed
    if command -v terraform &> /dev/null; then
        echo "OK: Terraform is installed"
        terraform version
    else
        echo -e "${RED}ERROR: Terraform is not installed. Please install it first.${NC}"
        exit 1
    fi
    
    # Check AWS credentials
    if aws sts get-caller-identity &> /dev/null; then
        echo "OK: AWS credentials are configured"
        aws sts get-caller-identity --query '[Account, Arn]' --output table
    else
        echo -e "${RED}ERROR: AWS credentials not configured or invalid.${NC}"
        exit 1
    fi
    
    # Check if terraform.tfvars exists
    if [ -f "$TERRAFORM_DIR/terraform.tfvars" ]; then
        echo "OK: terraform.tfvars file exists"
    else
        echo -e "${RED}ERROR: terraform.tfvars file not found.${NC}"
        echo "Please create $TERRAFORM_DIR/terraform.tfvars with required variables."
        echo "See $TERRAFORM_DIR/terraform.tfvars.example for template."
        exit 1
    fi
    
    # Check if required files exist
    required_files=(
        "$PROJECT_ROOT/lambda/patch_deduplication.py"
        "$PROJECT_ROOT/lambda/requirements.txt"
        "$PROJECT_ROOT/documents/improved-patch-automation.yaml"
        "$TERRAFORM_DIR/enhanced-main.tf"
    )
    
    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            echo "OK: $(basename "$file") exists"
        else
            echo -e "${RED}ERROR: Required file missing: $file${NC}"
            exit 1
        fi
    done
}

# Function to initialize Terraform
initialize_terraform() {
    print_step "2" "Initializing Terraform"
    
    cd "$TERRAFORM_DIR"
    
    echo "Initializing Terraform backend..."
    terraform init
    check_status "Terraform initialization"
}

# Function to plan deployment
plan_deployment() {
    print_step "3" "Planning Deployment"
    
    echo "Creating Terraform execution plan..."
    terraform plan -var-file="terraform.tfvars" -out=tfplan
    check_status "Terraform planning"
    
    echo -e "\n${YELLOW}Please review the plan above.${NC}"
    read -p "Do you want to proceed with the deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Deployment cancelled by user.${NC}"
        exit 1
    fi
}

# Function to apply Terraform configuration
apply_terraform() {
    print_step "4" "Applying Terraform Configuration"
    
    echo "Deploying AWS infrastructure..."
    terraform apply tfplan
    check_status "Terraform apply"
    
    # Clean up plan file
    rm -f tfplan
}

# Function to verify deployment
verify_deployment() {
    print_step "5" "Verifying Deployment"
    
    echo "Checking deployed resources..."
    
    # Check Lambda function
    echo -n "Lambda function: "
    LAMBDA_STATE=$(aws lambda get-function --function-name patch-deduplication-function --query 'Configuration.State' --output text 2>/dev/null || echo "NOT_FOUND")
    if [ "$LAMBDA_STATE" = "Active" ]; then
        echo -e "${GREEN}OK: Active${NC}"
    else
        echo -e "${RED}ERROR: $LAMBDA_STATE${NC}"
    fi
    
    # Check DynamoDB table
    echo -n "DynamoDB table: "
    DYNAMODB_STATUS=$(aws dynamodb describe-table --table-name PatchExecutionState --query 'Table.TableStatus' --output text 2>/dev/null || echo "NOT_FOUND")
    if [ "$DYNAMODB_STATUS" = "ACTIVE" ]; then
        echo -e "${GREEN}OK: Active${NC}"
    else
        echo -e "${RED}ERROR: $DYNAMODB_STATUS${NC}"
    fi
    
    # Check EventBridge rule
    echo -n "EventBridge rule: "
    EVENTBRIDGE_STATE=$(aws events describe-rule --name inspector-vulnerability-findings --query 'State' --output text 2>/dev/null || echo "NOT_FOUND")
    if [ "$EVENTBRIDGE_STATE" = "ENABLED" ]; then
        echo -e "${GREEN}OK: Enabled${NC}"
    else
        echo -e "${RED}ERROR: $EVENTBRIDGE_STATE${NC}"
    fi
    
    # Check SSM document
    echo -n "SSM document: "
    SSM_STATUS=$(aws ssm describe-document --name ImprovedPatchAutomation --query 'Document.Status' --output text 2>/dev/null || echo "NOT_FOUND")
    if [ "$SSM_STATUS" = "Active" ]; then
        echo -e "${GREEN}OK: Active${NC}"
    else
        echo -e "${RED}ERROR: $SSM_STATUS${NC}"
    fi
    
    # Display important outputs
    echo -e "\n${BLUE}Deployment Outputs:${NC}"
    echo "----------------------------------------"
    terraform output
}

# Function to setup post-deployment configuration
post_deployment_setup() {
    print_step "6" "Post-Deployment Setup"
    
    echo "Checking Inspector2 status..."
    INSPECTOR_STATUS=$(aws inspector2 get-configuration --query 'status' --output text 2>/dev/null || echo "DISABLED")
    
    if [ "$INSPECTOR_STATUS" != "ENABLED" ]; then
        echo -e "${YELLOW}WARNING: Inspector2 is not enabled. Enabling now...${NC}"
        aws inspector2 enable --resource-types EC2 ECR
        echo "OK: Inspector2 enabled for EC2 and ECR resources"
    else
        echo "OK: Inspector2 is already enabled"
    fi
    
    # Get SNS topic ARN
    SNS_TOPIC_ARN=$(terraform output -raw sns_topic_arn 2>/dev/null)
    
    if [ -n "$SNS_TOPIC_ARN" ]; then
        echo -e "\n${YELLOW}Email Subscription Setup:${NC}"
        echo "An email subscription has been created for SNS topic:"
        echo "$SNS_TOPIC_ARN"
        echo -e "${YELLOW}Please check your email and confirm the subscription.${NC}"
        
        # Check subscription status
        echo -n "Checking subscription status: "
        CONFIRMED=$(aws sns list-subscriptions-by-topic --topic-arn "$SNS_TOPIC_ARN" --query 'Subscriptions[0].SubscriptionArn' --output text 2>/dev/null)
        if [[ "$CONFIRMED" == *"arn:aws:sns"* ]]; then
            echo -e "${GREEN}OK: Confirmed${NC}"
        else
            echo -e "${YELLOW}PENDING: Awaiting confirmation${NC}"
        fi
    fi
    
    # Display CloudWatch dashboard URL
    DASHBOARD_URL=$(terraform output -raw dashboard_url 2>/dev/null)
    if [ -n "$DASHBOARD_URL" ]; then
        echo -e "\n${BLUE}CloudWatch Dashboard:${NC}"
        echo "$DASHBOARD_URL"
    fi
}

# Function to provide next steps
show_next_steps() {
    echo -e "\n${GREEN}Deployment Complete${NC}"
    echo "============================================================="
    echo ""
    echo "Next steps:"
    echo "1. Confirm your email subscription for SNS notifications"
    echo "2. Create a test EC2 instance with AutoPatch=true tag"
    echo "3. Run the test suite: ./scripts/test.sh"
    echo "4. Monitor the CloudWatch dashboard"
    echo ""
    echo "Useful commands:"
    echo "• View Lambda logs: aws logs tail /aws/lambda/patch-deduplication-function --follow"
    echo "• Check deployment: terraform output"
    echo "• Run tests: ./scripts/test.sh"
    echo "• Clean up: ./scripts/cleanup.sh"
    echo ""
    echo "For troubleshooting, see: docs/06-troubleshooting-maintenance.md"
}

# Main execution
main() {
    validate_prerequisites
    initialize_terraform
    plan_deployment
    apply_terraform
    verify_deployment
    post_deployment_setup
    show_next_steps
}

# Handle script interruption
cleanup_on_exit() {
    echo -e "\n${RED}Script interrupted. Cleaning up...${NC}"
    cd "$TERRAFORM_DIR"
    rm -f tfplan
    exit 1
}

trap cleanup_on_exit INT TERM

# Run main function
main "$@"