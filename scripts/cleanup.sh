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

echo -e "${BLUE}🧹 AWS Vulnerability Auto-Patching System Cleanup${NC}"
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

# Function to confirm cleanup action
confirm_cleanup() {
    echo -e "${RED}⚠️  WARNING: This will destroy ALL AWS resources created by this project!${NC}"
    echo ""
    echo "Resources to be destroyed include:"
    echo "• Lambda functions and associated logs"
    echo "• DynamoDB table and all stored data"
    echo "• VPC, subnets, and networking resources"
    echo "• IAM roles and policies"
    echo "• SNS topics and subscriptions"
    echo "• EventBridge rules"
    echo "• CloudWatch alarms and dashboards"
    echo "• KMS keys"
    echo ""
    echo -e "${YELLOW}This action cannot be undone!${NC}"
    echo ""
    
    read -p "Are you sure you want to proceed with cleanup? (type 'YES' to confirm): " -r
    if [[ $REPLY != "YES" ]]; then
        echo -e "${GREEN}Cleanup cancelled. No resources were destroyed.${NC}"
        exit 0
    fi
    
    echo ""
    read -p "Final confirmation - destroy all resources? (type 'DESTROY' to confirm): " -r
    if [[ $REPLY != "DESTROY" ]]; then
        echo -e "${GREEN}Cleanup cancelled. No resources were destroyed.${NC}"
        exit 0
    fi
}

# Function to check prerequisites
check_prerequisites() {
    print_step "1" "Checking Prerequisites"
    
    # Check if Terraform is installed
    if command -v terraform &> /dev/null; then
        echo "✓ Terraform is installed"
    else
        echo -e "${RED}❌ Terraform is not installed.${NC}"
        exit 1
    fi
    
    # Check AWS credentials
    if aws sts get-caller-identity &> /dev/null; then
        echo "✓ AWS credentials are configured"
    else
        echo -e "${RED}❌ AWS credentials not configured.${NC}"
        exit 1
    fi
    
    # Check if in terraform directory or if terraform directory exists
    if [ -d "$TERRAFORM_DIR" ]; then
        echo "✓ Terraform directory found"
    else
        echo -e "${RED}❌ Terraform directory not found at $TERRAFORM_DIR${NC}"
        exit 1
    fi
    
    # Check if terraform.tfvars exists
    if [ -f "$TERRAFORM_DIR/terraform.tfvars" ]; then
        echo "✓ terraform.tfvars file exists"
    else
        echo -e "${RED}❌ terraform.tfvars file not found.${NC}"
        echo "Cannot proceed without Terraform variables."
        exit 1
    fi
    
    # Check if Terraform state exists
    if [ -f "$TERRAFORM_DIR/terraform.tfstate" ] || [ -f "$TERRAFORM_DIR/.terraform/terraform.tfstate" ]; then
        echo "✓ Terraform state found"
    else
        echo -e "${YELLOW}⚠️  No Terraform state file found. Resources may not exist or may need manual cleanup.${NC}"
        read -p "Do you want to continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Cleanup cancelled."
            exit 0
        fi
    fi
}

# Function to backup important data before cleanup
backup_data() {
    print_step "2" "Backing Up Critical Data"
    
    BACKUP_DIR="$PROJECT_ROOT/cleanup-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    echo "Creating backup directory: $BACKUP_DIR"
    
    # Backup DynamoDB data if table exists
    echo -n "Backing up DynamoDB data: "
    if aws dynamodb describe-table --table-name PatchExecutionState &>/dev/null; then
        aws dynamodb scan \
            --table-name PatchExecutionState \
            --output json > "$BACKUP_DIR/dynamodb-data.json" 2>/dev/null || true
        echo -e "${GREEN}✓ Completed${NC}"
    else
        echo -e "${YELLOW}⚠️  Table not found${NC}"
    fi
    
    # Backup Lambda function code
    echo -n "Backing up Lambda function: "
    if aws lambda get-function --function-name patch-deduplication-function &>/dev/null; then
        aws lambda get-function \
            --function-name patch-deduplication-function > "$BACKUP_DIR/lambda-function.json" 2>/dev/null || true
        echo -e "${GREEN}✓ Completed${NC}"
    else
        echo -e "${YELLOW}⚠️  Function not found${NC}"
    fi
    
    # Backup CloudWatch logs (recent entries)
    echo -n "Backing up recent CloudWatch logs: "
    aws logs filter-log-events \
        --log-group-name "/aws/lambda/patch-deduplication-function" \
        --start-time "$(date -d '7 days ago' +%s)000" \
        --output json > "$BACKUP_DIR/cloudwatch-logs.json" 2>/dev/null || true
    echo -e "${GREEN}✓ Completed${NC}"
    
    # Copy Terraform state
    echo -n "Backing up Terraform state: "
    if [ -f "$TERRAFORM_DIR/terraform.tfstate" ]; then
        cp "$TERRAFORM_DIR/terraform.tfstate" "$BACKUP_DIR/"
        echo -e "${GREEN}✓ Completed${NC}"
    else
        echo -e "${YELLOW}⚠️  No state file${NC}"
    fi
    
    # Copy Terraform configuration
    cp -r "$TERRAFORM_DIR"/*.tf "$TERRAFORM_DIR"/*.tfvars "$BACKUP_DIR/" 2>/dev/null || true
    
    echo "Backup completed in: $BACKUP_DIR"
}

# Function to list resources before destruction
list_resources() {
    print_step "3" "Listing Resources to be Destroyed"
    
    cd "$TERRAFORM_DIR"
    
    echo "Generating destruction plan..."
    terraform plan -destroy -var-file="terraform.tfvars" -out=destroy.tfplan
    
    echo -e "\n${YELLOW}Resources that will be destroyed:${NC}"
    terraform show destroy.tfplan | grep -E "# .* will be destroyed" | head -20
    
    local resource_count=$(terraform show destroy.tfplan | grep -c "# .* will be destroyed" || echo "0")
    echo ""
    echo "Total resources to destroy: $resource_count"
    
    if [ "$resource_count" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  No resources found to destroy. Infrastructure may already be cleaned up.${NC}"
        rm -f destroy.tfplan
        exit 0
    fi
}

# Function to delete additional resources not managed by Terraform
cleanup_additional_resources() {
    print_step "4" "Cleaning Up Additional Resources"
    
    echo "Checking for additional resources to clean up..."
    
    # Clean up CloudWatch Log Groups (if not managed by Terraform)
    echo -n "CloudWatch Log Groups: "
    LOG_GROUPS=$(aws logs describe-log-groups \
        --log-group-name-prefix "/aws/lambda/patch-deduplication" \
        --query 'logGroups[*].logGroupName' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$LOG_GROUPS" ]; then
        for log_group in $LOG_GROUPS; do
            echo -n "Deleting $log_group... "
            aws logs delete-log-group --log-group-name "$log_group" 2>/dev/null || true
        done
        echo -e "${GREEN}✓ Completed${NC}"
    else
        echo -e "${YELLOW}⚠️  None found${NC}"
    fi
    
    # Clean up EBS snapshots created by the system
    echo -n "EBS Snapshots (PrePatchBackup): "
    SNAPSHOTS=$(aws ec2 describe-snapshots \
        --owner-ids self \
        --filters "Name=tag:Purpose,Values=PrePatchBackup" \
        --query 'Snapshots[*].SnapshotId' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$SNAPSHOTS" ] && [ "$SNAPSHOTS" != "None" ]; then
        for snapshot in $SNAPSHOTS; do
            echo -n "Deleting $snapshot... "
            aws ec2 delete-snapshot --snapshot-id "$snapshot" 2>/dev/null || true
        done
        echo -e "${GREEN}✓ Completed${NC}"
    else
        echo -e "${YELLOW}⚠️  None found${NC}"
    fi
    
    # Clean up any remaining EventBridge rules
    echo -n "EventBridge Rules: "
    RULES=$(aws events list-rules --name-prefix "inspector-vulnerability" --query 'Rules[*].Name' --output text 2>/dev/null || echo "")
    if [ -n "$RULES" ] && [ "$RULES" != "None" ]; then
        for rule in $RULES; do
            # Remove targets first
            aws events remove-targets --rule "$rule" --ids "1" 2>/dev/null || true
            # Delete rule
            aws events delete-rule --name "$rule" 2>/dev/null || true
        done
        echo -e "${GREEN}✓ Completed${NC}"
    else
        echo -e "${YELLOW}⚠️  None found${NC}"
    fi
}

# Function to destroy Terraform-managed infrastructure
destroy_infrastructure() {
    print_step "5" "Destroying Terraform Infrastructure"
    
    cd "$TERRAFORM_DIR"
    
    echo "Applying destruction plan..."
    terraform apply destroy.tfplan
    check_status "Infrastructure destruction"
    
    # Clean up Lambda ENIs that might prevent VPC deletion
    echo "🔧 Cleaning up Lambda ENIs..."
    FUNCTION_NAME="patch-deduplication-function"
    
    aws ec2 describe-network-interfaces \
        --filters "Name=description,Values=AWS Lambda VPC ENI-${FUNCTION_NAME}*" \
        --query 'NetworkInterfaces[].NetworkInterfaceId' \
        --output text 2>/dev/null | tr '\t' '\n' | while read -r eni_id; do
        if [[ -n "$eni_id" && "$eni_id" != "None" ]]; then
            echo "Deleting Lambda ENI: $eni_id"
            aws ec2 delete-network-interface --network-interface-id "$eni_id" 2>/dev/null || true
        fi
    done
    
    # Clean up Terraform files
    rm -f destroy.tfplan
    rm -f terraform.tfplan
    
    echo -e "${GREEN}✅ All Terraform-managed resources destroyed${NC}"
}

# Function to verify cleanup completion
verify_cleanup() {
    print_step "6" "Verifying Cleanup Completion"
    
    local cleanup_issues=0
    
    # Check Lambda function
    echo -n "Lambda function: "
    if aws lambda get-function --function-name patch-deduplication-function &>/dev/null; then
        echo -e "${RED}✗ Still exists${NC}"
        cleanup_issues=$((cleanup_issues + 1))
    else
        echo -e "${GREEN}✓ Destroyed${NC}"
    fi
    
    # Check DynamoDB table
    echo -n "DynamoDB table: "
    if aws dynamodb describe-table --table-name PatchExecutionState &>/dev/null; then
        echo -e "${RED}✗ Still exists${NC}"
        cleanup_issues=$((cleanup_issues + 1))
    else
        echo -e "${GREEN}✓ Destroyed${NC}"
    fi
    
    # Check EventBridge rule
    echo -n "EventBridge rule: "
    if aws events describe-rule --name inspector-vulnerability-findings &>/dev/null; then
        echo -e "${RED}✗ Still exists${NC}"
        cleanup_issues=$((cleanup_issues + 1))
    else
        echo -e "${GREEN}✓ Destroyed${NC}"
    fi
    
    # Check SSM document
    echo -n "SSM document: "
    if aws ssm describe-document --name ImprovedPatchAutomation &>/dev/null; then
        echo -e "${RED}✗ Still exists${NC}"
        cleanup_issues=$((cleanup_issues + 1))
    else
        echo -e "${GREEN}✓ Destroyed${NC}"
    fi
    
    if [ $cleanup_issues -eq 0 ]; then
        echo -e "\n${GREEN}✅ Cleanup verification passed - all resources destroyed${NC}"
        return 0
    else
        echo -e "\n${YELLOW}⚠️  $cleanup_issues resource(s) may still exist${NC}"
        echo "These may need manual cleanup or may be managed outside of this project."
        return 1
    fi
}

# Function to clean up local files
cleanup_local_files() {
    print_step "7" "Cleaning Up Local Files"
    
    cd "$TERRAFORM_DIR"
    
    echo "Removing Terraform state and cache files..."
    
    # Remove Terraform state files (backup first)
    if [ -f "terraform.tfstate" ]; then
        echo "• Moving terraform.tfstate to backup"
        mv terraform.tfstate "$PROJECT_ROOT/cleanup-backup-$(date +%Y%m%d-%H%M%S)/" 2>/dev/null || \
        cp terraform.tfstate "$PROJECT_ROOT/terraform.tfstate.backup.$(date +%Y%m%d-%H%M%S)" || true
    fi
    
    if [ -f "terraform.tfstate.backup" ]; then
        echo "• Removing terraform.tfstate.backup"
        rm -f terraform.tfstate.backup
    fi
    
    # Remove Terraform cache
    if [ -d ".terraform" ]; then
        echo "• Removing .terraform directory"
        rm -rf .terraform
    fi
    
    # Remove lock files
    if [ -f ".terraform.lock.hcl" ]; then
        echo "• Removing .terraform.lock.hcl"
        rm -f .terraform.lock.hcl
    fi
    
    # Remove any plan files
    rm -f *.tfplan
    
    echo -e "${GREEN}✅ Local cleanup completed${NC}"
}

# Function to show final summary
show_cleanup_summary() {
    echo -e "\n${GREEN}🎉 CLEANUP COMPLETED!${NC}"
    echo "============================================================="
    echo ""
    echo "Summary:"
    echo "• ✅ All AWS resources destroyed"
    echo "• ✅ Local Terraform files cleaned"
    echo "• ✅ Critical data backed up"
    echo ""
    echo "Backup location:"
    if ls "$PROJECT_ROOT"/cleanup-backup-* &>/dev/null; then
        echo "$(ls -td "$PROJECT_ROOT"/cleanup-backup-* | head -1)"
    else
        echo "No backups created (no data found)"
    fi
    echo ""
    echo -e "${BLUE}Your AWS resources have been completely cleaned up.${NC}"
    echo "You will no longer incur charges for the vulnerability patching system."
    echo ""
    echo "To redeploy the system in the future, run:"
    echo "  ./scripts/deploy.sh"
}

# Function to handle manual cleanup guidance
show_manual_cleanup_guidance() {
    echo -e "\n${YELLOW}🔧 MANUAL CLEANUP REQUIRED${NC}"
    echo "============================================================="
    echo ""
    echo "Some resources may require manual cleanup. Please check:"
    echo ""
    echo "1. AWS Console - EC2 Service:"
    echo "   • Check for any remaining EC2 instances with 'AutoPatch' tag"
    echo "   • Verify EBS snapshots are cleaned up"
    echo ""
    echo "2. AWS Console - CloudWatch Service:"
    echo "   • Check for any remaining log groups"
    echo "   • Verify custom metrics are no longer being generated"
    echo ""
    echo "3. AWS Console - IAM Service:"
    echo "   • Check for any orphaned roles or policies"
    echo ""
    echo "4. AWS Console - VPC Service:"
    echo "   • Verify VPC and associated resources are cleaned up"
    echo ""
    echo "5. Cost Management:"
    echo "   • Check your AWS billing dashboard for any unexpected charges"
    echo ""
    echo "If you find resources that weren't cleaned up, you can:"
    echo "• Delete them manually through the AWS Console"
    echo "• Use AWS CLI commands to remove specific resources"
    echo "• Contact AWS Support if you need assistance"
}

# Main execution function
main() {
    confirm_cleanup
    check_prerequisites
    backup_data
    list_resources
    cleanup_additional_resources
    destroy_infrastructure
    
    if verify_cleanup; then
        cleanup_local_files
        show_cleanup_summary
    else
        show_manual_cleanup_guidance
        echo -e "\n${YELLOW}Cleanup completed with warnings. Please review manual cleanup guidance above.${NC}"
    fi
}

# Handle script interruption
cleanup_on_exit() {
    echo -e "\n${RED}Cleanup interrupted. Some resources may still exist.${NC}"
    echo "You may need to:"
    echo "1. Run this script again"
    echo "2. Manually clean up resources through AWS Console"
    echo "3. Check your AWS billing to ensure no unexpected charges"
    exit 1
}

trap cleanup_on_exit INT TERM

# Check if running with appropriate warnings
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly
    main "$@"
else
    # Script is being sourced
    echo -e "${YELLOW}⚠️  This script should be executed directly, not sourced.${NC}"
    echo "Run: ./scripts/cleanup.sh"
fi