# Deployment Guide

## Step-by-Step Deployment Process

### Phase 1: Pre-Deployment Preparation

#### 1.1 Configure Your Environment
```bash
# Navigate to project directory
cd aws-vulnerability-patching-portfolio

# Set AWS profile (if using multiple profiles)
export AWS_PROFILE=development

# Verify AWS connectivity
aws sts get-caller-identity
```

#### 1.2 Create Terraform Variables File
```bash

# Edit with your specific values
nano terraform/terraform.tfvars
```

**Required `terraform.tfvars` content:**
```hcl
aws_region = "us-east-1"  # Change to your preferred region
environment = "dev"
notification_email = "toluidni@gmail.com"  # CHANGE THIS
maintenance_window_start = 2  # 2 AM
maintenance_window_end = 5    # 5 AM
enable_snapshot_before_patch = true
project_name = "vulnerability-automation"
```

#### 1.3 Validate All Files Are Present
```bash
# Check project structure
find . -type f -name "*.tf" -o -name "*.py" -o -name "*.json" -o -name "*.yaml" | sort

# Expected files:
# ./lambda/patch_deduplication.py
# ./documents/improved-patch-automation.yaml
# ./terraform/enhanced-main.tf
# ./terraform/variables.tf
# ./terraform/outputs.tf
# ./terraform/policies/*.json
```

### Phase 2: Terraform Deployment

#### 2.1 Initialize Terraform
```bash
cd terraform

# Initialize Terraform (downloads providers)
terraform init

# Expected output: "Terraform has been successfully initialized!"
```

#### 2.2 Plan the Deployment
```bash
# Create execution plan
terraform plan -var-file="terraform.tfvars"

# Review the plan carefully 
# Look for any errors or warnings
```

**What to verify in the plan:**
- VPC and subnets are being created
- Two Lambda functions with VPC configuration (main + scheduler)
- DynamoDB table with encryption and scheduling support
- SNS topic with KMS encryption
- IAM roles with restrictive policies
- EventBridge rules for Inspector2 and maintenance scheduling
- CloudWatch alarms and dashboard

#### 2.3 Deploy Infrastructure
```bash
# Apply the configuration (this will take 5-10 minutes)
terraform apply -var-file="terraform.tfvars"

# Type 'yes' when prompted
```


#### 2.4 Verify Deployment Success
```bash
# Check Terraform outputs
terraform output

# Verify key resources
aws lambda get-function --function-name patch-deduplication-function
aws lambda get-function --function-name patch-maintenance-scheduler
aws dynamodb describe-table --table-name PatchExecutionState
aws ssm describe-document --name ImprovedPatchAutomation
aws events describe-rule --name patch-maintenance-scheduler
```

### Phase 3: Post-Deployment Configuration

#### 3.1 Confirm SNS Subscription
```bash
# Check your email for SNS subscription confirmation
# Click the confirmation link in the email

# Verify subscription is confirmed
aws sns list-subscriptions-by-topic \
  --topic-arn $(terraform output -raw sns_topic_arn)
```

#### 3.2 Enable Inspector2 Scanning
```bash
# Verify Inspector2 is enabled
aws inspector2 get-configuration

# If not enabled, enable it:
aws inspector2 enable --resource-types EC2 ECR
```


### Phase 4: Create Test EC2 Instance

#### 4.1 Create Test Instance with Proper Configuration
```bash
# Get the instance profile name from Terraform output
INSTANCE_PROFILE=$(terraform output -raw ec2_instance_profile_name)

# Create test instance (using Amazon Linux 2)
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t3.micro \
  --iam-instance-profile Name=$INSTANCE_PROFILE \
  --security-group-ids $(aws ec2 describe-security-groups --filters "Name=group-name,Values=default" --query "SecurityGroups[0].GroupId" --output text) \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=VulnTestInstance},{Key=AutoPatch,Value=true},{Key=Environment,Value=dev}]' \
  --user-data '#!/bin/bash
yum update -y
yum install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
# Install some packages with known vulnerabilities for testing
yum install -y httpd
systemctl enable httpd'
```

#### 4.2 Verify Instance Setup
```bash
# Wait 2-3 minutes for instance to boot, then check SSM connectivity
aws ssm describe-instance-information --filters "Key=tag:Name,Values=VulnTestInstance"

# Should show the instance as "Online" after a few minutes
```

### Phase 5: Monitoring Setup

#### 5.1 Access CloudWatch Dashboard
```bash
# Get dashboard URL
echo $(terraform output -raw dashboard_url)

# Open in browser to view metrics
```

#### 5.2 Set Up CloudWatch Logs Monitoring
```bash
# View main Lambda logs
aws logs tail /aws/lambda/patch-deduplication-function --follow

# View scheduler Lambda logs (in another terminal)
aws logs tail /aws/lambda/patch-maintenance-scheduler --follow

# View SSM logs (in another terminal)
aws logs tail /aws/ssm/patch-automation --follow
```

### Common Deployment Issues & Solutions

#### Issue 1: Terraform Plan Shows Errors
**Symptoms:** `terraform plan` fails with validation errors
**Solution:**
```bash
# Check variable values
terraform console
> var.notification_email

# Validate email format
# Fix terraform.tfvars file
```

#### Issue 2: Lambda Function Not Created
**Symptoms:** Lambda function deployment fails
**Solution:**
```bash
# Check if zip file exists
ls -la terraform/lambda_package.zip

# Recreate if missing
cd terraform
terraform refresh
terraform plan
```

#### Issue 3: VPC Creation Fails
**Symptoms:** VPC or subnet creation errors
**Solution:**
```bash
# Check availability zones
aws ec2 describe-availability-zones --query 'AvailabilityZones[*].ZoneName'

# Ensure region has at least 2 AZs
# Change region if needed in terraform.tfvars
```

#### Issue 4: IAM Permission Errors
**Symptoms:** Access denied errors during deployment
**Solution:**
```bash
# Verify IAM user permissions
aws iam get-user-policy --user-name vulnerability-automation-dev --policy-name PowerUserAccess

# If using roles, check assume role permissions
aws sts get-caller-identity
```

### Success Criteria

Your deployment is successful when:
- All Terraform resources created without errors
- Lambda function shows "Active" state
- DynamoDB table shows "ACTIVE" status
- SNS email subscription confirmed
- EventBridge rule is "ENABLED"
- Test EC2 instance appears in SSM
- CloudWatch dashboard accessible
- No errors in CloudWatch logs


### Cleanup (When Done Testing)

```bash
# Destroy all resources to avoid charges
terraform destroy -var-file="terraform.tfvars"

Or 
#Run the cleanup script directly 

cd ./scripts/cleanup.sh 

# Verify all resources are deleted
aws resourcegroupstaggingapi get-resources --tag-filters Key=Environment,Values=dev
```

**Estimated total deployment time: 15-20 minutes**
**Estimated monthly cost: $10-25 (during testing)**