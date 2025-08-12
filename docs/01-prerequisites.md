# Prerequisites and Environment Setup

## Required Tools

### 1. Development Environment
```bash
# Install required tools
brew install terraform        # v1.5+
brew install awscli          # v2.x
brew install python          # 3.9+
pip install boto3 botocore   # Latest
```

### 2. AWS Account Setup
- **AWS Account**: Free tier sufficient for testing
- **Estimated Cost**: $10-25/month during development
- **Required Regions**: Choose one (us-east-1 recommended for learning)

### 3. Local Development Setup
```bash
# Create project directory
mkdir aws-vulnerability-patching-portfolio
cd aws-vulnerability-patching-portfolio

# Initialize git repository
git init
echo "*.tfstate*" >> .gitignore
echo "*.zip" >> .gitignore
echo ".terraform/" >> .gitignore
echo "__pycache__/" >> .gitignore
```

## AWS Configuration

### 1. Create IAM User for Development
```bash
# Create IAM user with programmatic access
aws iam create-user --user-name vulnerability-automation-dev

# Create access keys (save these securely!)
aws iam create-access-key --user-name vulnerability-automation-dev

# Attach necessary policies for development
aws iam attach-user-policy \
  --user-name vulnerability-automation-dev \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
```

### 2. Configure AWS CLI
```bash
# Configure AWS credentials
aws configure
# Enter your Access Key ID
# Enter your Secret Access Key  
# Enter your default region (e.g., us-east-1)
# Enter default output format: json

# Verify configuration
aws sts get-caller-identity
```

### 3. Enable Required AWS Services
```bash
# Enable Inspector V2
aws inspector2 enable --resource-types EC2 ECR

# Verify Inspector is enabled
aws inspector2 get-configuration
```

## Development Environment Validation

### Test AWS Connectivity
```bash
# Test basic AWS access
aws ec2 describe-regions

# Test Terraform
terraform version

# Test Python/Boto3
python3 -c "import boto3; print('Boto3 version:', boto3.__version__)"
```

## Security Considerations for Development

### 1. Credential Management
```bash
# Create .aws/credentials file with profiles
[development]
aws_access_key_id = YOUR_DEV_KEY
aws_secret_access_key = YOUR_DEV_SECRET
region = us-east-1

# Use profile in commands
export AWS_PROFILE=development
```

### 2. Resource Tagging Strategy
All resources will be tagged with:
- `Environment = dev`
- `Project = vulnerability-automation`
- `Owner = ToluGIT` - change based on your prefered option
- `Purpose = Learning`


## Troubleshooting Common Setup Issues

### Issue: AWS CLI Not Configured
```bash
# Solution: Reconfigure with proper credentials
aws configure list
aws configure --profile development
```

### Issue: Terraform Provider Issues
```bash
# Solution: Clear Terraform cache
rm -rf .terraform/
terraform init
```

### Issue: Python Import Errors
```bash
# Solution: Install in virtual environment
python3 -m venv venv
source venv/bin/activate
pip install boto3 botocore
```

## Next Steps
Refer to 02 for the next steps
