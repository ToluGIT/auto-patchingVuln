
# **Common Issues & Solutions**

### **Deployment Issues**

#### **Issue 1: Terraform Init Fails**
```
Error: Failed to query available provider packages
```

**Root Cause**: Network connectivity or provider version issues

**Solution**:
```bash
# Clear Terraform cache
rm -rf .terraform/
rm .terraform.lock.hcl

# Re-initialize with specific provider version
terraform init -upgrade

# If behind corporate proxy
export HTTPS_PROXY=your-proxy:port
export HTTP_PROXY=your-proxy:port
terraform init
```

#### **Issue 2: VPC Creation Fails - Insufficient Availability Zones**
```
Error: Not enough subnets available (have 1, need at least 2)
```

**Root Cause**: Region doesn't have enough AZs

**Solution**:
```bash
# Check available AZs
aws ec2 describe-availability-zones --query 'AvailabilityZones[*].ZoneName'

# Switch to region with more AZs (us-east-1, us-west-2, eu-west-1)
# Update terraform.tfvars:
aws_region = "us-east-1"
```

#### **Issue 3: Lambda Deployment Fails - Package Too Large**
```
Error: InvalidParameterValueException: Unzipped size must be smaller than 262144000 bytes
```

**Root Cause**: Lambda deployment package exceeds size limits

**Solution**:
```bash
# Check package size
ls -la terraform/lambda_package.zip

# Remove unnecessary files from lambda directory
cd lambda
rm -rf __pycache__ *.pyc tests/

# Rebuild package
cd ../terraform
terraform apply
```

### **Runtime Issues**

#### **Issue 4: Lambda Function Timeouts**
```
Task timed out after 300.00 seconds
```

**Root Cause**: VPC networking delays or long-running operations

**Solution**:
```bash
# Check Lambda configuration
aws lambda get-function-configuration --function-name patch-deduplication-function

# Increase timeout in Terraform
# In enhanced-main.tf:
timeout = 900  # Increase to 15 minutes

# Check VPC endpoint connectivity
aws ec2 describe-vpc-endpoints --filters "Name=service-name,Values=com.amazonaws.us-east-1.dynamodb"
```

#### **Issue 5: DynamoDB Conditional Check Failed**
```
ConditionalCheckFailedException: The conditional request failed
```

**Root Cause**: Race condition with multiple simultaneous events (this is expected behavior)

**This is Normal**: The system is designed to prevent duplicate patching operations

**Verification**:
```bash
# Check DynamoDB item
aws dynamodb get-item \
  --table-name PatchExecutionState \
  --key '{"instance_id":{"S":"i-1234567890abcdef0"}}'

# Should show IN_PROGRESS status
```

#### **Issue 6: SSM Agent Not Available**
```
SSM agent not available on i-1234567890abcdef0
```

**Root Cause**: EC2 instance doesn't have SSM agent or proper IAM role

**Solution**:
```bash
# Check instance has correct IAM role
aws ec2 describe-instances \
  --instance-ids i-1234567890abcdef0 \
  --query 'Reservations[0].Instances[0].IamInstanceProfile'

# Should show EC2-SSM-Profile

# If missing, attach the profile
aws ec2 associate-iam-instance-profile \
  --instance-id i-1234567890abcdef0 \
  --iam-instance-profile Name=EC2-SSM-Profile

# Check SSM agent status
aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=i-1234567890abcdef0"
```

### **Permissions Issues**

#### **Issue 7: AccessDenied Errors in Lambda**
```
An error occurred (AccessDenied) when calling the DescribeInstances operation
```

**Root Cause**: IAM permissions too restrictive or missing

**Diagnosis**:
```bash
# Check Lambda execution role
aws lambda get-function \
  --function-name patch-deduplication-function \
  --query 'Configuration.Role'

# Get role name and check policies
ROLE_ARN=$(aws lambda get-function --function-name patch-deduplication-function --query 'Configuration.Role' --output text)
ROLE_NAME=$(echo $ROLE_ARN | awk -F'/' '{print $NF}')

aws iam list-role-policies --role-name $ROLE_NAME
aws iam list-attached-role-policies --role-name $ROLE_NAME
```

**Solution**:
```bash
# Update IAM policy in terraform/policies/lambda-execution-policy.json
# Ensure instance has AutoPatch tag
aws ec2 create-tags \
  --resources i-1234567890abcdef0 \
  --tags Key=AutoPatch,Value=true
```

### **Monitoring Issues**

#### **Issue 8: No Metrics in CloudWatch**
**Root Cause**: Metrics not being generated or wrong namespace

**Solution**:
```bash
# Check if Lambda is being invoked
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=patch-deduplication-function \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum

# Manually invoke Lambda to generate metrics
aws lambda invoke \
  --function-name patch-deduplication-function \
  --payload '{"test": "event"}' \
  response.json
```

#### **Issue 9: SNS Notifications Not Received**
**Root Cause**: Email subscription not confirmed or topic misconfigured

**Solution**:
```bash
# Check subscription status
aws sns list-subscriptions-by-topic \
  --topic-arn $(terraform output -raw sns_topic_arn)

# Should show "ConfirmationWasAuthenticated": true

# Re-send confirmation if needed
aws sns subscribe \
  --topic-arn $(terraform output -raw sns_topic_arn) \
  --protocol email \
  --notification-endpoint toluidni@gmail.com 
```

---

## **Performance Optimization**

### **Lambda Optimization**

#### **Memory and Timeout Tuning**
```bash
# Monitor Lambda performance
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=patch-deduplication-function \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Average,Maximum,Minimum

# Optimize memory based on results
# If average duration < 30s and max memory used < 256MB:
aws lambda update-function-configuration \
  --function-name patch-deduplication-function \
  --memory-size 256 \
  --timeout 600
```

#### **VPC Configuration Optimization**
```bash
# Check VPC endpoint usage
aws ec2 describe-vpc-endpoints \
  --filters "Name=service-name,Values=com.amazonaws.us-east-1.dynamodb" \
  --query 'VpcEndpoints[*].[VpcEndpointId,State,ServiceName]'

# Monitor NAT gateway costs
aws cloudwatch get-metric-statistics \
  --namespace AWS/NATGateway \
  --metric-name BytesInFromDestination \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 86400 \
  --statistics Sum
```

### **Cost Optimization**

#### **DynamoDB Optimization**
```bash
# Analyze DynamoDB usage patterns
aws cloudwatch get-metric-statistics \
  --namespace AWS/DynamoDB \
  --metric-name ConsumedReadCapacityUnits \
  --dimensions Name=TableName,Value=PatchExecutionState \
  --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 86400 \
  --statistics Maximum,Average

# Consider switching to provisioned capacity if usage is predictable
```

#### **Snapshot Lifecycle Management**
```bash
# Create lifecycle policy for automated snapshot deletion
aws dlm create-lifecycle-policy \
  --execution-role-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/DLMServiceRole \
  --description "Delete patch automation snapshots after 7 days" \
  --state ENABLED \
  --policy-details '{
    "ResourceTypes": ["SNAPSHOT"],
    "TargetTags": [{"Key": "Purpose", "Value": "PrePatchBackup"}],
    "Schedules": [{
      "Name": "Daily snapshots",
      "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
      "RetainRule": {"Count": 7}
    }]
  }'
```

---

