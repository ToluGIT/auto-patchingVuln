import json
import boto3
import os
import time
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
import logging
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['STATE_TABLE_NAME'])
ssm = boto3.client('ssm')
sns = boto3.client('sns')
ec2 = boto3.client('ec2')

# Configuration from environment variables
MAINTENANCE_START = int(os.environ.get('MAINTENANCE_WINDOW_START', '2'))
MAINTENANCE_END = int(os.environ.get('MAINTENANCE_WINDOW_END', '5'))
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
AUTOMATION_DOCUMENT = os.environ['AUTOMATION_DOCUMENT_NAME']
AUTOMATION_ROLE_ARN = os.environ['AUTOMATION_ROLE_ARN']

def lambda_handler(event, context):
    """
    Main handler for processing Inspector findings
    """
    logger.info(f"Received event: {json.dumps(event, default=str)}")
    
    try:
        # Validate input event
        if not validate_event_structure(event):
            logger.error("Invalid event structure")
            return create_response(400, "Invalid event structure")
        
        # Parse Inspector finding
        finding_detail = parse_inspector_finding(event)
        instance_id = finding_detail['instance_id']
        
        logger.info(f"Processing finding for instance: {instance_id}")
        
        # Check if instance is already being patched
        patch_status = check_patch_status(instance_id)
        
        if patch_status == 'IN_PROGRESS':
            logger.info(f"Patch already in progress for {instance_id}, queueing vulnerability")
            queue_vulnerability(instance_id, finding_detail['vulnerability'])
            return create_response(200, "Vulnerability queued for existing patch operation")
        
        if patch_status == 'RECENTLY_COMPLETED':
            logger.info(f"Instance {instance_id} was recently patched, skipping")
            return create_response(200, "Instance recently patched, skipping")
        
        # Check maintenance window
        if not is_in_maintenance_window():
            logger.info(f"Outside maintenance window, scheduling patch for {instance_id}")
            schedule_for_maintenance(instance_id, finding_detail['vulnerability'])
            return create_response(200, "Patch scheduled for maintenance window")
        
        # Validate instance
        if not validate_instance(instance_id):
            logger.error(f"Instance {instance_id} validation failed")
            send_notification(
                "Instance Validation Failed",
                f"Instance {instance_id} failed validation checks for patching"
            )
            return create_response(400, "Instance validation failed")
        
        # Lock instance for patching
        if not acquire_patch_lock(instance_id, finding_detail['vulnerability'], context.aws_request_id):
            logger.error(f"Failed to acquire lock for {instance_id}")
            return create_response(409, "Failed to acquire patch lock")
        
        # Create pre-patch snapshot
        snapshot_ids = create_snapshots(instance_id)
        
        # Start patch automation
        execution_id = start_patch_automation(instance_id, snapshot_ids)
        
        # Send start notification
        send_notification(
            f"Patch Automation Started - {instance_id}",
            f"Automation ID: {execution_id}\nSnapshots: {snapshot_ids}\nSeverity: {finding_detail['vulnerability']['severity']}"
        )
        
        return create_response(200, {
            'message': 'Patch automation started successfully',
            'execution_id': execution_id,
            'instance_id': instance_id,
            'snapshots': snapshot_ids
        })
        
    except Exception as e:
        logger.exception(f"Error processing finding: {str(e)}")
        send_notification(
            "Patch Automation Error",
            f"Error processing finding: {str(e)}"
        )
        return create_response(500, f"Error: {str(e)}")

def validate_event_structure(event):
    """Validate incoming EventBridge event structure"""
    try:
        required_fields = ['detail', 'source', 'detail-type']
        for field in required_fields:
            if field not in event:
                logger.error(f"Missing required field: {field}")
                return False
        
        if event.get('source') != 'aws.inspector2':
            logger.error(f"Invalid source: {event.get('source')}")
            return False
        
        detail = event['detail']
        if 'resources' not in detail or not detail['resources']:
            logger.error("No resources in event detail")
            return False
        
        # Check if we have a valid resource identifier (ARN or instance ID)
        resource_id = detail['resources'][0].get('id', '')
        if not resource_id:
            logger.error("Missing resource ID in event detail")
            return False
        
        # Accept both full ARN format and instance ID format
        is_valid_arn = resource_id.startswith('arn:aws:ec2:')
        is_valid_instance_id = resource_id.startswith('i-') and len(resource_id) >= 10
        
        if not (is_valid_arn or is_valid_instance_id):
            logger.error(f"Invalid resource identifier: {resource_id}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating event structure: {str(e)}")
        return False

def parse_inspector_finding(event):
    """Extract relevant information from Inspector finding"""
    detail = event['detail']
    
    # Extract instance ID from resource identifier (ARN or instance ID)
    resource_id = detail['resources'][0]['id']
    
    try:
        if resource_id.startswith('arn:aws:ec2:'):
            # Extract instance ID from full ARN
            instance_id = resource_id.split('/')[-1]
            if not instance_id.startswith('i-') or len(instance_id) < 10:
                raise ValueError("Invalid instance ID in ARN")
        elif resource_id.startswith('i-') and len(resource_id) >= 10:
            # Already an instance ID
            instance_id = resource_id
        else:
            raise ValueError("Invalid resource identifier format")
            
        logger.info(f"Extracted instance ID: {instance_id} from resource: {resource_id}")
        
    except (IndexError, ValueError) as e:
        logger.error(f"Failed to extract instance ID from resource: {resource_id}")
        raise ValueError(f"Invalid resource identifier format: {resource_id}")
    
    vulnerability = {
        'finding_id': detail.get('findingArn', 'unknown'),
        'severity': detail.get('severity', 'UNKNOWN'),
        'title': detail.get('title', 'Unknown vulnerability'),
        'package': detail.get('packageVulnerabilityDetails', {}).get('vulnerablePackages', [{}])[0].get('name', 'unknown'),
        'cve': detail.get('packageVulnerabilityDetails', {}).get('cveId', 'unknown'),
        'remediation': detail.get('remediation', {}).get('recommendation', {}).get('text', 'Apply security updates'),
        'timestamp': datetime.now().isoformat()
    }
    
    return {
        'instance_id': instance_id,
        'vulnerability': vulnerability
    }

def check_patch_status(instance_id):
    """Check if instance is already being patched or was recently patched"""
    try:
        response = table.get_item(Key={'instance_id': instance_id})
        
        if 'Item' not in response:
            return 'NOT_FOUND'
        
        item = response['Item']
        status = item['status']
        
        if status == 'IN_PROGRESS':
            return 'IN_PROGRESS'
        
        if status == 'COMPLETED':
            completed_time = datetime.fromisoformat(item['completed_at'])
            if datetime.now() - completed_time < timedelta(hours=6):
                return 'RECENTLY_COMPLETED'
        
        return 'AVAILABLE'
        
    except Exception as e:
        logger.error(f"Error checking patch status: {str(e)}")
        return 'ERROR'

def queue_vulnerability(instance_id, vulnerability):
    """Add vulnerability to queue for existing patch operation"""
    try:
        table.update_item(
            Key={'instance_id': instance_id},
            UpdateExpression='SET queued_vulnerabilities = list_append(if_not_exists(queued_vulnerabilities, :empty_list), :vuln)',
            ExpressionAttributeValues={
                ':vuln': [vulnerability],
                ':empty_list': []
            }
        )
        logger.info(f"Queued vulnerability for {instance_id}")
    except Exception as e:
        logger.error(f"Error queueing vulnerability: {str(e)}")

def is_in_maintenance_window():
    """Check if current time is within maintenance window"""
    current_hour = datetime.now().hour
    
    # Handle maintenance windows that cross midnight
    if MAINTENANCE_START > MAINTENANCE_END:
        return current_hour >= MAINTENANCE_START or current_hour < MAINTENANCE_END
    else:
        return MAINTENANCE_START <= current_hour < MAINTENANCE_END

def validate_instance(instance_id):
    """Validate instance is ready for patching"""
    try:
        # Check instance exists and is running
        response = ec2.describe_instances(InstanceIds=[instance_id])
        
        if not response['Reservations']:
            logger.error(f"Instance {instance_id} not found")
            return False
        
        instance = response['Reservations'][0]['Instances'][0]
        
        if instance['State']['Name'] != 'running':
            logger.error(f"Instance {instance_id} is not running: {instance['State']['Name']}")
            return False
        
        # Check if instance has AutoPatch tag
        tags = instance.get('Tags', [])
        patch_enabled = any(tag['Key'] == 'AutoPatch' and tag['Value'].lower() == 'true' for tag in tags)
        
        if not patch_enabled:
            logger.info(f"Instance {instance_id} not tagged for auto-patching")
            return False
        
        # Check SSM agent status
        ssm_response = ssm.describe_instance_information(
            Filters=[
                {
                    'Key': 'InstanceIds',
                    'Values': [instance_id]
                }
            ]
        )
        
        if not ssm_response['InstanceInformationList']:
            logger.error(f"SSM agent not available on {instance_id}")
            return False
        
        agent_info = ssm_response['InstanceInformationList'][0]
        if agent_info['PingStatus'] != 'Online':
            logger.error(f"SSM agent not online on {instance_id}: {agent_info['PingStatus']}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating instance: {str(e)}")
        return False

def acquire_patch_lock(instance_id, vulnerability, request_id):
    """Acquire lock for patching instance"""
    try:
        # Generate unique lock ID
        lock_id = f"{request_id}-{int(time.time())}"
        
        item = {
            'instance_id': instance_id,
            'status': 'IN_PROGRESS',
            'started_at': datetime.now().isoformat(),
            'vulnerabilities': [vulnerability],
            'queued_vulnerabilities': [],
            'expiration_time': int(time.time() + 7200),  # 2 hour TTL
            'lock_id': lock_id,
            'request_id': request_id
        }
        
        # Conditional put to prevent race conditions
        table.put_item(
            Item=item,
            ConditionExpression='attribute_not_exists(instance_id) OR #status <> :in_progress',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':in_progress': 'IN_PROGRESS'}
        )
        
        logger.info(f"Acquired patch lock for {instance_id} with lock ID: {lock_id}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.warning(f"Lock already exists for {instance_id}")
            return False
        logger.error(f"Error acquiring lock: {str(e)}")
        raise

def create_snapshots(instance_id):
    """Create EBS snapshots before patching"""
    try:
        # Get instance volumes
        response = ec2.describe_instances(InstanceIds=[instance_id])
        volumes = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                for mapping in instance['BlockDeviceMappings']:
                    if 'Ebs' in mapping:
                        volumes.append({
                            'VolumeId': mapping['Ebs']['VolumeId'],
                            'Device': mapping['DeviceName']
                        })
        
        # Create snapshots
        snapshot_ids = []
        for volume in volumes:
            try:
                response = ec2.create_snapshot(
                    VolumeId=volume['VolumeId'],
                    Description=f'Pre-patch snapshot for {instance_id} - {volume["Device"]}',
                    TagSpecifications=[
                        {
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'Name', 'Value': f'PrePatch-{instance_id}-{datetime.now().strftime("%Y%m%d-%H%M%S")}'},
                                {'Key': 'InstanceId', 'Value': instance_id},
                                {'Key': 'Purpose', 'Value': 'PrePatchBackup'},
                                {'Key': 'Device', 'Value': volume['Device']},
                                {'Key': 'AutoDelete', 'Value': 'true'}
                            ]
                        }
                    ]
                )
                snapshot_ids.append(response['SnapshotId'])
                logger.info(f"Created snapshot {response['SnapshotId']} for volume {volume['VolumeId']}")
            except Exception as e:
                logger.error(f"Failed to create snapshot for volume {volume['VolumeId']}: {str(e)}")
        
        return ','.join(snapshot_ids) if snapshot_ids else "NONE"
        
    except Exception as e:
        logger.error(f"Error creating snapshots: {str(e)}")
        # Continue without snapshots but log the error
        send_notification(
            "Snapshot Creation Failed",
            f"Failed to create snapshots for {instance_id}: {str(e)}"
        )
        return "NONE"

def start_patch_automation(instance_id, snapshot_ids):
    """Start SSM automation for patching with enhanced parameter support"""
    try:
        # Base parameters
        parameters = {
            'InstanceId': [instance_id],
            'SnapshotId': [snapshot_ids],
            'AutomationAssumeRole': [AUTOMATION_ROLE_ARN],
            'SnsTopicArn': [SNS_TOPIC_ARN]
        }
        
        # Enhanced: Support for optional BaselineId and PatchGroup from environment
        baseline_id = os.environ.get('PATCH_BASELINE_ID', '')
        patch_group = os.environ.get('PATCH_GROUP', '')
        
        if baseline_id:
            parameters['BaselineId'] = [baseline_id]
            logger.info(f"Using custom patch baseline: {baseline_id}")
        
        if patch_group:
            parameters['PatchGroup'] = [patch_group]
            logger.info(f"Using patch group: {patch_group}")
        
        response = ssm.start_automation_execution(
            DocumentName=AUTOMATION_DOCUMENT,
            Parameters=parameters
        )
        
        execution_id = response['AutomationExecutionId']
        logger.info(f"Started automation execution: {execution_id}")
        return execution_id
        
    except Exception as e:
        logger.error(f"Error starting automation: {str(e)}")
        # Update state to failed
        try:
            table.update_item(
                Key={'instance_id': instance_id},
                UpdateExpression='SET #status = :failed, failed_at = :time, error = :error',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':failed': 'FAILED',
                    ':time': datetime.now().isoformat(),
                    ':error': str(e)
                }
            )
        except Exception as db_e:
            logger.error(f"Failed to update status to FAILED: {str(db_e)}")
        raise

def schedule_for_maintenance(instance_id, vulnerability):
    """Schedule patch for next maintenance window"""
    next_window = calculate_next_maintenance_window()
    
    # Store in DynamoDB with scheduled status
    item = {
        'instance_id': instance_id,
        'status': 'SCHEDULED',
        'scheduled_for': next_window.isoformat(),
        'vulnerabilities': [vulnerability],
        'expiration_time': int(next_window.timestamp() + 86400)  # Expire 1 day after scheduled time
    }
    
    try:
        table.put_item(Item=item)
        logger.info(f"Scheduled patch for {instance_id} at {next_window}")
    except Exception as e:
        logger.error(f"Error scheduling patch: {str(e)}")

def calculate_next_maintenance_window():
    """Calculate next maintenance window start time"""
    now = datetime.now()
    next_window = now.replace(hour=MAINTENANCE_START, minute=0, second=0, microsecond=0)
    
    # If we've passed today's window, schedule for tomorrow
    if now.hour >= MAINTENANCE_END:
        next_window += timedelta(days=1)
    
    return next_window

def send_notification(subject, message):
    """Send SNS notification with rate limiting"""
    try:
        # Simple rate limiting - could be enhanced with Redis/DynamoDB
        notification_key = f"notification_{hash(subject + message) % 1000}"
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[Patch Automation] {subject}",
            Message=f"{message}\n\nTimestamp: {datetime.now().isoformat()}"
        )
        logger.info(f"Sent notification: {subject}")
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")

def create_response(status_code, body):
    """Create Lambda response"""
    if isinstance(body, dict):
        body = json.dumps(body)
    
    return {
        'statusCode': status_code,
        'body': body,
        'headers': {
            'Content-Type': 'application/json',
            'X-Request-ID': str(uuid.uuid4())
        }
    }