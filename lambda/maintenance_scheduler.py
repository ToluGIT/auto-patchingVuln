import json
import boto3
import os
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['STATE_TABLE_NAME'])
lambda_client = boto3.client('lambda')

# Configuration from environment variables
MAINTENANCE_START = int(os.environ.get('MAINTENANCE_WINDOW_START', '2'))
MAINTENANCE_END = int(os.environ.get('MAINTENANCE_WINDOW_END', '7'))
DEDUPLICATION_FUNCTION_NAME = os.environ['DEDUPLICATION_FUNCTION_NAME']

def lambda_handler(event, context):
    """
    Maintenance scheduler Lambda function
    Runs every hour during maintenance window to process scheduled patches
    """
    logger.info(f"Maintenance scheduler started at {datetime.utcnow().isoformat()}")
    logger.info(f"Current maintenance window: {MAINTENANCE_START}:00 - {MAINTENANCE_END}:00 UTC")
    
    try:
        # Check if we're currently in maintenance window
        if not is_in_maintenance_window():
            logger.info("Outside maintenance window, skipping scheduled patch processing")
            return create_response(200, "Outside maintenance window")
        
        # Get all scheduled patch operations
        scheduled_patches = get_scheduled_patches()
        
        if not scheduled_patches:
            logger.info("No scheduled patches found")
            return create_response(200, "No scheduled patches")
        
        logger.info(f"Found {len(scheduled_patches)} scheduled patch operations")
        
        # Process each scheduled patch
        processed_count = 0
        failed_count = 0
        
        for patch_item in scheduled_patches:
            try:
                if should_process_patch(patch_item):
                    process_scheduled_patch(patch_item)
                    processed_count += 1
                else:
                    logger.info(f"Skipping patch for {patch_item['instance_id']} - not yet time or conditions not met")
            except Exception as e:
                logger.error(f"Failed to process scheduled patch for {patch_item['instance_id']}: {str(e)}")
                failed_count += 1
        
        result = {
            'processed': processed_count,
            'failed': failed_count,
            'total_scheduled': len(scheduled_patches)
        }
        
        logger.info(f"Maintenance scheduler completed: {json.dumps(result)}")
        return create_response(200, result)
        
    except Exception as e:
        logger.exception(f"Error in maintenance scheduler: {str(e)}")
        return create_response(500, f"Error: {str(e)}")

def is_in_maintenance_window():
    """Check if current time is within maintenance window"""
    current_hour = datetime.utcnow().hour
    logger.info(f"Current hour: {current_hour}, Maintenance window: {MAINTENANCE_START}-{MAINTENANCE_END}")
    
    # Handle maintenance windows that cross midnight
    if MAINTENANCE_START > MAINTENANCE_END:
        in_window = current_hour >= MAINTENANCE_START or current_hour < MAINTENANCE_END
    else:
        in_window = MAINTENANCE_START <= current_hour < MAINTENANCE_END
    
    logger.info(f"In maintenance window: {in_window}")
    return in_window

def get_scheduled_patches():
    """Get all items with SCHEDULED status from DynamoDB"""
    try:
        # Scan for all items with status = SCHEDULED
        response = table.scan(
            FilterExpression='#status = :scheduled',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':scheduled': 'SCHEDULED'}
        )
        
        return response.get('Items', [])
        
    except Exception as e:
        logger.error(f"Error getting scheduled patches: {str(e)}")
        return []

def should_process_patch(patch_item):
    """
    Determine if a scheduled patch should be processed now
    """
    try:
        # Check if scheduled time has passed
        scheduled_for = patch_item.get('scheduled_for')
        if not scheduled_for:
            logger.warning(f"No scheduled_for time for {patch_item['instance_id']}")
            return False
        
        scheduled_time = datetime.fromisoformat(scheduled_for.replace('Z', '+00:00'))
        current_time = datetime.utcnow().replace(tzinfo=scheduled_time.tzinfo)
        
        # Process if scheduled time has passed
        if current_time >= scheduled_time:
            logger.info(f"Patch for {patch_item['instance_id']} is due (scheduled: {scheduled_time}, current: {current_time})")
            return True
        
        logger.info(f"Patch for {patch_item['instance_id']} not yet due (scheduled: {scheduled_time}, current: {current_time})")
        return False
        
    except Exception as e:
        logger.error(f"Error checking patch schedule for {patch_item['instance_id']}: {str(e)}")
        return False

def process_scheduled_patch(patch_item):
    """
    Process a scheduled patch by invoking the main deduplication Lambda
    """
    instance_id = patch_item['instance_id']
    vulnerabilities = patch_item.get('vulnerabilities', [])
    
    logger.info(f"Processing scheduled patch for instance {instance_id}")
    
    # Create a synthetic Inspector event for the scheduled patch
    # Use the first vulnerability as the trigger, others will be queued
    if not vulnerabilities:
        logger.warning(f"No vulnerabilities found for scheduled patch {instance_id}")
        # Mark as failed and return
        mark_patch_failed(instance_id, "No vulnerabilities found")
        return
    
    primary_vuln = vulnerabilities[0]
    
    # Create synthetic EventBridge event
    synthetic_event = {
        'source': 'aws.inspector2',
        'detail-type': 'Inspector2 Finding',
        'detail': {
            'findingArn': primary_vuln.get('finding_id', 'scheduled-patch'),
            'severity': primary_vuln.get('severity', 'HIGH'),
            'title': f"Scheduled patch processing for {instance_id}",
            'resources': [{'id': instance_id}],
            'packageVulnerabilityDetails': {
                'vulnerablePackages': [{'name': primary_vuln.get('package', 'unknown')}],
                'cveId': primary_vuln.get('cve', 'unknown')
            },
            'remediation': {
                'recommendation': {
                    'text': 'Apply security updates via scheduled maintenance'
                }
            }
        }
    }
    
    try:
        # Update status to indicate processing has started
        update_patch_status(instance_id, 'PROCESSING_SCHEDULED', {
            'processing_started_at': datetime.utcnow().isoformat(),
            'original_status': 'SCHEDULED'
        })
        
        # Invoke the main deduplication Lambda function
        response = lambda_client.invoke(
            FunctionName=DEDUPLICATION_FUNCTION_NAME,
            InvocationType='Event',  # Async invocation
            Payload=json.dumps(synthetic_event)
        )
        
        logger.info(f"Successfully invoked deduplication Lambda for {instance_id}")
        
        # The main Lambda will handle updating the status to IN_PROGRESS or FAILED
        
    except Exception as e:
        logger.error(f"Failed to process scheduled patch for {instance_id}: {str(e)}")
        mark_patch_failed(instance_id, f"Failed to invoke processing: {str(e)}")
        raise

def update_patch_status(instance_id, new_status, additional_data=None):
    """Update patch status in DynamoDB"""
    try:
        update_expression = 'SET #status = :status, updated_at = :updated_at'
        expression_values = {
            ':status': new_status,
            ':updated_at': datetime.utcnow().isoformat()
        }
        
        if additional_data:
            for key, value in additional_data.items():
                update_expression += f', {key} = :{key}'
                expression_values[f':{key}'] = value
        
        table.update_item(
            Key={'instance_id': instance_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues=expression_values
        )
        
        logger.info(f"Updated status for {instance_id} to {new_status}")
        
    except Exception as e:
        logger.error(f"Error updating patch status for {instance_id}: {str(e)}")
        raise

def mark_patch_failed(instance_id, error_message):
    """Mark a scheduled patch as failed"""
    try:
        update_patch_status(instance_id, 'FAILED', {
            'failed_at': datetime.utcnow().isoformat(),
            'error': error_message
        })
        
    except Exception as e:
        logger.error(f"Error marking patch as failed for {instance_id}: {str(e)}")

def create_response(status_code, body):
    """Create Lambda response"""
    if isinstance(body, dict):
        body = json.dumps(body, default=str)
    
    return {
        'statusCode': status_code,
        'body': body,
        'headers': {
            'Content-Type': 'application/json'
        }
    }