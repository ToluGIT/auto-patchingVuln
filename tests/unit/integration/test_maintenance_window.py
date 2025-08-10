#!/usr/bin/env python3
import boto3
import json
from datetime import datetime

def test_maintenance_window():
    """Test maintenance window logic"""
    lambda_client = boto3.client('lambda')
    
    # Get current hour
    current_hour = datetime.now().hour
    print(f"Current hour: {current_hour}")
    
    # Test event outside maintenance window
    test_event = {
        "source": "aws.inspector2",
        "detail-type": "Inspector2 Finding",
        "detail": {
            "resources": [{"id": "arn:aws:ec2:us-east-1:123456789012:instance/i-test"}],
            "severity": "HIGH",
            "status": "ACTIVE",
            "type": "PACKAGE_VULNERABILITY"
        }
    }
    
    print("🧪 Testing Lambda function with current time...")
    response = lambda_client.invoke(
        FunctionName='patch-deduplication-function',
        Payload=json.dumps(test_event)
    )
    
    result = json.loads(response['Payload'].read())
    print(f"Response: {result}")
    
    # Check if it's in maintenance window
    if 2 <= current_hour < 5:  # Default maintenance window
        print("✅ Currently IN maintenance window - patching should proceed")
    else:
        print("⏰ Currently OUTSIDE maintenance window - patching should be scheduled")

if __name__ == '__main__':
    test_maintenance_window()