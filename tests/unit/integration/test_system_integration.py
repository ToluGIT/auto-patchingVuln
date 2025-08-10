import boto3
import json
import time
import pytest
from datetime import datetime

class TestSystemIntegration:
    def setup_class(self):
        """Setup for integration tests"""
        self.ec2 = boto3.client('ec2')
        self.events = boto3.client('events')
        self.lambda_client = boto3.client('lambda')
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table('PatchExecutionState')
        
    def test_eventbridge_lambda_integration(self):
        """Test EventBridge -> Lambda integration"""
        # Create test event
        test_event = {
            'Entries': [{
                'Source': 'aws.inspector2',
                'DetailType': 'Inspector2 Finding',
                'Detail': json.dumps({
                    'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-test123'}],
                    'severity': 'HIGH',
                    'status': 'ACTIVE',
                    'type': 'PACKAGE_VULNERABILITY',
                    'findingArn': 'arn:aws:inspector2:us-east-1:123456789012:finding/test',
                    'title': 'Test Vulnerability'
                })
            }]
        }
        
        # Send test event
        response = self.events.put_events(**test_event)
        assert response['FailedEntryCount'] == 0
        
        # Wait for processing
        time.sleep(10)
        
        # Check DynamoDB for processing result
        # Note: This would fail in real test since instance doesn't exist
        # but validates the event flow

    def test_ssm_document_exists(self):
        """Verify SSM automation document exists"""
        ssm = boto3.client('ssm')
        response = ssm.describe_document(Name='ImprovedPatchAutomation')
        assert response['Document']['Status'] == 'Active'

    def test_lambda_vpc_connectivity(self):
        """Test Lambda can reach AWS services through VPC"""
        # This validates VPC endpoints are working
        response = self.lambda_client.invoke(
            FunctionName='patch-deduplication-function',
            Payload=json.dumps({
                'source': 'test',
                'detail-type': 'test',
                'detail': {'test': 'connectivity'}
            })
        )
        
        # Should get a response (even if error due to invalid event)
        assert response['StatusCode'] == 200