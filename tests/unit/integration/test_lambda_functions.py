import pytest
import json
import boto3
from moto import mock_dynamodb, mock_sns, mock_ssm, mock_ec2
from unittest.mock import patch, MagicMock
import sys
import os

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../lambda'))
from patch_deduplication import lambda_handler, validate_event_structure, parse_inspector_finding

class TestLambdaValidation:
    def test_validate_event_structure_valid(self):
        """Test valid Inspector2 event structure"""
        valid_event = {
            'source': 'aws.inspector2',
            'detail-type': 'Inspector2 Finding',
            'detail': {
                'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0'}],
                'severity': 'HIGH',
                'status': 'ACTIVE'
            }
        }
        assert validate_event_structure(valid_event) == True

    def test_validate_event_structure_invalid_source(self):
        """Test invalid event source"""
        invalid_event = {
            'source': 'aws.ec2',
            'detail-type': 'Inspector2 Finding',
            'detail': {'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-test'}]}
        }
        assert validate_event_structure(invalid_event) == False

    def test_validate_event_structure_missing_resources(self):
        """Test missing resources in event"""
        invalid_event = {
            'source': 'aws.inspector2',
            'detail-type': 'Inspector2 Finding',
            'detail': {}
        }
        assert validate_event_structure(invalid_event) == False

    def test_parse_inspector_finding_valid(self):
        """Test parsing valid Inspector finding"""
        event = {
            'detail': {
                'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0'}],
                'findingArn': 'arn:aws:inspector2:us-east-1:123456789012:finding/test-finding',
                'severity': 'HIGH',
                'title': 'Test Vulnerability',
                'packageVulnerabilityDetails': {
                    'vulnerablePackages': [{'name': 'test-package'}],
                    'cveId': 'CVE-2023-1234'
                }
            }
        }
        
        result = parse_inspector_finding(event)
        
        assert result['instance_id'] == 'i-1234567890abcdef0'
        assert result['vulnerability']['severity'] == 'HIGH'
        assert result['vulnerability']['cve'] == 'CVE-2023-1234'

@mock_dynamodb
@mock_sns
@mock_ssm
@mock_ec2
class TestLambdaIntegration:
    def setup_method(self):
        """Set up mock AWS services"""
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        self.sns = boto3.client('sns', region_name='us-east-1')
        self.ssm = boto3.client('ssm', region_name='us-east-1')
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
        
        # Create mock DynamoDB table
        self.table = self.dynamodb.create_table(
            TableName='PatchExecutionState',
            KeySchema=[{'AttributeName': 'instance_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'instance_id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # Create mock SNS topic
        self.topic = self.sns.create_topic(Name='patch-notifications')
        
        # Set environment variables
        os.environ['STATE_TABLE_NAME'] = 'PatchExecutionState'
        os.environ['SNS_TOPIC_ARN'] = self.topic['TopicArn']
        os.environ['AUTOMATION_DOCUMENT_NAME'] = 'TestAutomation'
        os.environ['AUTOMATION_ROLE_ARN'] = 'arn:aws:iam::123456789012:role/TestRole'

    def test_lambda_handler_invalid_event(self):
        """Test lambda handler with invalid event"""
        invalid_event = {'source': 'invalid'}
        context = MagicMock()
        context.aws_request_id = 'test-request-id'
        
        response = lambda_handler(invalid_event, context)
        
        assert response['statusCode'] == 400
        assert 'Invalid event structure' in response['body']

# Run tests
if __name__ == '__main__':
    pytest.main([__file__])