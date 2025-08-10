#!/usr/bin/env python3
"""
Basic Lambda Function Tests
Tests core functionality of the vulnerability patching Lambda function
"""

import pytest
import json
import boto3
from moto import mock_dynamodb, mock_sns, mock_ssm, mock_ec2
from unittest.mock import patch, MagicMock
import sys
import os

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lambda'))

# Mock environment variables
os.environ.update({
    'STATE_TABLE_NAME': 'PatchExecutionState',
    'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic',
    'AUTOMATION_DOCUMENT_NAME': 'TestAutomation',
    'AUTOMATION_ROLE_ARN': 'arn:aws:iam::123456789012:role/TestRole',
    'MAINTENANCE_WINDOW_START': '2',
    'MAINTENANCE_WINDOW_END': '5'
})

from patch_deduplication import (
    validate_event_structure,
    parse_inspector_finding,
    is_in_maintenance_window,
    create_response
)

class TestEventValidation:
    """Test event validation functions"""
    
    def test_valid_inspector_event(self):
        """Test validation of properly formatted Inspector2 event"""
        valid_event = {
            'source': 'aws.inspector2',
            'detail-type': 'Inspector2 Finding',
            'detail': {
                'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0'}],
                'severity': 'HIGH',
                'status': 'ACTIVE',
                'type': 'PACKAGE_VULNERABILITY'
            }
        }
        
        assert validate_event_structure(valid_event) == True
    
    def test_invalid_source(self):
        """Test rejection of invalid event source"""
        invalid_event = {
            'source': 'aws.ec2',  # Wrong source
            'detail-type': 'Inspector2 Finding',
            'detail': {
                'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-test'}]
            }
        }
        
        assert validate_event_structure(invalid_event) == False
    
    def test_missing_resources(self):
        """Test handling of events missing resource information"""
        invalid_event = {
            'source': 'aws.inspector2',
            'detail-type': 'Inspector2 Finding',
            'detail': {}  # No resources
        }
        
        assert validate_event_structure(invalid_event) == False

class TestInspectorParsing:
    """Test Inspector finding parsing"""
    
    def test_parse_valid_finding(self):
        """Test parsing of complete Inspector finding"""
        event = {
            'detail': {
                'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0'}],
                'findingArn': 'arn:aws:inspector2:us-east-1:123456789012:finding/test-finding',
                'severity': 'CRITICAL',
                'title': 'Critical Apache Vulnerability',
                'packageVulnerabilityDetails': {
                    'vulnerablePackages': [{'name': 'httpd'}],
                    'cveId': 'CVE-2023-1234'
                },
                'remediation': {
                    'recommendation': {
                        'text': 'Update httpd package to version 2.4.55'
                    }
                }
            }
        }
        
        result = parse_inspector_finding(event)
        
        assert result['instance_id'] == 'i-1234567890abcdef0'
        assert result['vulnerability']['severity'] == 'CRITICAL'
        assert result['vulnerability']['cve'] == 'CVE-2023-1234'
        assert result['vulnerability']['package'] == 'httpd'
    
    def test_parse_minimal_finding(self):
        """Test parsing of minimal Inspector finding with defaults"""
        event = {
            'detail': {
                'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-minimal'}]
            }
        }
        
        result = parse_inspector_finding(event)
        
        assert result['instance_id'] == 'i-minimal'
        assert result['vulnerability']['severity'] == 'UNKNOWN'
        assert result['vulnerability']['remediation'] == 'Apply security updates'

class TestMaintenanceWindow:
    """Test maintenance window logic"""
    
    @patch('patch_deduplication.datetime')
    def test_inside_maintenance_window(self, mock_datetime):
        """Test when current time is inside maintenance window"""
        mock_datetime.now.return_value.hour = 3  # 3 AM, inside 2-5 AM window
        
        assert is_in_maintenance_window() == True
    
    @patch('patch_deduplication.datetime')  
    def test_outside_maintenance_window(self, mock_datetime):
        """Test when current time is outside maintenance window"""
        mock_datetime.now.return_value.hour = 10  # 10 AM, outside 2-5 AM window
        
        assert is_in_maintenance_window() == False
    
    @patch('patch_deduplication.datetime')
    def test_maintenance_window_crossing_midnight(self, mock_datetime):
        """Test maintenance window that crosses midnight"""
        # Mock environment for 22:00-02:00 window
        with patch.dict(os.environ, {'MAINTENANCE_WINDOW_START': '22', 'MAINTENANCE_WINDOW_END': '2'}):
            mock_datetime.now.return_value.hour = 23  # 11 PM
            assert is_in_maintenance_window() == True
            
            mock_datetime.now.return_value.hour = 1   # 1 AM  
            assert is_in_maintenance_window() == True
            
            mock_datetime.now.return_value.hour = 10  # 10 AM
            assert is_in_maintenance_window() == False

class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_create_response_with_dict(self):
        """Test response creation with dictionary body"""
        response_data = {'message': 'success', 'execution_id': 'exec-123'}
        response = create_response(200, response_data)
        
        assert response['statusCode'] == 200
        assert 'message' in response['body']
        assert 'X-Request-ID' in response['headers']
    
    def test_create_response_with_string(self):
        """Test response creation with string body"""
        response = create_response(400, 'Invalid request')
        
        assert response['statusCode'] == 400
        assert response['body'] == 'Invalid request'

@mock_dynamodb
@mock_sns
@mock_ec2
class TestIntegrationScenarios:
    """Integration test scenarios with mocked AWS services"""
    
    def setup_method(self):
        """Set up mock AWS resources"""
        # DynamoDB
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        self.table = self.dynamodb.create_table(
            TableName='PatchExecutionState',
            KeySchema=[{'AttributeName': 'instance_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'instance_id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # SNS
        self.sns = boto3.client('sns', region_name='us-east-1')
        self.topic = self.sns.create_topic(Name='patch-notifications')
        
        # EC2
        self.ec2 = boto3.client('ec2', region_name='us-east-1')
    
    def test_dynamodb_state_management(self):
        """Test DynamoDB state management operations"""
        from patch_deduplication import table
        
        # Test item creation
        test_item = {
            'instance_id': 'i-test123',
            'status': 'IN_PROGRESS',
            'started_at': '2024-01-01T10:00:00',
            'expiration_time': 1704110400
        }
        
        # Put item
        table.put_item(Item=test_item)
        
        # Get item
        response = table.get_item(Key={'instance_id': 'i-test123'})
        assert 'Item' in response
        assert response['Item']['status'] == 'IN_PROGRESS'

if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '--tb=short'])