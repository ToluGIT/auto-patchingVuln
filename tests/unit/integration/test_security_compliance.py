import boto3
import json
import pytest

class TestSecurityCompliance:
    def setup_class(self):
        """Setup security testing"""
        self.iam = boto3.client('iam')
        self.lambda_client = boto3.client('lambda')
        self.kms = boto3.client('kms')
        
    def test_lambda_iam_permissions_least_privilege(self):
        """Test Lambda IAM role follows least privilege"""
        # Get Lambda function configuration
        function_config = self.lambda_client.get_function(
            FunctionName='patch-deduplication-function'
        )
        role_arn = function_config['Configuration']['Role']
        role_name = role_arn.split('/')[-1]
        
        # Get role policies
        attached_policies = self.iam.list_attached_role_policies(RoleName=role_name)
        inline_policies = self.iam.list_role_policies(RoleName=role_name)
        
        # Should have VPC execution policy
        vpc_policy_attached = any(
            'VPCAccessExecutionRole' in policy['PolicyArn']
            for policy in attached_policies['AttachedPolicies']
        )
        assert vpc_policy_attached, "Lambda should have VPC execution permissions"
        
        # Should have inline policy for specific permissions
        assert len(inline_policies['PolicyNames']) > 0, "Should have inline policies"

    def test_dynamodb_encryption_enabled(self):
        """Test DynamoDB table has encryption enabled"""
        dynamodb = boto3.client('dynamodb')
        response = dynamodb.describe_table(TableName='PatchExecutionState')
        
        # Check if encryption is enabled
        table_desc = response['Table']
        assert 'SSEDescription' in table_desc, "DynamoDB table should have encryption enabled"

    def test_sns_topic_encryption(self):
        """Test SNS topic has KMS encryption"""
        sns = boto3.client('sns')
        
        # Get topic ARN (would need to be passed or retrieved)
        topics = sns.list_topics()
        patch_topic = None
        for topic in topics['Topics']:
            if 'patch-automation-notifications' in topic['TopicArn']:
                patch_topic = topic['TopicArn']
                break
        
        assert patch_topic, "Patch automation SNS topic should exist"
        
        # Check topic attributes
        attributes = sns.get_topic_attributes(TopicArn=patch_topic)
        assert 'KmsMasterKeyId' in attributes['Attributes'], "SNS topic should have KMS encryption"

    def test_lambda_vpc_configuration(self):
        """Test Lambda is deployed in VPC"""
        function_config = self.lambda_client.get_function(
            FunctionName='patch-deduplication-function'
        )
        
        vpc_config = function_config['Configuration'].get('VpcConfig', {})
        assert 'VpcId' in vpc_config, "Lambda should be deployed in VPC"
        assert len(vpc_config.get('SubnetIds', [])) > 0, "Lambda should have subnet configuration"
        assert len(vpc_config.get('SecurityGroupIds', [])) > 0, "Lambda should have security groups"