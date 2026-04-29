import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import Optional, Dict, Any, List
import logging
from app.config import settings

logger = logging.getLogger(__name__)


class AWSClient:
    """
    AWS Client wrapper with automatic fallback to mock mode
    Supports S3, EC2, IAM, and CloudTrail services
    """
    
    def __init__(self, region: Optional[str] = None, mock_mode: bool = False):
        """
        Initialize AWS Client
        
        Args:
            region: AWS region (defaults to settings.AWS_REGION)
            mock_mode: Force mock mode even if credentials exist
        """
        self.region = region or settings.AWS_REGION
        self.mock_mode = mock_mode
        self._session = None
        self._clients = {}
        
        # Try to initialize real AWS session
        if not mock_mode:
            try:
                self._initialize_session()
            except (NoCredentialsError, PartialCredentialsError) as e:
                logger.warning(f"AWS credentials not found: {e}. Switching to mock mode.")
                self.mock_mode = True
            except Exception as e:
                logger.warning(f"Failed to initialize AWS session: {e}. Switching to mock mode.")
                self.mock_mode = True
        
        if self.mock_mode:
            logger.info("Running in MOCK MODE - No real AWS calls will be made")
    
    def _initialize_session(self):
        """Initialize boto3 session with credentials"""
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            self._session = boto3.Session(
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=self.region
            )
        else:
            # Try to use default credentials (IAM role, env vars, etc.)
            self._session = boto3.Session(region_name=self.region)
        
        # Test credentials by making a simple STS call
        sts = self._session.client('sts')
        identity = sts.get_caller_identity()
        logger.info(f"AWS session initialized for account: {identity['Account']}")
    
    def get_client(self, service_name: str):
        """
        Get or create boto3 client for a service
        
        Args:
            service_name: AWS service name (s3, ec2, iam, cloudtrail, etc.)
            
        Returns:
            Boto3 client or None if in mock mode
        """
        if self.mock_mode:
            return None
        
        if service_name not in self._clients:
            self._clients[service_name] = self._session.client(service_name)
        
        return self._clients[service_name]
    
    def is_mock_mode(self) -> bool:
        """Check if running in mock mode"""
        return self.mock_mode
    
    # ==================== S3 Helper Functions ====================
    
    def list_s3_buckets(self) -> List[Dict[str, Any]]:
        """List all S3 buckets"""
        if self.mock_mode:
            return self._mock_s3_buckets()
        
        try:
            s3 = self.get_client('s3')
            response = s3.list_buckets()
            return response.get('Buckets', [])
        except ClientError as e:
            logger.error(f"Error listing S3 buckets: {e}")
            return []
    
    def get_bucket_acl(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Get S3 bucket ACL"""
        if self.mock_mode:
            return self._mock_bucket_acl(bucket_name)
        
        try:
            s3 = self.get_client('s3')
            return s3.get_bucket_acl(Bucket=bucket_name)
        except ClientError as e:
            logger.error(f"Error getting ACL for bucket {bucket_name}: {e}")
            return None
    
    def get_bucket_policy(self, bucket_name: str) -> Optional[str]:
        """Get S3 bucket policy"""
        if self.mock_mode:
            return None
        
        try:
            s3 = self.get_client('s3')
            response = s3.get_bucket_policy(Bucket=bucket_name)
            return response.get('Policy')
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return None
            logger.error(f"Error getting policy for bucket {bucket_name}: {e}")
            return None
    
    def get_bucket_encryption(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Get S3 bucket encryption configuration"""
        if self.mock_mode:
            return None
        
        try:
            s3 = self.get_client('s3')
            return s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return None
            logger.error(f"Error getting encryption for bucket {bucket_name}: {e}")
            return None
    
    def get_public_access_block(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Get S3 bucket public access block configuration"""
        if self.mock_mode:
            return self._mock_public_access_block(bucket_name)
        
        try:
            s3 = self.get_client('s3')
            response = s3.get_public_access_block(Bucket=bucket_name)
            return response.get('PublicAccessBlockConfiguration')
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                return None
            logger.error(f"Error getting public access block for bucket {bucket_name}: {e}")
            return None
    
    # ==================== EC2 Helper Functions ====================
    
    def describe_instances(self, filters: Optional[List[Dict]] = None) -> List[Dict[str, Any]]:
        """Describe EC2 instances"""
        if self.mock_mode:
            return self._mock_ec2_instances()
        
        try:
            ec2 = self.get_client('ec2')
            params = {}
            if filters:
                params['Filters'] = filters
            
            response = ec2.describe_instances(**params)
            instances = []
            for reservation in response.get('Reservations', []):
                instances.extend(reservation.get('Instances', []))
            return instances
        except ClientError as e:
            logger.error(f"Error describing EC2 instances: {e}")
            return []
    
    def describe_security_groups(self, group_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Describe EC2 security groups"""
        if self.mock_mode:
            return self._mock_security_groups()
        
        try:
            ec2 = self.get_client('ec2')
            params = {}
            if group_ids:
                params['GroupIds'] = group_ids
            
            response = ec2.describe_security_groups(**params)
            return response.get('SecurityGroups', [])
        except ClientError as e:
            logger.error(f"Error describing security groups: {e}")
            return []
    
    # ==================== IAM Helper Functions ====================
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List IAM users"""
        if self.mock_mode:
            return self._mock_iam_users()
        
        try:
            iam = self.get_client('iam')
            response = iam.list_users()
            return response.get('Users', [])
        except ClientError as e:
            logger.error(f"Error listing IAM users: {e}")
            return []
    
    def get_user_policies(self, user_name: str) -> List[str]:
        """Get inline policies for an IAM user"""
        if self.mock_mode:
            return []
        
        try:
            iam = self.get_client('iam')
            response = iam.list_user_policies(UserName=user_name)
            return response.get('PolicyNames', [])
        except ClientError as e:
            logger.error(f"Error getting policies for user {user_name}: {e}")
            return []
    
    def list_attached_user_policies(self, user_name: str) -> List[Dict[str, Any]]:
        """Get attached managed policies for an IAM user"""
        if self.mock_mode:
            return self._mock_attached_user_policies(user_name)
        
        try:
            iam = self.get_client('iam')
            response = iam.list_attached_user_policies(UserName=user_name)
            return response.get('AttachedPolicies', [])
        except ClientError as e:
            logger.error(f"Error getting attached policies for user {user_name}: {e}")
            return []
    
    def get_account_password_policy(self) -> Optional[Dict[str, Any]]:
        """Get account password policy"""
        if self.mock_mode:
            return self._mock_password_policy()
        
        try:
            iam = self.get_client('iam')
            response = iam.get_account_password_policy()
            return response.get('PasswordPolicy')
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return None
            logger.error(f"Error getting password policy: {e}")
            return None
    
    def list_mfa_devices(self, user_name: str) -> List[Dict[str, Any]]:
        """List MFA devices for an IAM user"""
        if self.mock_mode:
            return self._mock_mfa_devices(user_name)
        
        try:
            iam = self.get_client('iam')
            response = iam.list_mfa_devices(UserName=user_name)
            return response.get('MFADevices', [])
        except ClientError as e:
            logger.error(f"Error listing MFA devices for user {user_name}: {e}")
            return []
    
    def get_policy(self, policy_arn: str) -> Optional[Dict[str, Any]]:
        """Get IAM policy details"""
        if self.mock_mode:
            return self._mock_policy(policy_arn)
        
        try:
            iam = self.get_client('iam')
            response = iam.get_policy(PolicyArn=policy_arn)
            return response.get('Policy')
        except ClientError as e:
            logger.error(f"Error getting policy {policy_arn}: {e}")
            return None
    
    def get_policy_version(self, policy_arn: str, version_id: str) -> Optional[Dict[str, Any]]:
        """Get IAM policy version document"""
        if self.mock_mode:
            return self._mock_policy_version(policy_arn)
        
        try:
            iam = self.get_client('iam')
            response = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            return response.get('PolicyVersion')
        except ClientError as e:
            logger.error(f"Error getting policy version {policy_arn}:{version_id}: {e}")
            return None
    
    def list_groups_for_user(self, user_name: str) -> List[Dict[str, Any]]:
        """List groups for an IAM user"""
        if self.mock_mode:
            return self._mock_user_groups(user_name)
        
        try:
            iam = self.get_client('iam')
            response = iam.list_groups_for_user(UserName=user_name)
            return response.get('Groups', [])
        except ClientError as e:
            logger.error(f"Error listing groups for user {user_name}: {e}")
            return []
    
    def list_attached_group_policies(self, group_name: str) -> List[Dict[str, Any]]:
        """Get attached managed policies for an IAM group"""
        if self.mock_mode:
            return []
        
        try:
            iam = self.get_client('iam')
            response = iam.list_attached_group_policies(GroupName=group_name)
            return response.get('AttachedPolicies', [])
        except ClientError as e:
            logger.error(f"Error getting attached policies for group {group_name}: {e}")
            return []
    
    # ==================== CloudTrail Helper Functions ====================
    
    def lookup_events(self, start_time=None, end_time=None, max_results: int = 50) -> List[Dict[str, Any]]:
        """Lookup CloudTrail events"""
        if self.mock_mode:
            return self._mock_cloudtrail_events()
        
        try:
            cloudtrail = self.get_client('cloudtrail')
            params = {'MaxResults': max_results}
            if start_time:
                params['StartTime'] = start_time
            if end_time:
                params['EndTime'] = end_time
            
            response = cloudtrail.lookup_events(**params)
            return response.get('Events', [])
        except ClientError as e:
            logger.error(f"Error looking up CloudTrail events: {e}")
            return []
    
    # ==================== Mock Data Functions ====================
    
    def _mock_s3_buckets(self) -> List[Dict[str, Any]]:
        """Mock S3 buckets for testing"""
        from datetime import datetime
        return [
            {'Name': 'public-data-bucket', 'CreationDate': datetime(2024, 1, 15)},
            {'Name': 'company-logs-bucket', 'CreationDate': datetime(2024, 2, 20)},
            {'Name': 'backup-storage', 'CreationDate': datetime(2024, 3, 10)},
        ]
    
    def _mock_bucket_acl(self, bucket_name: str) -> Dict[str, Any]:
        """Mock bucket ACL"""
        # Simulate a public bucket
        if 'public' in bucket_name.lower():
            return {
                'Grants': [
                    {
                        'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                        'Permission': 'READ'
                    }
                ]
            }
        return {'Grants': []}
    
    def _mock_public_access_block(self, bucket_name: str) -> Dict[str, Any]:
        """Mock public access block config"""
        # Simulate missing public access block for public buckets
        if 'public' in bucket_name.lower():
            return {
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False
            }
        return {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    
    def _mock_ec2_instances(self) -> List[Dict[str, Any]]:
        """Mock EC2 instances"""
        return [
            {
                'InstanceId': 'i-1234567890abcdef0',
                'InstanceType': 't2.micro',
                'State': {'Name': 'running'},
                'SecurityGroups': [{'GroupId': 'sg-12345678', 'GroupName': 'web-server-sg'}],
                'PublicIpAddress': '54.123.45.67',
                'Tags': [{'Key': 'Name', 'Value': 'WebServer'}]
            },
            {
                'InstanceId': 'i-0987654321fedcba0',
                'InstanceType': 't3.medium',
                'State': {'Name': 'running'},
                'SecurityGroups': [{'GroupId': 'sg-87654321', 'GroupName': 'database-sg'}],
                'Tags': [{'Key': 'Name', 'Value': 'Database'}]
            }
        ]
    
    def _mock_security_groups(self) -> List[Dict[str, Any]]:
        """Mock security groups"""
        return [
            {
                'GroupId': 'sg-12345678',
                'GroupName': 'web-server-sg',
                'Description': 'Web server security group',
                'IpPermissions': [
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Insecure!
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            }
        ]
    
    def _mock_iam_users(self) -> List[Dict[str, Any]]:
        """Mock IAM users"""
        from datetime import datetime
        return [
            {
                'UserName': 'admin-user',
                'UserId': 'AIDAI23EXAMPLEUSER1',
                'Arn': 'arn:aws:iam::123456789012:user/admin-user',
                'CreateDate': datetime(2023, 1, 1),
                'PasswordLastUsed': datetime(2024, 4, 20)
            },
            {
                'UserName': 'developer',
                'UserId': 'AIDAI23EXAMPLEUSER2',
                'Arn': 'arn:aws:iam::123456789012:user/developer',
                'CreateDate': datetime(2023, 6, 15),
                'PasswordLastUsed': datetime(2024, 4, 22)
            },
            {
                'UserName': 'service-account',
                'UserId': 'AIDAI23EXAMPLEUSER3',
                'Arn': 'arn:aws:iam::123456789012:user/service-account',
                'CreateDate': datetime(2023, 3, 10),
                'PasswordLastUsed': datetime(2024, 4, 15)
            }
        ]
    
    def _mock_mfa_devices(self, user_name: str) -> List[Dict[str, Any]]:
        """Mock MFA devices - only admin-user has MFA"""
        from datetime import datetime
        if user_name == 'admin-user':
            return [
                {
                    'UserName': user_name,
                    'SerialNumber': f'arn:aws:iam::123456789012:mfa/{user_name}',
                    'EnableDate': datetime(2023, 1, 5)
                }
            ]
        return []  # Other users don't have MFA
    
    def _mock_attached_user_policies(self, user_name: str) -> List[Dict[str, Any]]:
        """Mock attached user policies - admin-user has admin access, developer has no admin"""
        if user_name == 'admin-user':
            return [
                {
                    'PolicyName': 'AdministratorAccess',
                    'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
                }
            ]
        elif user_name == 'developer':
            return [
                {
                    'PolicyName': 'ReadOnlyAccess',
                    'PolicyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'
                }
            ]
        return []
    
    def _mock_user_groups(self, user_name: str) -> List[Dict[str, Any]]:
        """Mock user groups"""
        if user_name == 'admin-user':
            return [
                {
                    'GroupName': 'Administrators',
                    'GroupId': 'AGPAI23EXAMPLEGROUP1',
                    'Arn': 'arn:aws:iam::123456789012:group/Administrators'
                }
            ]
        return []
    
    def _mock_policy(self, policy_arn: str) -> Dict[str, Any]:
        """Mock policy details"""
        return {
            'PolicyName': 'AdministratorAccess',
            'PolicyId': 'ANPAI23EXAMPLEPOLICY',
            'Arn': policy_arn,
            'DefaultVersionId': 'v1'
        }
    
    def _mock_policy_version(self, policy_arn: str) -> Dict[str, Any]:
        """Mock policy version document"""
        import json
        # Check if this is an admin policy
        if 'Administrator' in policy_arn or 'admin' in policy_arn.lower():
            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
        else:
            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": "*"
                    }
                ]
            }
        
        return {
            'Document': json.dumps(policy_doc),
            'IsDefaultVersion': True
        }
    
    def _mock_password_policy(self) -> Dict[str, Any]:
        """Mock weak password policy"""
        return {
            'MinimumPasswordLength': 6,  # Too short!
            'RequireSymbols': False,
            'RequireNumbers': False,
            'RequireUppercaseCharacters': False,
            'RequireLowercaseCharacters': False,
            'AllowUsersToChangePassword': True,
            'ExpirePasswords': False,
            'MaxPasswordAge': 0,
            'PasswordReusePrevention': 0
        }
    
    def _mock_cloudtrail_events(self) -> List[Dict[str, Any]]:
        """Mock CloudTrail events"""
        from datetime import datetime
        return [
            {
                'EventId': 'event-123',
                'EventName': 'ConsoleLogin',
                'EventTime': datetime(2024, 4, 23, 10, 30),
                'Username': 'admin-user',
                'Resources': [],
                'CloudTrailEvent': '{"eventVersion":"1.05","userIdentity":{"type":"IAMUser","principalId":"AIDAI23EXAMPLEUSER1","userName":"admin-user"},"eventTime":"2024-04-23T10:30:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.1","userAgent":"Mozilla/5.0","requestParameters":null,"responseElements":{"ConsoleLogin":"Success"},"additionalEventData":{"LoginTo":"https://console.aws.amazon.com/","MobileVersion":"No","MFAUsed":"No"}}'
            },
            {
                'EventId': 'event-456',
                'EventName': 'PutBucketPolicy',
                'EventTime': datetime(2024, 4, 23, 14, 15),
                'Username': 'developer',
                'Resources': [{'ResourceType': 'AWS::S3::Bucket', 'ResourceName': 'public-data-bucket'}],
                'CloudTrailEvent': '{"eventVersion":"1.05","userIdentity":{"type":"IAMUser","principalId":"AIDAI23EXAMPLEUSER2","userName":"developer"},"eventTime":"2024-04-23T14:15:00Z","eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.1","userAgent":"aws-cli/2.0.0"}'
            }
        ]


# Global instance
_aws_client: Optional[AWSClient] = None


def get_aws_client(region: Optional[str] = None, force_new: bool = False) -> AWSClient:
    """
    Get singleton AWS client instance
    
    Args:
        region: AWS region (optional)
        force_new: Create new instance instead of reusing singleton
        
    Returns:
        AWSClient instance
    """
    global _aws_client
    
    if force_new or _aws_client is None:
        _aws_client = AWSClient(region=region)
    
    return _aws_client
