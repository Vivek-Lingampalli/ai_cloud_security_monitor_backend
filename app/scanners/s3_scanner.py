from typing import List, Dict, Any
import logging
from app.utils.aws_client import get_aws_client
from app.db.schemas import FindingCreate, SeverityLevel

logger = logging.getLogger(__name__)


class S3Scanner:
    """
    S3 Security Scanner
    Scans S3 buckets for security issues including public access
    """
    
    def __init__(self, region: str = None):
        """
        Initialize S3 Scanner
        
        Args:
            region: AWS region to scan
        """
        self.aws_client = get_aws_client(region=region)
        self.region = region or "us-east-1"
    
    def scan(self) -> List[FindingCreate]:
        """
        Run comprehensive S3 security scan
        
        Returns:
            List of security findings
        """
        findings = []
        
        try:
            logger.info("Starting S3 security scan...")
            
            # Get all S3 buckets
            buckets = self.list_buckets()
            logger.info(f"Found {len(buckets)} S3 buckets")
            
            # Scan each bucket for security issues
            for bucket in buckets:
                bucket_name = bucket.get('Name')
                if not bucket_name:
                    continue
                
                logger.debug(f"Scanning bucket: {bucket_name}")
                
                # Check for public access issues
                public_findings = self._check_public_access(bucket_name, bucket)
                findings.extend(public_findings)
                
                # Check for encryption
                encryption_findings = self._check_encryption(bucket_name, bucket)
                findings.extend(encryption_findings)
            
            logger.info(f"S3 scan completed. Found {len(findings)} security issues")
            
        except Exception as e:
            logger.error(f"Error during S3 scan: {e}")
        
        return findings
    
    def list_buckets(self) -> List[Dict[str, Any]]:
        """
        List all S3 buckets in the account
        
        Returns:
            List of bucket information dictionaries
        """
        try:
            buckets = self.aws_client.list_s3_buckets()
            logger.info(f"Listed {len(buckets)} S3 buckets")
            return buckets
        except Exception as e:
            logger.error(f"Failed to list S3 buckets: {e}")
            return []
    
    def _check_public_access(self, bucket_name: str, bucket_info: Dict[str, Any]) -> List[FindingCreate]:
        """
        Check if bucket has public access enabled
        
        Args:
            bucket_name: Name of the S3 bucket
            bucket_info: Bucket information dictionary
            
        Returns:
            List of findings related to public access
        """
        findings = []
        
        # Check Public Access Block configuration
        public_access_block = self.aws_client.get_public_access_block(bucket_name)
        if public_access_block:
            if not all([
                public_access_block.get('BlockPublicAcls', False),
                public_access_block.get('IgnorePublicAcls', False),
                public_access_block.get('BlockPublicPolicy', False),
                public_access_block.get('RestrictPublicBuckets', False)
            ]):
                findings.append(FindingCreate(
                    title=f"S3 Bucket Public Access Block Not Fully Enabled: {bucket_name}",
                    description=f"The S3 bucket '{bucket_name}' does not have all Public Access Block settings enabled. "
                               f"This could allow public access to bucket contents. "
                               f"Settings: BlockPublicAcls={public_access_block.get('BlockPublicAcls')}, "
                               f"IgnorePublicAcls={public_access_block.get('IgnorePublicAcls')}, "
                               f"BlockPublicPolicy={public_access_block.get('BlockPublicPolicy')}, "
                               f"RestrictPublicBuckets={public_access_block.get('RestrictPublicBuckets')}",
                    severity=SeverityLevel.HIGH,
                    resource_type="S3",
                    resource_id=bucket_name,
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    region=self.region
                ))
        else:
            # No public access block configured at all
            findings.append(FindingCreate(
                title=f"S3 Bucket Missing Public Access Block: {bucket_name}",
                description=f"The S3 bucket '{bucket_name}' has no Public Access Block configuration. "
                           f"This is a critical security risk as it may allow unrestricted public access.",
                severity=SeverityLevel.CRITICAL,
                resource_type="S3",
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                region=self.region
            ))
        
        # Check bucket ACL for public grants
        acl = self.aws_client.get_bucket_acl(bucket_name)
        if acl and 'Grants' in acl:
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')
                
                # Check for AllUsers or AuthenticatedUsers
                if grantee.get('Type') == 'Group':
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri:
                        findings.append(FindingCreate(
                            title=f"S3 Bucket Publicly Accessible via ACL: {bucket_name}",
                            description=f"The S3 bucket '{bucket_name}' grants {permission} permission to AllUsers (anyone on the internet). "
                                       f"This is a critical security vulnerability. Bucket contents may be publicly accessible.",
                            severity=SeverityLevel.CRITICAL,
                            resource_type="S3",
                            resource_id=bucket_name,
                            resource_arn=f"arn:aws:s3:::{bucket_name}",
                            region=self.region
                        ))
                    elif 'AuthenticatedUsers' in uri:
                        findings.append(FindingCreate(
                            title=f"S3 Bucket Accessible to All Authenticated AWS Users: {bucket_name}",
                            description=f"The S3 bucket '{bucket_name}' grants {permission} permission to all authenticated AWS users. "
                                       f"This allows any AWS account holder to access this bucket.",
                            severity=SeverityLevel.HIGH,
                            resource_type="S3",
                            resource_id=bucket_name,
                            resource_arn=f"arn:aws:s3:::{bucket_name}",
                            region=self.region
                        ))
        
        # Check bucket policy for public access
        policy = self.aws_client.get_bucket_policy(bucket_name)
        if policy:
            import json
            try:
                policy_doc = json.loads(policy)
                statements = policy_doc.get('Statement', [])
                
                for statement in statements:
                    principal = statement.get('Principal', {})
                    effect = statement.get('Effect', '')
                    
                    # Check for wildcard principal with Allow effect
                    if effect == 'Allow':
                        if principal == '*' or principal.get('AWS') == '*':
                            findings.append(FindingCreate(
                                title=f"S3 Bucket Policy Allows Public Access: {bucket_name}",
                                description=f"The S3 bucket '{bucket_name}' has a bucket policy that allows public access (Principal: *). "
                                           f"Action: {statement.get('Action', 'N/A')}. This could expose sensitive data.",
                                severity=SeverityLevel.CRITICAL,
                                resource_type="S3",
                                resource_id=bucket_name,
                                resource_arn=f"arn:aws:s3:::{bucket_name}",
                                region=self.region
                            ))
            except json.JSONDecodeError:
                logger.warning(f"Could not parse bucket policy for {bucket_name}")
        
        return findings
    
    def _check_encryption(self, bucket_name: str, bucket_info: Dict[str, Any]) -> List[FindingCreate]:
        """
        Check if bucket has encryption enabled
        
        Args:
            bucket_name: Name of the S3 bucket
            bucket_info: Bucket information dictionary
            
        Returns:
            List of findings related to encryption
        """
        findings = []
        
        encryption = self.aws_client.get_bucket_encryption(bucket_name)
        if not encryption:
            findings.append(FindingCreate(
                title=f"S3 Bucket Encryption Not Enabled: {bucket_name}",
                description=f"The S3 bucket '{bucket_name}' does not have default encryption enabled. "
                           f"Data stored in this bucket is not encrypted at rest, which could lead to data exposure.",
                severity=SeverityLevel.MEDIUM,
                resource_type="S3",
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                region=self.region
            ))
        
        return findings
    
    def get_bucket_details(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific bucket
        
        Args:
            bucket_name: Name of the S3 bucket
            
        Returns:
            Dictionary with bucket details
        """
        details = {
            'name': bucket_name,
            'region': self.region,
            'public_access_block': self.aws_client.get_public_access_block(bucket_name),
            'acl': self.aws_client.get_bucket_acl(bucket_name),
            'policy': self.aws_client.get_bucket_policy(bucket_name),
            'encryption': self.aws_client.get_bucket_encryption(bucket_name),
        }
        
        return details
