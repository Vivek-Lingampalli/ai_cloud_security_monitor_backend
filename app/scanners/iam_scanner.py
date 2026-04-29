from typing import List, Dict, Any
import logging
import json
from app.utils.aws_client import get_aws_client
from app.db.schemas import FindingCreate, SeverityLevel

logger = logging.getLogger(__name__)


class IAMScanner:
    """
    IAM Security Scanner
    Scans IAM users and policies for security issues including MFA enforcement and admin access
    """
    
    def __init__(self, region: str = None):
        """
        Initialize IAM Scanner
        
        Args:
            region: AWS region to scan
        """
        self.aws_client = get_aws_client(region=region)
        self.region = region or "us-east-1"
    
    def scan(self) -> List[FindingCreate]:
        """
        Run comprehensive IAM security scan
        
        Returns:
            List of security findings
        """
        findings = []
        
        try:
            logger.info("Starting IAM security scan...")
            
            # Get all IAM users
            users = self.list_users()
            logger.info(f"Found {len(users)} IAM users")
            
            # Check for users without MFA
            mfa_findings = self._check_users_without_mfa(users)
            findings.extend(mfa_findings)
            
            # Check for admin policies
            admin_findings = self._check_admin_policies(users)
            findings.extend(admin_findings)
            
            # Check password policy
            password_findings = self._check_password_policy()
            findings.extend(password_findings)
            
            logger.info(f"IAM scan completed. Found {len(findings)} security issues")
            
        except Exception as e:
            logger.error(f"Error during IAM scan: {e}")
        
        return findings
    
    def list_users(self) -> List[Dict[str, Any]]:
        """
        List all IAM users in the account
        
        Returns:
            List of user information dictionaries
        """
        try:
            users = self.aws_client.list_users()
            logger.info(f"Listed {len(users)} IAM users")
            return users
        except Exception as e:
            logger.error(f"Failed to list IAM users: {e}")
            return []
    
    def _check_users_without_mfa(self, users: List[Dict[str, Any]]) -> List[FindingCreate]:
        """
        Check for IAM users without MFA enabled
        
        Args:
            users: List of IAM user dictionaries
            
        Returns:
            List of findings for users without MFA
        """
        findings = []
        
        for user in users:
            user_name = user.get('UserName')
            if not user_name:
                continue
            
            logger.debug(f"Checking MFA status for user: {user_name}")
            
            # Check if user has MFA devices
            mfa_devices = self.aws_client.list_mfa_devices(user_name)
            
            if not mfa_devices:
                # Check if user has console access (password last used)
                has_console_access = user.get('PasswordLastUsed') is not None
                
                # Determine severity based on whether user has console access
                severity = SeverityLevel.HIGH if has_console_access else SeverityLevel.MEDIUM
                
                description = (
                    f"IAM user '{user_name}' does not have Multi-Factor Authentication (MFA) enabled. "
                    f"MFA adds an extra layer of security to prevent unauthorized access even if credentials are compromised. "
                )
                
                if has_console_access:
                    description += (
                        f"This user has console access (last password use: {user.get('PasswordLastUsed')}), "
                        f"making this a high-priority security risk."
                    )
                else:
                    description += "This user may be using access keys for programmatic access."
                
                findings.append(FindingCreate(
                    title=f"IAM User Without MFA: {user_name}",
                    description=description,
                    severity=severity,
                    resource_type="IAM",
                    resource_id=user_name,
                    resource_arn=user.get('Arn'),
                    region="global",  # IAM is global
                    account_id=self._extract_account_id(user.get('Arn'))
                ))
                
                logger.debug(f"User {user_name} does not have MFA enabled")
            else:
                logger.debug(f"User {user_name} has {len(mfa_devices)} MFA device(s)")
        
        return findings
    
    def _check_admin_policies(self, users: List[Dict[str, Any]]) -> List[FindingCreate]:
        """
        Check for users with administrator access policies
        
        Args:
            users: List of IAM user dictionaries
            
        Returns:
            List of findings for users with admin policies
        """
        findings = []
        
        for user in users:
            user_name = user.get('UserName')
            if not user_name:
                continue
            
            logger.debug(f"Checking admin policies for user: {user_name}")
            
            has_admin_access = False
            admin_policy_sources = []
            
            # Check directly attached managed policies
            attached_policies = self.aws_client.list_attached_user_policies(user_name)
            for policy in attached_policies:
                policy_arn = policy.get('PolicyArn', '')
                policy_name = policy.get('PolicyName', '')
                
                if self._is_admin_policy(policy_arn, policy_name):
                    has_admin_access = True
                    admin_policy_sources.append(f"Attached Policy: {policy_name}")
                    logger.debug(f"User {user_name} has admin policy: {policy_name}")
            
            # Check inline policies
            inline_policies = self.aws_client.get_user_policies(user_name)
            if inline_policies:
                # For inline policies, we would need to get the policy document to check for admin access
                # For now, we'll note their existence
                for policy_name in inline_policies:
                    if 'admin' in policy_name.lower():
                        has_admin_access = True
                        admin_policy_sources.append(f"Inline Policy: {policy_name}")
            
            # Check group memberships
            groups = self.aws_client.list_groups_for_user(user_name)
            for group in groups:
                group_name = group.get('GroupName', '')
                
                # Check if group name suggests admin access
                if 'admin' in group_name.lower():
                    # Check group's attached policies
                    group_policies = self.aws_client.list_attached_group_policies(group_name)
                    for policy in group_policies:
                        policy_arn = policy.get('PolicyArn', '')
                        policy_name = policy.get('PolicyName', '')
                        
                        if self._is_admin_policy(policy_arn, policy_name):
                            has_admin_access = True
                            admin_policy_sources.append(
                                f"Group Membership: {group_name} -> Policy: {policy_name}"
                            )
            
            # Create finding if user has admin access
            if has_admin_access:
                # Check MFA status to determine severity
                mfa_devices = self.aws_client.list_mfa_devices(user_name)
                has_mfa = len(mfa_devices) > 0
                
                # Admin without MFA is CRITICAL, admin with MFA is HIGH (for tracking)
                severity = SeverityLevel.CRITICAL if not has_mfa else SeverityLevel.HIGH
                
                policy_list = "\n".join([f"  - {source}" for source in admin_policy_sources])
                
                description = (
                    f"IAM user '{user_name}' has administrator-level access to the AWS account. "
                    f"This grants full permissions to all AWS resources and services.\n\n"
                    f"Admin access granted through:\n{policy_list}\n\n"
                )
                
                if not has_mfa:
                    description += (
                        "⚠️ CRITICAL: This user does NOT have MFA enabled! "
                        "Admin users without MFA are a severe security risk. "
                        "If credentials are compromised, attackers have unrestricted access to your entire AWS account."
                    )
                else:
                    description += (
                        "✓ This user has MFA enabled, which provides additional security. "
                        "However, admin access should be granted sparingly and monitored closely. "
                        "Consider using role-based access with temporary credentials instead."
                    )
                
                findings.append(FindingCreate(
                    title=f"IAM User With Administrator Access: {user_name}" + 
                          ("" if has_mfa else " (NO MFA)"),
                    description=description,
                    severity=severity,
                    resource_type="IAM",
                    resource_id=user_name,
                    resource_arn=user.get('Arn'),
                    region="global",
                    account_id=self._extract_account_id(user.get('Arn'))
                ))
                
                logger.info(f"User {user_name} has admin access (MFA: {has_mfa})")
        
        return findings
    
    def _check_password_policy(self) -> List[FindingCreate]:
        """
        Check account password policy for security best practices
        
        Returns:
            List of findings related to password policy
        """
        findings = []
        
        try:
            policy = self.aws_client.get_account_password_policy()
            
            if not policy:
                findings.append(FindingCreate(
                    title="No IAM Password Policy Configured",
                    description=(
                        "The AWS account does not have a password policy configured. "
                        "A strong password policy is essential for preventing unauthorized access. "
                        "Recommended settings: minimum 14 characters, require uppercase, lowercase, "
                        "numbers, and symbols, password expiration, and prevent password reuse."
                    ),
                    severity=SeverityLevel.HIGH,
                    resource_type="IAM",
                    resource_id="account-password-policy",
                    resource_arn="arn:aws:iam::account:policy/password-policy",
                    region="global"
                ))
                return findings
            
            # Check password policy requirements
            issues = []
            
            min_length = policy.get('MinimumPasswordLength', 0)
            if min_length < 14:
                issues.append(
                    f"Minimum password length is {min_length} (recommended: 14+)"
                )
            
            if not policy.get('RequireSymbols', False):
                issues.append("Does not require symbols")
            
            if not policy.get('RequireNumbers', False):
                issues.append("Does not require numbers")
            
            if not policy.get('RequireUppercaseCharacters', False):
                issues.append("Does not require uppercase characters")
            
            if not policy.get('RequireLowercaseCharacters', False):
                issues.append("Does not require lowercase characters")
            
            if not policy.get('ExpirePasswords', False):
                issues.append("Passwords do not expire")
            
            reuse_prevention = policy.get('PasswordReusePrevention', 0)
            if reuse_prevention < 5:
                issues.append(
                    f"Password reuse prevention is {reuse_prevention} (recommended: 5+)"
                )
            
            if issues:
                issues_list = "\n".join([f"  - {issue}" for issue in issues])
                severity = SeverityLevel.HIGH if len(issues) >= 4 else SeverityLevel.MEDIUM
                
                findings.append(FindingCreate(
                    title="Weak IAM Password Policy",
                    description=(
                        f"The AWS account password policy does not meet security best practices. "
                        f"Weak password policies increase the risk of unauthorized access.\n\n"
                        f"Issues identified:\n{issues_list}\n\n"
                        f"Recommendation: Configure a strong password policy requiring minimum 14 characters, "
                        f"all character types (uppercase, lowercase, numbers, symbols), password expiration, "
                        f"and prevention of password reuse."
                    ),
                    severity=severity,
                    resource_type="IAM",
                    resource_id="account-password-policy",
                    resource_arn="arn:aws:iam::account:policy/password-policy",
                    region="global"
                ))
        
        except Exception as e:
            logger.error(f"Error checking password policy: {e}")
        
        return findings
    
    def _is_admin_policy(self, policy_arn: str, policy_name: str) -> bool:
        """
        Check if a policy grants administrator access
        
        Args:
            policy_arn: Policy ARN
            policy_name: Policy name
            
        Returns:
            True if policy grants admin access
        """
        # Check for AWS managed admin policies
        admin_policy_arns = [
            'arn:aws:iam::aws:policy/AdministratorAccess',
            'arn:aws:iam::aws:policy/PowerUserAccess',  # Nearly full access
        ]
        
        if policy_arn in admin_policy_arns:
            return True
        
        # Check policy name
        if 'administrator' in policy_name.lower() or 'admin' in policy_name.lower():
            # Try to get policy document to verify
            try:
                policy_details = self.aws_client.get_policy(policy_arn)
                if policy_details:
                    version_id = policy_details.get('DefaultVersionId')
                    if version_id:
                        policy_version = self.aws_client.get_policy_version(policy_arn, version_id)
                        if policy_version:
                            doc = policy_version.get('Document')
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            
                            # Check if policy grants * actions on * resources
                            statements = doc.get('Statement', [])
                            for statement in statements:
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    resources = statement.get('Resource', [])
                                    
                                    # Check for wildcard permissions
                                    if actions == '*' or '*' in actions:
                                        if resources == '*' or '*' in resources:
                                            return True
            except Exception as e:
                logger.debug(f"Could not verify policy document for {policy_name}: {e}")
            
            # If we can't verify but name suggests admin access, be conservative
            return True
        
        return False
    
    def _extract_account_id(self, arn: str) -> str:
        """
        Extract account ID from ARN
        
        Args:
            arn: AWS ARN string
            
        Returns:
            Account ID or empty string
        """
        if not arn:
            return ""
        
        try:
            # ARN format: arn:aws:service:region:account-id:resource
            parts = arn.split(':')
            if len(parts) >= 5:
                return parts[4]
        except Exception:
            pass
        
        return ""
