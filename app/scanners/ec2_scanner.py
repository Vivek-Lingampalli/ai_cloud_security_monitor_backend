from typing import List, Dict, Any, Set
import logging
from app.utils.aws_client import get_aws_client
from app.db.schemas import FindingCreate, SeverityLevel

logger = logging.getLogger(__name__)


class EC2Scanner:
    """
    EC2 Security Scanner
    Scans EC2 instances and security groups for security issues including open ports
    """
    
    # Ports that should never be open to 0.0.0.0/0
    CRITICAL_PORTS = {
        22: 'SSH',
        3389: 'RDP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        1433: 'MSSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        9200: 'Elasticsearch',
        5601: 'Kibana',
        8080: 'HTTP Alt',
        8443: 'HTTPS Alt',
        23: 'Telnet',
        21: 'FTP',
        445: 'SMB',
        135: 'RPC',
        137: 'NetBIOS',
        139: 'NetBIOS',
    }
    
    def __init__(self, region: str = None):
        """
        Initialize EC2 Scanner
        
        Args:
            region: AWS region to scan
        """
        self.aws_client = get_aws_client(region=region)
        self.region = region or "us-east-1"
    
    def scan(self) -> List[FindingCreate]:
        """
        Run comprehensive EC2 security scan
        
        Returns:
            List of security findings
        """
        findings = []
        
        try:
            logger.info("Starting EC2 security scan...")
            
            # Get all security groups
            security_groups = self.list_security_groups()
            logger.info(f"Found {len(security_groups)} security groups")
            
            # Check for open ports to 0.0.0.0/0
            sg_findings = self._check_security_group_rules(security_groups)
            findings.extend(sg_findings)
            
            # Get all EC2 instances
            instances = self.list_instances()
            logger.info(f"Found {len(instances)} EC2 instances")
            
            # Check for instances with public IPs and insecure security groups
            instance_findings = self._check_instance_exposure(instances, security_groups)
            findings.extend(instance_findings)
            
            logger.info(f"EC2 scan completed. Found {len(findings)} security issues")
            
        except Exception as e:
            logger.error(f"Error during EC2 scan: {e}")
        
        return findings
    
    def list_instances(self) -> List[Dict[str, Any]]:
        """
        List all EC2 instances
        
        Returns:
            List of instance information dictionaries
        """
        try:
            instances = self.aws_client.describe_instances()
            logger.info(f"Listed {len(instances)} EC2 instances")
            return instances
        except Exception as e:
            logger.error(f"Failed to list EC2 instances: {e}")
            return []
    
    def list_security_groups(self) -> List[Dict[str, Any]]:
        """
        List all security groups
        
        Returns:
            List of security group information dictionaries
        """
        try:
            security_groups = self.aws_client.describe_security_groups()
            logger.info(f"Listed {len(security_groups)} security groups")
            return security_groups
        except Exception as e:
            logger.error(f"Failed to list security groups: {e}")
            return []
    
    def _check_security_group_rules(self, security_groups: List[Dict[str, Any]]) -> List[FindingCreate]:
        """
        Check security group rules for open ports to 0.0.0.0/0
        
        Args:
            security_groups: List of security group dictionaries
            
        Returns:
            List of findings for insecure security group rules
        """
        findings = []
        
        for sg in security_groups:
            group_id = sg.get('GroupId')
            group_name = sg.get('GroupName', 'Unknown')
            vpc_id = sg.get('VpcId', 'No VPC')
            
            if not group_id:
                continue
            
            logger.debug(f"Checking security group: {group_id} ({group_name})")
            
            # Check inbound rules (IpPermissions)
            inbound_rules = sg.get('IpPermissions', [])
            for rule in inbound_rules:
                open_findings = self._check_rule_for_open_access(
                    rule, group_id, group_name, vpc_id, 'Inbound'
                )
                findings.extend(open_findings)
            
            # Check outbound rules (IpPermissionsEgress) - less critical but still important
            outbound_rules = sg.get('IpPermissionsEgress', [])
            for rule in outbound_rules:
                # Only flag outbound if it's unrestricted on critical ports
                if self._is_unrestricted_outbound(rule):
                    finding = FindingCreate(
                        title=f"Security Group Allows Unrestricted Outbound Traffic: {group_name}",
                        description=(
                            f"Security group '{group_name}' ({group_id}) allows unrestricted outbound traffic "
                            f"to 0.0.0.0/0 on all ports and protocols. While less critical than inbound rules, "
                            f"this could allow compromised instances to communicate with any external destination. "
                            f"VPC: {vpc_id}"
                        ),
                        severity=SeverityLevel.LOW,
                        resource_type="EC2",
                        resource_id=group_id,
                        resource_arn=f"arn:aws:ec2:{self.region}::security-group/{group_id}",
                        region=self.region
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_rule_for_open_access(
        self, 
        rule: Dict[str, Any], 
        group_id: str, 
        group_name: str,
        vpc_id: str,
        direction: str
    ) -> List[FindingCreate]:
        """
        Check a single security group rule for open access to 0.0.0.0/0
        
        Args:
            rule: Security group rule dictionary
            group_id: Security group ID
            group_name: Security group name
            vpc_id: VPC ID
            direction: 'Inbound' or 'Outbound'
            
        Returns:
            List of findings for this rule
        """
        findings = []
        
        # Get IP ranges
        ip_ranges = rule.get('IpRanges', [])
        ipv6_ranges = rule.get('Ipv6Ranges', [])
        
        # Check for 0.0.0.0/0 or ::/0
        has_open_ipv4 = any(ip.get('CidrIp') == '0.0.0.0/0' for ip in ip_ranges)
        has_open_ipv6 = any(ip.get('CidrIpv6') == '::/0' for ip in ipv6_ranges)
        
        if not (has_open_ipv4 or has_open_ipv6):
            return findings
        
        # Get protocol and port information
        ip_protocol = rule.get('IpProtocol', '-1')
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        
        # Handle different protocol scenarios
        if ip_protocol == '-1':
            # All protocols and ports are open
            findings.append(FindingCreate(
                title=f"Security Group Wide Open to Internet: {group_name}",
                description=(
                    f"Security group '{group_name}' ({group_id}) allows {direction.lower()} traffic "
                    f"from 0.0.0.0/0 on ALL protocols and ALL ports. This is extremely dangerous "
                    f"and exposes all services to the internet. VPC: {vpc_id}\n\n"
                    f"Immediate action required: Restrict access to specific IP ranges and ports only."
                ),
                severity=SeverityLevel.CRITICAL,
                resource_type="EC2",
                resource_id=group_id,
                resource_arn=f"arn:aws:ec2:{self.region}::security-group/{group_id}",
                region=self.region
            ))
        elif from_port is not None and to_port is not None:
            # Specific port range
            port_range = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
            
            # Check each port in the range
            for port in range(from_port, to_port + 1):
                severity, protocol_name = self._classify_port_risk(port, ip_protocol)
                
                if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                    open_to = "0.0.0.0/0 (IPv4)" if has_open_ipv4 else ""
                    if has_open_ipv6:
                        open_to += " and ::/0 (IPv6)" if open_to else "::/0 (IPv6)"
                    
                    findings.append(FindingCreate(
                        title=f"Security Group Exposes {protocol_name} Port to Internet: {group_name}",
                        description=(
                            f"Security group '{group_name}' ({group_id}) allows {direction.lower()} traffic "
                            f"on {protocol_name} port {port}/{ip_protocol} from {open_to}. "
                            f"This exposes sensitive services to potential attacks from the entire internet. "
                            f"VPC: {vpc_id}\n\n"
                            f"Recommendation: Restrict access to specific trusted IP addresses or use a VPN/bastion host. "
                            f"Never expose administrative or database ports to the public internet."
                        ),
                        severity=severity,
                        resource_type="EC2",
                        resource_id=group_id,
                        resource_arn=f"arn:aws:ec2:{self.region}::security-group/{group_id}",
                        region=self.region
                    ))
                elif port == 80 or port == 443:
                    # HTTP/HTTPS are common but still worth noting
                    findings.append(FindingCreate(
                        title=f"Security Group Allows Public {protocol_name} Access: {group_name}",
                        description=(
                            f"Security group '{group_name}' ({group_id}) allows {direction.lower()} traffic "
                            f"on {protocol_name} port {port} from 0.0.0.0/0. While common for web servers, "
                            f"ensure this is intentional and that the service is properly secured. "
                            f"VPC: {vpc_id}"
                        ),
                        severity=SeverityLevel.INFO,
                        resource_type="EC2",
                        resource_id=group_id,
                        resource_arn=f"arn:aws:ec2:{self.region}::security-group/{group_id}",
                        region=self.region
                    ))
        
        return findings
    
    def _classify_port_risk(self, port: int, protocol: str) -> tuple:
        """
        Classify the risk level of an open port
        
        Args:
            port: Port number
            protocol: IP protocol (tcp, udp, etc.)
            
        Returns:
            Tuple of (SeverityLevel, protocol_name)
        """
        if port in self.CRITICAL_PORTS:
            return SeverityLevel.CRITICAL, self.CRITICAL_PORTS[port]
        elif port == 80:
            return SeverityLevel.INFO, 'HTTP'
        elif port == 443:
            return SeverityLevel.INFO, 'HTTPS'
        elif port < 1024:
            return SeverityLevel.HIGH, f'Privileged Port {port}'
        else:
            return SeverityLevel.MEDIUM, f'Port {port}'
    
    def _is_unrestricted_outbound(self, rule: Dict[str, Any]) -> bool:
        """
        Check if an outbound rule is completely unrestricted
        
        Args:
            rule: Outbound rule dictionary
            
        Returns:
            True if rule allows all traffic to 0.0.0.0/0
        """
        ip_ranges = rule.get('IpRanges', [])
        has_open_ipv4 = any(ip.get('CidrIp') == '0.0.0.0/0' for ip in ip_ranges)
        
        if not has_open_ipv4:
            return False
        
        # Check if it's all protocols
        ip_protocol = rule.get('IpProtocol', '')
        return ip_protocol == '-1'
    
    def _check_instance_exposure(
        self, 
        instances: List[Dict[str, Any]], 
        security_groups: List[Dict[str, Any]]
    ) -> List[FindingCreate]:
        """
        Check EC2 instances for public exposure with insecure security groups
        
        Args:
            instances: List of EC2 instances
            security_groups: List of security groups
            
        Returns:
            List of findings for exposed instances
        """
        findings = []
        
        # Build a map of security group IDs to their risk level
        sg_risk_map = self._build_security_group_risk_map(security_groups)
        
        for instance in instances:
            instance_id = instance.get('InstanceId')
            instance_state = instance.get('State', {}).get('Name', 'unknown')
            public_ip = instance.get('PublicIpAddress')
            instance_name = self._get_instance_name(instance)
            
            if not instance_id or instance_state != 'running':
                continue
            
            # Only check instances with public IPs
            if not public_ip:
                continue
            
            # Check security groups attached to this instance
            instance_sgs = instance.get('SecurityGroups', [])
            critical_sgs = []
            high_sgs = []
            
            for sg in instance_sgs:
                sg_id = sg.get('GroupId')
                if sg_id in sg_risk_map:
                    risk_level = sg_risk_map[sg_id]
                    if risk_level == SeverityLevel.CRITICAL:
                        critical_sgs.append(sg.get('GroupName', sg_id))
                    elif risk_level == SeverityLevel.HIGH:
                        high_sgs.append(sg.get('GroupName', sg_id))
            
            if critical_sgs or high_sgs:
                sg_list = ', '.join(critical_sgs + high_sgs)
                severity = SeverityLevel.CRITICAL if critical_sgs else SeverityLevel.HIGH
                
                findings.append(FindingCreate(
                    title=f"Public EC2 Instance with Insecure Security Groups: {instance_name}",
                    description=(
                        f"EC2 instance '{instance_name}' ({instance_id}) has a public IP address ({public_ip}) "
                        f"and is associated with security groups that allow open access from the internet.\n\n"
                        f"Insecure Security Groups: {sg_list}\n\n"
                        f"This instance is directly exposed to the internet with overly permissive firewall rules, "
                        f"making it vulnerable to attacks. "
                        f"Recommendation: Review and restrict security group rules, or remove public IP if not needed."
                    ),
                    severity=severity,
                    resource_type="EC2",
                    resource_id=instance_id,
                    resource_arn=f"arn:aws:ec2:{self.region}::instance/{instance_id}",
                    region=self.region
                ))
        
        return findings
    
    def _build_security_group_risk_map(self, security_groups: List[Dict[str, Any]]) -> Dict[str, SeverityLevel]:
        """
        Build a map of security group IDs to their highest risk level
        
        Args:
            security_groups: List of security groups
            
        Returns:
            Dictionary mapping security group IDs to risk levels
        """
        risk_map = {}
        
        for sg in security_groups:
            group_id = sg.get('GroupId')
            if not group_id:
                continue
            
            highest_risk = SeverityLevel.INFO
            
            # Check all inbound rules
            for rule in sg.get('IpPermissions', []):
                ip_ranges = rule.get('IpRanges', [])
                has_open_access = any(ip.get('CidrIp') == '0.0.0.0/0' for ip in ip_ranges)
                
                if has_open_access:
                    ip_protocol = rule.get('IpProtocol', '-1')
                    from_port = rule.get('FromPort')
                    
                    if ip_protocol == '-1':
                        highest_risk = SeverityLevel.CRITICAL
                        break
                    elif from_port in self.CRITICAL_PORTS:
                        highest_risk = SeverityLevel.CRITICAL
                        break
                    elif from_port and from_port < 1024:
                        if highest_risk != SeverityLevel.CRITICAL:
                            highest_risk = SeverityLevel.HIGH
            
            risk_map[group_id] = highest_risk
        
        return risk_map
    
    def _get_instance_name(self, instance: Dict[str, Any]) -> str:
        """
        Extract instance name from tags
        
        Args:
            instance: Instance dictionary
            
        Returns:
            Instance name or ID if no name tag exists
        """
        tags = instance.get('Tags', [])
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value', instance.get('InstanceId', 'Unknown'))
        
        return instance.get('InstanceId', 'Unknown')
