from typing import Any, Dict, List, Optional
import json
from datetime import datetime, timedelta
import hashlib


def calculate_risk_score(severity: str, confidence: float = 1.0) -> float:
    """
    Calculate risk score based on severity and confidence
    
    Args:
        severity: Severity level (critical, high, medium, low, info)
        confidence: Confidence score (0.0 to 1.0)
        
    Returns:
        Risk score (0.0 to 100.0)
    """
    severity_weights = {
        'critical': 100.0,
        'high': 75.0,
        'medium': 50.0,
        'low': 25.0,
        'info': 10.0
    }
    
    base_score = severity_weights.get(severity.lower(), 50.0)
    return round(base_score * confidence, 2)


def is_public_cidr(cidr: str) -> bool:
    """
    Check if CIDR block allows public access
    
    Args:
        cidr: CIDR block (e.g., '0.0.0.0/0')
        
    Returns:
        True if public access, False otherwise
    """
    public_cidrs = ['0.0.0.0/0', '::/0']
    return cidr in public_cidrs


def format_arn(resource_type: str, resource_id: str, region: str = "us-east-1", account_id: str = "123456789012") -> str:
    """
    Format AWS ARN
    
    Args:
        resource_type: AWS resource type (s3, ec2, iam, etc.)
        resource_id: Resource identifier
        region: AWS region
        account_id: AWS account ID
        
    Returns:
        Formatted ARN
    """
    if resource_type == 's3':
        return f"arn:aws:s3:::{resource_id}"
    elif resource_type == 'iam':
        return f"arn:aws:iam::{account_id}:{resource_id}"
    elif resource_type == 'ec2':
        return f"arn:aws:ec2:{region}:{account_id}:instance/{resource_id}"
    else:
        return f"arn:aws:{resource_type}:{region}:{account_id}:{resource_id}"


def extract_event_metadata(cloudtrail_event: str) -> Dict[str, Any]:
    """
    Extract metadata from CloudTrail event JSON
    
    Args:
        cloudtrail_event: CloudTrail event JSON string
        
    Returns:
        Dictionary with extracted metadata
    """
    try:
        event = json.loads(cloudtrail_event)
        
        return {
            'event_name': event.get('eventName'),
            'event_source': event.get('eventSource'),
            'event_time': event.get('eventTime'),
            'user_identity': event.get('userIdentity', {}).get('userName'),
            'source_ip': event.get('sourceIPAddress'),
            'user_agent': event.get('userAgent'),
            'aws_region': event.get('awsRegion'),
            'error_code': event.get('errorCode'),
            'error_message': event.get('errorMessage')
        }
    except json.JSONDecodeError:
        return {}


def is_suspicious_ip(ip_address: str, known_ips: List[str] = None) -> bool:
    """
    Check if IP address is suspicious (simple check)
    
    Args:
        ip_address: IP address to check
        known_ips: List of known safe IPs
        
    Returns:
        True if suspicious, False otherwise
    """
    if known_ips and ip_address in known_ips:
        return False
    
    # Simple checks for common suspicious patterns
    # In production, integrate with threat intelligence feeds
    suspicious_patterns = [
        '0.0.0.0',
        '127.0.0.1'
    ]
    
    return any(pattern in ip_address for pattern in suspicious_patterns)


def get_country_from_ip(ip_address: str) -> str:
    """
    Get country from IP address (placeholder)
    
    In production, integrate with GeoIP service
    
    Args:
        ip_address: IP address
        
    Returns:
        Country name or 'Unknown'
    """
    # Placeholder - in production use GeoIP2 or similar service
    if ip_address.startswith('203.'):
        return 'Australia'
    elif ip_address.startswith('198.'):
        return 'United States'
    elif ip_address.startswith('54.'):
        return 'United States'
    else:
        return 'Unknown'


def generate_finding_id(resource_id: str, finding_type: str) -> str:
    """
    Generate unique finding ID
    
    Args:
        resource_id: AWS resource ID
        finding_type: Type of finding
        
    Returns:
        Unique finding ID
    """
    data = f"{resource_id}:{finding_type}:{datetime.utcnow().isoformat()}"
    return hashlib.md5(data.encode()).hexdigest()[:16]


def is_recent_event(event_time: datetime, hours: int = 24) -> bool:
    """
    Check if event occurred within specified hours
    
    Args:
        event_time: Event timestamp
        hours: Number of hours to check
        
    Returns:
        True if event is recent, False otherwise
    """
    if not event_time:
        return False
    
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    return event_time >= cutoff_time


def truncate_text(text: str, max_length: int = 200) -> str:
    """
    Truncate text to specified length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        
    Returns:
        Truncated text with ellipsis if needed
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - 3] + "..."


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes to human-readable size
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., '1.5 GB')
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def safe_get(dictionary: Dict, *keys: str, default: Any = None) -> Any:
    """
    Safely get nested dictionary value
    
    Args:
        dictionary: Dictionary to query
        *keys: Keys to traverse
        default: Default value if key not found
        
    Returns:
        Value or default
    """
    value = dictionary
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
            if value is None:
                return default
        else:
            return default
    return value


def batch_list(items: List[Any], batch_size: int = 100) -> List[List[Any]]:
    """
    Split list into batches
    
    Args:
        items: List to batch
        batch_size: Size of each batch
        
    Returns:
        List of batched lists
    """
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]


def merge_dicts(*dicts: Dict) -> Dict:
    """
    Merge multiple dictionaries
    
    Args:
        *dicts: Dictionaries to merge
        
    Returns:
        Merged dictionary
    """
    result = {}
    for d in dicts:
        result.update(d)
    return result
