"""
Zerava Security Scanner - Open Ports Checker

This module scans for open ports on the target host to identify
potentially exposed services.
"""

import logging
import socket
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.models.finding import Finding

logger = logging.getLogger(__name__)


class OpenPortsChecker:
    """
    Checker for open ports on target hosts.
    
    Scans common ports to identify exposed services that may present
    security risks if not properly secured.
    """
    
    # Common port information
    PORT_INFO = {
        21: {'name': 'FTP', 'risk': 'High', 'description': 'File Transfer Protocol (unencrypted)'},
        22: {'name': 'SSH', 'risk': 'Medium', 'description': 'Secure Shell'},
        23: {'name': 'Telnet', 'risk': 'Critical', 'description': 'Telnet (unencrypted remote access)'},
        25: {'name': 'SMTP', 'risk': 'Medium', 'description': 'Simple Mail Transfer Protocol'},
        53: {'name': 'DNS', 'risk': 'Low', 'description': 'Domain Name System'},
        80: {'name': 'HTTP', 'risk': 'Medium', 'description': 'Hypertext Transfer Protocol'},
        110: {'name': 'POP3', 'risk': 'High', 'description': 'Post Office Protocol (unencrypted)'},
        143: {'name': 'IMAP', 'risk': 'High', 'description': 'Internet Message Access Protocol (unencrypted)'},
        443: {'name': 'HTTPS', 'risk': 'Low', 'description': 'HTTP over SSL/TLS'},
        465: {'name': 'SMTPS', 'risk': 'Low', 'description': 'SMTP over SSL'},
        587: {'name': 'SMTP', 'risk': 'Low', 'description': 'SMTP Submission'},
        993: {'name': 'IMAPS', 'risk': 'Low', 'description': 'IMAP over SSL'},
        995: {'name': 'POP3S', 'risk': 'Low', 'description': 'POP3 over SSL'},
        3306: {'name': 'MySQL', 'risk': 'Critical', 'description': 'MySQL Database'},
        3389: {'name': 'RDP', 'risk': 'High', 'description': 'Remote Desktop Protocol'},
        5432: {'name': 'PostgreSQL', 'risk': 'Critical', 'description': 'PostgreSQL Database'},
        6379: {'name': 'Redis', 'risk': 'Critical', 'description': 'Redis Database'},
        8080: {'name': 'HTTP-Alt', 'risk': 'Medium', 'description': 'HTTP Alternate Port'},
        8443: {'name': 'HTTPS-Alt', 'risk': 'Low', 'description': 'HTTPS Alternate Port'},
        27017: {'name': 'MongoDB', 'risk': 'Critical', 'description': 'MongoDB Database'}
    }
    
    def __init__(self, ports: List[int] = None, timeout: float = 1.0, 
                 max_workers: int = 50):
        """
        Initialize the open ports checker.
        
        Args:
            ports: List of ports to scan (None for default common ports)
            timeout: Connection timeout in seconds
            max_workers: Maximum number of concurrent threads
        """
        self.ports = ports or [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 
            993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017
        ]
        self.timeout = timeout
        self.max_workers = max_workers
    
    def check(self, target_url: str) -> Tuple[List[Finding], Dict[str, any]]:
        """
        Perform port scanning on the target.
        
        Args:
            target_url: URL to check
        
        Returns:
            Tuple of (list of findings, metadata dict)
        """
        findings = []
        metadata = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'total_ports_scanned': len(self.ports),
            'scan_duration': 0
        }
        
        logger.info(f"Starting port scan for {target_url}")
        
        # Extract hostname from URL
        parsed = urlparse(target_url)
        hostname = parsed.netloc or parsed.path
        
        # Remove port if specified in URL
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Resolve hostname to IP
        try:
            ip_address = socket.gethostbyname(hostname)
            metadata['ip_address'] = ip_address
            logger.info(f"Resolved {hostname} to {ip_address}")
        except socket.gaierror as e:
            logger.error(f"Could not resolve hostname {hostname}: {e}")
            findings.append(Finding(
                title='Hostname Resolution Failed',
                severity='Info',
                category='Network Security',
                description=f'Could not resolve hostname {hostname} to IP address: {str(e)}',
                impact='Port scanning could not be completed.',
                recommendation='Verify the hostname is correct and DNS is properly configured.',
                fix_steps=[
                    'Verify the hostname is correct',
                    'Check DNS configuration',
                    'Ensure the domain has valid DNS records'
                ],
                affected_url=target_url
            ))
            return findings, metadata
        
        # Scan ports concurrently
        import time
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self._scan_port, hostname, port): port 
                for port in self.ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, state = future.result()
                    
                    if is_open:
                        metadata['open_ports'].append(port)
                        
                        # Create finding for open port
                        port_finding = self._create_port_finding(
                            hostname, port, target_url
                        )
                        if port_finding:
                            findings.append(port_finding)
                    
                    elif state == 'filtered':
                        metadata['filtered_ports'].append(port)
                    else:
                        metadata['closed_ports'].append(port)
                
                except Exception as e:
                    logger.error(f"Error scanning port {port}: {e}")
        
        metadata['scan_duration'] = time.time() - start_time
        
        # Sort open ports for consistent output
        metadata['open_ports'].sort()
        
        logger.info(f"Port scan complete for {target_url}. "
                   f"Found {len(metadata['open_ports'])} open ports out of {len(self.ports)} scanned.")
        
        return findings, metadata
    
    def _scan_port(self, hostname: str, port: int) -> Tuple[bool, str]:
        """
        Scan a single port.
        
        Args:
            hostname: Target hostname
            port: Port number to scan
        
        Returns:
            Tuple of (is_open, state) where state is 'open', 'closed', or 'filtered'
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result == 0:
                return True, 'open'
            else:
                return False, 'closed'
        
        except socket.timeout:
            sock.close()
            return False, 'filtered'
        
        except socket.error:
            sock.close()
            return False, 'filtered'
        
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            sock.close()
            return False, 'filtered'
    
    def _create_port_finding(self, hostname: str, port: int, 
                            url: str) -> Optional[Finding]:
        """
        Create a finding for an open port.
        
        Args:
            hostname: Target hostname
            port: Open port number
            url: Original URL
        
        Returns:
            Finding object or None
        """
        port_info = self.PORT_INFO.get(port, {
            'name': f'Port {port}',
            'risk': 'Medium',
            'description': 'Unknown service'
        })
        
        service_name = port_info['name']
        risk_level = port_info['risk']
        description = port_info['description']
        
        # Map risk level to severity
        severity_map = {
            'Critical': 'Critical',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low'
        }
        severity = severity_map.get(risk_level, 'Medium')
        
        # Only create findings for potentially risky open ports
        # Don't report standard web ports (80, 443, 8080, 8443) unless they're the only service
        if port in [80, 443, 8080, 8443]:
            return None
        
        # Create specific recommendations based on service
        if port == 23:  # Telnet
            return Finding(
                title=f'Insecure Telnet Service Exposed (Port {port})',
                severity='Critical',
                category='Network Security',
                description=f'Telnet service is exposed on port {port}. Telnet transmits data in plaintext including passwords.',
                impact='Attackers can intercept all Telnet traffic including credentials. This is a critical security vulnerability.',
                recommendation='Disable Telnet immediately and use SSH (port 22) instead for secure remote access.',
                fix_steps=[
                    'Disable the Telnet service on the server',
                    'Install and configure SSH for secure remote access',
                    'Update firewall rules to block port 23',
                    'Ensure SSH uses key-based authentication',
                    'Verify Telnet is no longer accessible'
                ],
                affected_url=f"{hostname}:{port}",
                evidence={'port': port, 'service': service_name},
                cwe_id='CWE-319'
            )
        
        elif port in [21, 110, 143]:  # Unencrypted protocols
            secure_alternative = {
                21: 'SFTP or FTPS',
                110: 'POP3S (port 995)',
                143: 'IMAPS (port 993)'
            }
            
            return Finding(
                title=f'Unencrypted {service_name} Service Exposed (Port {port})',
                severity='High',
                category='Network Security',
                description=f'{service_name} service is exposed on port {port} without encryption.',
                impact=f'Data transmitted via {service_name} can be intercepted, including credentials and sensitive information.',
                recommendation=f'Use {secure_alternative[port]} instead of unencrypted {service_name}.',
                fix_steps=[
                    f'Configure the service to use encrypted protocol ({secure_alternative[port]})',
                    f'Disable unencrypted {service_name} on port {port}',
                    'Update client configurations to use secure protocols',
                    'Test encrypted connections',
                    'Update firewall rules to block unencrypted port'
                ],
                affected_url=f"{hostname}:{port}",
                evidence={'port': port, 'service': service_name},
                cwe_id='CWE-319'
            )
        
        elif port in [3306, 5432, 6379, 27017]:  # Databases
            db_name = {
                3306: 'MySQL',
                5432: 'PostgreSQL',
                6379: 'Redis',
                27017: 'MongoDB'
            }
            
            return Finding(
                title=f'{db_name[port]} Database Port Exposed (Port {port})',
                severity='Critical',
                category='Network Security',
                description=f'{db_name[port]} database port {port} is accessible from the network.',
                impact='Direct database access from the internet is extremely dangerous. Attackers may attempt to '
                       'exploit database vulnerabilities, brute force credentials, or access sensitive data.',
                recommendation=f'Restrict {db_name[port]} access to trusted networks only using firewall rules.',
                fix_steps=[
                    f'Configure firewall to block external access to port {port}',
                    'Allow database access only from application servers',
                    'Use VPN or SSH tunneling for remote database administration',
                    'Ensure database authentication is properly configured',
                    'Review database access logs for suspicious activity',
                    'Consider using a bastion host for administrative access'
                ],
                affected_url=f"{hostname}:{port}",
                evidence={'port': port, 'service': service_name},
                cwe_id='CWE-749'
            )
        
        elif port == 3389:  # RDP
            return Finding(
                title='Remote Desktop Protocol Exposed (Port 3389)',
                severity='High',
                category='Network Security',
                description='Remote Desktop Protocol (RDP) is accessible from the network.',
                impact='RDP is frequently targeted by attackers for brute force attacks and exploitation. '
                       'Exposed RDP can lead to system compromise.',
                recommendation='Restrict RDP access using firewall rules or VPN.',
                fix_steps=[
                    'Configure firewall to block external access to port 3389',
                    'Allow RDP only through VPN connection',
                    'Enable Network Level Authentication (NLA)',
                    'Use strong passwords or certificate-based authentication',
                    'Enable account lockout policies',
                    'Monitor RDP logs for failed login attempts',
                    'Consider using Remote Desktop Gateway'
                ],
                affected_url=f"{hostname}:{port}",
                evidence={'port': port, 'service': service_name},
                cwe_id='CWE-306'
            )
        
        elif port == 22:  # SSH
            return Finding(
                title='SSH Service Exposed (Port 22)',
                severity='Medium',
                category='Network Security',
                description='SSH service is accessible from the network.',
                impact='While SSH is encrypted, exposed SSH services are targeted for brute force attacks.',
                recommendation='Secure SSH with strong authentication and consider restricting access.',
                fix_steps=[
                    'Disable password authentication and use key-based authentication only',
                    'Change SSH to a non-standard port if possible',
                    'Use fail2ban or similar to prevent brute force attacks',
                    'Restrict SSH access to specific IP addresses if possible',
                    'Disable root login via SSH',
                    'Keep SSH server software updated',
                    'Review SSH logs regularly'
                ],
                affected_url=f"{hostname}:{port}",
                evidence={'port': port, 'service': service_name},
                cwe_id='CWE-307'
            )
        
        else:
            # Generic finding for other open ports
            return Finding(
                title=f'{service_name} Service Exposed (Port {port})',
                severity=severity,
                category='Network Security',
                description=f'{service_name} ({description}) is accessible on port {port}.',
                impact=f'Exposed services increase the attack surface and may be vulnerable to exploitation.',
                recommendation=f'Review if port {port} needs to be publicly accessible. If not, restrict access using firewall rules.',
                fix_steps=[
                    f'Determine if {service_name} on port {port} needs to be publicly accessible',
                    'If not needed publicly, configure firewall to block external access',
                    'If needed, ensure the service is properly secured and updated',
                    'Implement strong authentication',
                    'Monitor access logs for suspicious activity'
                ],
                affected_url=f"{hostname}:{port}",
                evidence={'port': port, 'service': service_name}
            )