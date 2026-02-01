"""
Zerava Security Scanner - HTTPS Checker

This module checks if a target website properly supports HTTPS and enforces
secure connections through redirects.
"""

import logging
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urlunparse
import requests
from requests.exceptions import RequestException, SSLError, Timeout, ConnectionError

from app.models.finding import Finding

logger = logging.getLogger(__name__)


class HTTPSChecker:
    """
    Checker for HTTPS availability and redirect behavior.
    
    Validates that websites:
    - Support HTTPS connections
    - Redirect HTTP to HTTPS
    - Have valid SSL/TLS certificates
    """
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        """
        Initialize the HTTPS checker.
        
        Args:
            timeout: Request timeout in seconds
            user_agent: User agent string for requests
        """
        self.timeout = timeout
        self.user_agent = user_agent or 'Zerava-Security-Scanner/1.0'
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
    
    def check(self, target_url: str) -> Tuple[List[Finding], Dict[str, any]]:
        """
        Perform HTTPS checks on the target URL.
        
        Args:
            target_url: URL to check
        
        Returns:
            Tuple of (list of findings, metadata dict)
        """
        findings = []
        metadata = {
            'https_available': False,
            'http_redirects_to_https': False,
            'certificate_valid': False,
            'final_url': None
        }
        
        logger.info(f"Starting HTTPS check for {target_url}")
        
        # Parse and normalize URL
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path
        
        # Remove any path/query/fragment for base checks
        if not parsed.netloc:
            domain = domain.split('/')[0]
        
        # Check HTTPS availability
        https_url = f"https://{domain}"
        https_available, https_error = self._check_https_available(https_url)
        metadata['https_available'] = https_available
        
        if not https_available:
            findings.append(Finding(
                title='HTTPS Not Available',
                severity='Critical',
                category='Encryption',
                description=f'The website does not support HTTPS connections. Error: {https_error}',
                impact='All data transmitted between users and the server is sent in plain text, '
                       'allowing attackers to intercept sensitive information including passwords, '
                       'session tokens, and personal data.',
                recommendation='Enable HTTPS by obtaining and installing an SSL/TLS certificate.',
                fix_steps=[
                    'Obtain an SSL/TLS certificate from a trusted Certificate Authority (or use Let\'s Encrypt)',
                    'Install the certificate on your web server',
                    'Configure your web server to accept HTTPS connections on port 443',
                    'Test HTTPS connectivity',
                    'Once working, redirect all HTTP traffic to HTTPS'
                ],
                affected_url=https_url,
                cwe_id='CWE-319'
            ))
        else:
            metadata['certificate_valid'] = True
            
            # Check if HTTP redirects to HTTPS
            http_url = f"http://{domain}"
            redirects_to_https, redirect_info = self._check_http_redirect(http_url, https_url)
            metadata['http_redirects_to_https'] = redirects_to_https
            metadata['final_url'] = redirect_info.get('final_url')
            
            if not redirects_to_https:
                findings.append(Finding(
                    title='HTTP Does Not Redirect to HTTPS',
                    severity='High',
                    category='Configuration',
                    description='The website is accessible over HTTP and does not redirect to HTTPS.',
                    impact='Users may access the site over insecure HTTP connections, exposing their '
                           'data to interception. Search engines may index HTTP versions of pages.',
                    recommendation='Configure your web server to redirect all HTTP requests to HTTPS.',
                    fix_steps=[
                        'Configure a 301 (permanent) redirect from HTTP to HTTPS',
                        'For Apache: Use mod_rewrite or Redirect directive in .htaccess or VirtualHost',
                        'For Nginx: Use return 301 https://$host$request_uri; in server block',
                        'Test by visiting http:// URL and verify it redirects to https://',
                        'Consider implementing HSTS header for additional protection'
                    ],
                    affected_url=http_url,
                    evidence={
                        'http_url': http_url,
                        'https_url': https_url,
                        'redirect_chain': redirect_info.get('redirect_chain', [])
                    },
                    cwe_id='CWE-319'
                ))
            else:
                # Check redirect method (should be 301 or 308 for permanent)
                redirect_status = redirect_info.get('redirect_status')
                if redirect_status not in [301, 308]:
                    findings.append(Finding(
                        title='HTTP Redirect Uses Temporary Status Code',
                        severity='Low',
                        category='Configuration',
                        description=f'HTTP to HTTPS redirect uses status code {redirect_status} instead of 301 or 308.',
                        impact='Search engines may not properly understand that HTTPS is the preferred version. '
                               'Users may not have the redirect cached.',
                        recommendation='Use HTTP status code 301 (Moved Permanently) or 308 (Permanent Redirect) for HTTP to HTTPS redirects.',
                        fix_steps=[
                            'Update web server configuration to use 301 or 308 status code',
                            'For Apache: Use "Redirect permanent" or "Redirect 301"',
                            'For Nginx: Use "return 301" instead of "return 302"',
                            'Test and verify the status code using browser developer tools or curl'
                        ],
                        affected_url=http_url,
                        evidence={'redirect_status': redirect_status}
                    ))
        
        logger.info(f"HTTPS check complete for {target_url}. Found {len(findings)} issues.")
        return findings, metadata
    
    def _check_https_available(self, https_url: str) -> Tuple[bool, Optional[str]]:
        """
        Check if HTTPS is available and certificate is valid.
        
        Args:
            https_url: HTTPS URL to check
        
        Returns:
            Tuple of (is_available, error_message)
        """
        try:
            response = self.session.get(
                https_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True  # Verify SSL certificate
            )
            
            # Any 2xx, 3xx, or even 4xx response means HTTPS is working
            if response.status_code < 500:
                return True, None
            else:
                return False, f"Server error: {response.status_code}"
                
        except SSLError as e:
            logger.warning(f"SSL error for {https_url}: {e}")
            return False, f"SSL/TLS certificate error: {str(e)}"
        
        except ConnectionError as e:
            logger.warning(f"Connection error for {https_url}: {e}")
            return False, f"Connection failed: {str(e)}"
        
        except Timeout:
            logger.warning(f"Timeout for {https_url}")
            return False, "Connection timeout"
        
        except RequestException as e:
            logger.warning(f"Request error for {https_url}: {e}")
            return False, f"Request failed: {str(e)}"
    
    def _check_http_redirect(self, http_url: str, expected_https_url: str) -> Tuple[bool, Dict]:
        """
        Check if HTTP URL redirects to HTTPS.
        
        Args:
            http_url: HTTP URL to check
            expected_https_url: Expected HTTPS URL
        
        Returns:
            Tuple of (redirects_to_https, redirect_info_dict)
        """
        redirect_info = {
            'redirect_chain': [],
            'final_url': None,
            'redirect_status': None
        }
        
        try:
            # Don't follow redirects automatically so we can inspect them
            response = self.session.get(
                http_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False  # Don't verify cert for HTTP request
            )
            
            # Check if it's a redirect status code
            if response.status_code in [301, 302, 303, 307, 308]:
                redirect_info['redirect_status'] = response.status_code
                location = response.headers.get('Location', '')
                redirect_info['redirect_chain'].append({
                    'from': http_url,
                    'to': location,
                    'status': response.status_code
                })
                
                # Check if redirect is to HTTPS
                if location.startswith('https://'):
                    redirect_info['final_url'] = location
                    return True, redirect_info
                
                # If relative redirect, make it absolute
                if location.startswith('/'):
                    parsed = urlparse(http_url)
                    location = f"https://{parsed.netloc}{location}"
                    redirect_info['final_url'] = location
                    return True, redirect_info
            
            # If no redirect, final URL is the HTTP URL
            redirect_info['final_url'] = http_url
            return False, redirect_info
            
        except RequestException as e:
            logger.warning(f"Error checking HTTP redirect for {http_url}: {e}")
            return False, redirect_info
    
    def close(self):
        """Close the session."""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()