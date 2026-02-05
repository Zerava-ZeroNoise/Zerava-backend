"""
Zerava Security Scanner - Configuration Module

This module contains all configuration settings for the Flask application,
scanning parameters, and application constants.
"""

import os
from datetime import timedelta


class Config:
    """Base configuration class for the Zerava scanner application."""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    
    # CORS Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5173').split(',')
    
    # Job Queue Configuration
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', '5'))
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '300'))  # 5 minutes default
    JOB_RESULT_TTL = int(os.environ.get('JOB_RESULT_TTL', '3600'))  # 1 hour
    
    # Scanning Configuration
    SCANNING_ENABLED = os.environ.get('SCANNING_ENABLED', 'True').lower() in ('true', '1', 't')
    
    # HTTP/HTTPS Checker Settings
    HTTP_REQUEST_TIMEOUT = int(os.environ.get('HTTP_REQUEST_TIMEOUT', '10'))
    HTTP_FOLLOW_REDIRECTS = os.environ.get('HTTP_FOLLOW_REDIRECTS', 'True').lower() in ('true', '1', 't')
    HTTP_VERIFY_SSL = os.environ.get('HTTP_VERIFY_SSL', 'True').lower() in ('true', '1', 't')
    
    # SSL/TLS Checker Settings
    SSL_MINIMUM_VERSION = os.environ.get('SSL_MINIMUM_VERSION', 'TLSv1.2')
    SSL_CHECK_CERTIFICATE_EXPIRY = True
    SSL_EXPIRY_WARNING_DAYS = int(os.environ.get('SSL_EXPIRY_WARNING_DAYS', '30'))
    
    # Security Headers to Check
    REQUIRED_SECURITY_HEADERS = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    # Port Scanning Settings
    PORT_SCAN_ENABLED = os.environ.get('PORT_SCAN_ENABLED', 'True').lower() in ('true', '1', 't')
    COMMON_PORTS = [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        53,   # DNS
        80,   # HTTP
        110,  # POP3
        143,  # IMAP
        443,  # HTTPS
        465,  # SMTPS
        587,  # SMTP Submission
        993,  # IMAPS
        995,  # POP3S
        3306, # MySQL
        3389, # RDP
        5432, # PostgreSQL
        6379, # Redis
        8080, # HTTP Alt
        8443, # HTTPS Alt
        27017 # MongoDB
    ]
    PORT_SCAN_TIMEOUT = float(os.environ.get('PORT_SCAN_TIMEOUT', '1.0'))
    
    # OWASP Top 10 Checks
    OWASP_CHECKS_ENABLED = os.environ.get('OWASP_CHECKS_ENABLED', 'True').lower() in ('true', '1', 't')
    OWASP_SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1' = '1",
        "' OR 1=1--",
        "admin' --",
        "' UNION SELECT NULL--"
    ]
    OWASP_XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>"
    ]
    
    # Scoring Configuration
    SCORE_WEIGHTS = {
        'critical': 40,
        'high': 20,
        'medium': 10,
        'low': 5
    }
    BASE_SCORE = 100
    MINIMUM_SCORE = 0
    MAXIMUM_SCORE = 100
    
    # Scan Type Configurations
    SCAN_TYPES = {
        'full': {
            'name': 'Full Scan',
            'description': 'Comprehensive security analysis including all checks',
            'checks': ['https', 'ssl_tls', 'headers', 'ports', 'owasp'],
            'estimated_time': 180  # seconds
        },
        'quick': {
            'name': 'Quick Scan',
            'description': 'Fast scan focusing on common vulnerabilities',
            'checks': ['https', 'headers'],
            'estimated_time': 30
        },
        'api': {
            'name': 'API Scan',
            'description': 'Specialized scan for API endpoints and authentication',
            'checks': ['https', 'ssl_tls', 'headers', 'owasp'],
            'estimated_time': 90
        },
        'headers': {
            'name': 'Headers Only',
            'description': 'Quick check of security headers and configuration',
            'checks': ['headers'],
            'estimated_time': 10
        }
    }
    
    # Finding Categories
    FINDING_CATEGORIES = [
        'Configuration',
        'Encryption',
        'Access Control',
        'Input Validation',
        'Authentication',
        'Session Management',
        'Data Exposure',
        'Network Security',
        'Injection',
        'Cross-Site Scripting'
    ]
    
    # Severity Levels
    SEVERITY_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Info']
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'True').lower() in ('true', '1', 't')
    RATE_LIMIT_PER_HOUR = int(os.environ.get('RATE_LIMIT_PER_HOUR', '10'))
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # User Agent for HTTP Requests
    USER_AGENT = 'Zerava-Security-Scanner/1.0 (+https://zerava.io)'
    
    # Storage Settings (for future database integration)
    DATABASE_URL = os.environ.get('DATABASE_URL', None)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Redis Configuration (if using for job queue)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    USE_REDIS_QUEUE = os.environ.get('USE_REDIS_QUEUE', 'False').lower() in ('true', '1', 't')


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    SCANNING_ENABLED = True


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    # Override with more restrictive settings for production
    HTTP_VERIFY_SSL = True
    RATE_LIMIT_ENABLED = True


class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    SCANNING_ENABLED = False  # Disable actual scanning in tests
    HTTP_REQUEST_TIMEOUT = 5


# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}