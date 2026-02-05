"""
Zerava Security Scanner - Status Routes

This module defines API routes for health checks and system status.
"""

import logging
from flask import Blueprint, jsonify
from datetime import datetime

from app.utils.job_queue import get_job_queue
from config import Config

logger = logging.getLogger(__name__)

status_bp = Blueprint('status', __name__)


@status_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.
    
    Returns:
        {
            "status": "healthy",
            "timestamp": "2026-02-01T12:00:00Z",
            "version": "1.0.0"
        }
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'version': '1.0.0',
        'service': 'zerava-scanner'
    }), 200


@status_bp.route('/queue', methods=['GET'])
def queue_status():
    """
    Get job queue status and statistics.
    
    Returns:
        {
            "queue_stats": {
                "total_jobs": 10,
                "pending": 2,
                "running": 3,
                "completed": 5,
                "failed": 0,
                "cancelled": 0,
                "max_workers": 5
            },
            "timestamp": "2026-02-01T12:00:00Z"
        }
    """
    try:
        job_queue = get_job_queue()
        stats = job_queue.get_stats()
        
        return jsonify({
            'queue_stats': stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting queue status: {e}")
        return jsonify({
            'error': 'Unable to get queue status',
            'details': str(e)
        }), 500


@status_bp.route('/config', methods=['GET'])
def get_configuration():
    """
    Get scanner configuration (non-sensitive settings).
    
    Returns:
        {
            "scanning_enabled": true,
            "max_concurrent_scans": 5,
            "scan_timeout": 300,
            "scan_types": {...},
            "checks_available": [...]
        }
    """
    return jsonify({
        'scanning_enabled': Config.SCANNING_ENABLED,
        'max_concurrent_scans': Config.MAX_CONCURRENT_SCANS,
        'scan_timeout': Config.SCAN_TIMEOUT,
        'scan_types': Config.SCAN_TYPES,
        'checks_available': {
            'https_check': True,
            'ssl_tls_check': True,
            'security_headers': True,
            'port_scan': Config.PORT_SCAN_ENABLED,
            'owasp_checks': Config.OWASP_CHECKS_ENABLED
        },
        'rate_limiting': {
            'enabled': Config.RATE_LIMIT_ENABLED,
            'limit_per_hour': Config.RATE_LIMIT_PER_HOUR
        }
    }), 200


@status_bp.route('/info', methods=['GET'])
def get_info():
    """
    Get general information about the scanner.
    
    Returns:
        {
            "name": "Zerava Security Scanner",
            "version": "1.0.0",
            "description": "...",
            "features": [...]
        }
    """
    return jsonify({
        'name': 'Zerava Security Scanner',
        'version': '1.0.0',
        'description': 'Comprehensive security scanning service for web applications',
        'features': [
            'HTTPS/TLS configuration checking',
            'SSL certificate validation',
            'Security headers analysis',
            'Port scanning',
            'OWASP Top 10 vulnerability checks',
            'Automated security scoring',
            'Detailed remediation guidance'
        ],
        'supported_scan_types': list(Config.SCAN_TYPES.keys()),
        'max_concurrent_scans': Config.MAX_CONCURRENT_SCANS,
        'documentation': 'https://zerava.io/docs'
    }), 200


@status_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """
    Get system metrics and statistics.
    
    Returns:
        {
            "uptime": 3600,
            "total_scans": 100,
            "scans_today": 25,
            "average_scan_time": 45.2,
            "queue_stats": {...}
        }
    """
    try:
        job_queue = get_job_queue()
        queue_stats = job_queue.get_stats()
        
        # Get all jobs to calculate metrics
        all_jobs = job_queue.list_jobs()
        
        # Calculate average scan time for completed scans
        completed_jobs = [j for j in all_jobs if j['status'] == 'completed']
        avg_scan_time = 0
        
        if completed_jobs:
            total_time = 0
            count = 0
            
            for job in completed_jobs:
                started = job.get('started_at')
                completed = job.get('completed_at')
                
                if started and completed:
                    try:
                        start_dt = datetime.fromisoformat(started.replace('Z', '+00:00'))
                        complete_dt = datetime.fromisoformat(completed.replace('Z', '+00:00'))
                        duration = (complete_dt - start_dt).total_seconds()
                        total_time += duration
                        count += 1
                    except:
                        pass
            
            if count > 0:
                avg_scan_time = total_time / count
        
        # Count scans today
        today = datetime.utcnow().date()
        scans_today = 0
        
        for job in all_jobs:
            created = job.get('created_at')
            if created:
                try:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    if created_dt.date() == today:
                        scans_today += 1
                except:
                    pass
        
        return jsonify({
            'total_scans': len(all_jobs),
            'scans_today': scans_today,
            'average_scan_time_seconds': round(avg_scan_time, 2),
            'queue_stats': queue_stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return jsonify({
            'error': 'Unable to get metrics',
            'details': str(e)
        }), 500


@status_bp.route('/ready', methods=['GET'])
def readiness_check():
    """
    Readiness check for Kubernetes/container orchestration.
    
    Returns 200 if service is ready to accept requests.
    Returns 503 if service is not ready.
    """
    try:
        # Check if job queue is initialized and running
        job_queue = get_job_queue()
        stats = job_queue.get_stats()
        
        # Check if scanning is enabled
        if not Config.SCANNING_ENABLED:
            return jsonify({
                'status': 'not_ready',
                'reason': 'Scanning is disabled'
            }), 503
        
        # Check if queue has capacity
        if stats['running'] >= stats['max_workers']:
            return jsonify({
                'status': 'degraded',
                'reason': 'Queue at maximum capacity',
                'queue_stats': stats
            }), 200  # Still ready, just degraded
        
        return jsonify({
            'status': 'ready',
            'queue_stats': stats
        }), 200
    
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return jsonify({
            'status': 'not_ready',
            'reason': str(e)
        }), 503


@status_bp.route('/live', methods=['GET'])
def liveness_check():
    """
    Liveness check for Kubernetes/container orchestration.
    
    Returns 200 if service is alive (even if degraded).
    Returns 500 if service has critical issues.
    """
    try:
        # Basic check - if we can respond, we're alive
        return jsonify({
            'status': 'alive',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 200
    
    except Exception as e:
        logger.error(f"Liveness check failed: {e}")
        return jsonify({
            'status': 'dead',
            'reason': str(e)
        }), 500


@status_bp.route('/version', methods=['GET'])
def get_version():
    """
    Get application version information.
    
    Returns:
        {
            "version": "1.0.0",
            "build_date": "2026-02-01",
            "api_version": "v1"
        }
    """
    return jsonify({
        'version': '1.0.0',
        'build_date': '2026-02-01',
        'api_version': 'v1',
        'python_version': '3.x',
        'flask_version': 'latest'
    }), 200


@status_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'error': 'Not found',
        'message': 'The requested endpoint does not exist'
    }), 404


@status_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500