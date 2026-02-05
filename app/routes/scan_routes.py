"""
Zerava Security Scanner - Scan Routes

This module defines the API routes for creating and managing security scans.
"""

import logging
from flask import Blueprint, request, jsonify
from typing import Dict, Any

from app.models.scan import Scan
from app.models.report import Report
from app.models.finding import Finding
from app.scanners.https_checker import HTTPSChecker
from app.scanners.ssl_tls_checker import SSLTLSChecker
from app.scanners.security_headers import SecurityHeadersChecker
from app.scanners.open_ports import OpenPortsChecker
from app.scanners.owasp_top10 import OWASPTop10Checker
from app.scoring.score_calculator import ScoreCalculator
from app.utils.job_queue import get_job_queue
from config import Config

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scans', __name__)


@scan_bp.route('', methods=['POST'])
def create_scan():
    """
    Create a new security scan.
    
    Request body:
        {
            "target": "https://example.com",
            "scan_type": "full|quick|api|headers"
        }
    
    Returns:
        {
            "scan_id": "scan-abc123",
            "status": "pending",
            "message": "Scan started"
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Request body is required'}), 400
        
        target = data.get('target')
        scan_type = data.get('scan_type', 'full')
        
        # Validate input
        if not target:
            return jsonify({'error': 'Target URL is required'}), 400
        
        if scan_type not in ['full', 'quick', 'api', 'headers']:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        # Create scan object
        scan = Scan(target=target, scan_type=scan_type)
        
        # Submit scan job to queue
        job_queue = get_job_queue()
        job_queue.submit_job(
            job_id=scan.id,
            func=execute_scan,
            scan=scan
        )
        
        logger.info(f"Scan {scan.id} created for target {target}")
        
        return jsonify({
            'scan_id': scan.id,
            'status': 'pending',
            'message': 'Scan started',
            'scan': scan.to_summary_dict()
        }), 201
    
    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500


@scan_bp.route('/<scan_id>', methods=['GET'])
def get_scan(scan_id: str):
    """
    Get scan status and results.
    
    Returns:
        For pending/running scans:
        {
            "scan_id": "scan-abc123",
            "status": "running",
            "progress": 50
        }
        
        For completed scans:
        {
            "id": "scan-abc123",
            "target": "example.com",
            "status": "completed",
            "score": 78,
            "findings": [...],
            "summary": {...}
        }
    """
    try:
        job_queue = get_job_queue()
        job_status = job_queue.get_job_status(scan_id)
        
        if not job_status:
            return jsonify({'error': 'Scan not found'}), 404
        
        # If scan is still pending or running, return status
        if job_status['status'] in ['pending', 'running']:
            return jsonify({
                'scan_id': scan_id,
                'status': job_status['status'],
                'progress': job_status.get('progress', 0),
                'created_at': job_status.get('created_at'),
                'started_at': job_status.get('started_at')
            }), 200
        
        # If scan failed, return error
        if job_status['status'] == 'failed':
            return jsonify({
                'scan_id': scan_id,
                'status': 'failed',
                'error': job_status.get('error', 'Unknown error'),
                'created_at': job_status.get('created_at')
            }), 200
        
        # If scan completed, return full results
        if job_status['status'] == 'completed':
            result = job_queue.get_job_result(scan_id)
            if result:
                return jsonify(result), 200
            else:
                return jsonify({'error': 'Scan results not available'}), 404
        
        return jsonify({'error': 'Invalid scan status'}), 500
    
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500


@scan_bp.route('', methods=['GET'])
def list_scans():
    """
    List all scans.
    
    Query parameters:
        status: Filter by status (optional)
    
    Returns:
        {
            "scans": [
                {
                    "scan_id": "scan-abc123",
                    "target": "example.com",
                    "status": "completed",
                    "score": 78,
                    ...
                }
            ],
            "total": 5
        }
    """
    try:
        status_filter = request.args.get('status')
        
        job_queue = get_job_queue()
        jobs = job_queue.list_jobs(status=status_filter)
        
        # Convert job data to scan summary format
        scans = []
        for job in jobs:
            scan_summary = {
                'scan_id': job['job_id'],
                'status': job['status'],
                'created_at': job.get('created_at'),
                'started_at': job.get('started_at'),
                'completed_at': job.get('completed_at')
            }
            
            # Add result summary if completed
            if job['status'] == 'completed' and job.get('result'):
                result = job['result']
                scan_summary.update({
                    'target': result.get('target'),
                    'type': result.get('type'),
                    'score': result.get('score'),
                    'findings': {
                        'critical': result.get('summary', {}).get('critical', 0),
                        'high': result.get('summary', {}).get('high', 0),
                        'medium': result.get('summary', {}).get('medium', 0),
                        'low': result.get('summary', {}).get('low', 0)
                    }
                })
            
            scans.append(scan_summary)
        
        return jsonify({
            'scans': scans,
            'total': len(scans)
        }), 200
    
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500


@scan_bp.route('/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id: str):
    """
    Cancel/delete a scan.
    
    Returns:
        {
            "message": "Scan cancelled",
            "scan_id": "scan-abc123"
        }
    """
    try:
        job_queue = get_job_queue()
        
        # Check if job exists
        job_status = job_queue.get_job_status(scan_id)
        if not job_status:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Try to cancel if pending or running
        if job_status['status'] in ['pending', 'running']:
            cancelled = job_queue.cancel_job(scan_id)
            if cancelled:
                return jsonify({
                    'message': 'Scan cancelled',
                    'scan_id': scan_id
                }), 200
            else:
                return jsonify({
                    'message': 'Scan is running and cannot be cancelled',
                    'scan_id': scan_id
                }), 400
        
        return jsonify({
            'message': 'Scan already completed',
            'scan_id': scan_id
        }), 400
    
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500


def execute_scan(scan: Scan) -> Dict[str, Any]:
    """
    Execute a security scan.
    
    This function runs all configured checks based on scan type and
    generates a complete report with findings and score.
    
    Args:
        scan: Scan object to execute
    
    Returns:
        Dictionary with complete scan results
    """
    logger.info(f"Executing scan {scan.id} for {scan.target}")
    
    # Mark scan as started
    scan.start()
    
    # Update progress
    job_queue = get_job_queue()
    job_queue.update_progress(scan.id, 5)
    
    # Create report
    report = Report.from_scan(scan)
    
    # Get scan configuration
    scan_config = Config.SCAN_TYPES.get(scan.scan_type, Config.SCAN_TYPES['full'])
    checks_to_run = scan_config.get('checks', [])
    
    total_checks = len(checks_to_run)
    checks_completed = 0
    
    try:
        # Run HTTPS checker
        if 'https' in checks_to_run:
            logger.info(f"Running HTTPS check for {scan.target}")
            with HTTPSChecker(
                timeout=Config.HTTP_REQUEST_TIMEOUT,
                user_agent=Config.USER_AGENT
            ) as checker:
                findings, metadata = checker.check(scan.target)
                report.add_findings(findings)
                report.add_metadata('https', metadata)
            
            checks_completed += 1
            progress = int((checks_completed / total_checks) * 90) + 5
            job_queue.update_progress(scan.id, progress)
        
        # Run SSL/TLS checker
        if 'ssl_tls' in checks_to_run:
            logger.info(f"Running SSL/TLS check for {scan.target}")
            checker = SSLTLSChecker(
                timeout=Config.HTTP_REQUEST_TIMEOUT,
                expiry_warning_days=Config.SSL_EXPIRY_WARNING_DAYS
            )
            findings, metadata = checker.check(scan.target)
            report.add_findings(findings)
            report.add_metadata('ssl_tls', metadata)
            
            checks_completed += 1
            progress = int((checks_completed / total_checks) * 90) + 5
            job_queue.update_progress(scan.id, progress)
        
        # Run security headers checker
        if 'headers' in checks_to_run:
            logger.info(f"Running security headers check for {scan.target}")
            with SecurityHeadersChecker(
                timeout=Config.HTTP_REQUEST_TIMEOUT,
                user_agent=Config.USER_AGENT,
                required_headers=Config.REQUIRED_SECURITY_HEADERS
            ) as checker:
                findings, metadata = checker.check(scan.target)
                report.add_findings(findings)
                report.add_metadata('security_headers', metadata)
            
            checks_completed += 1
            progress = int((checks_completed / total_checks) * 90) + 5
            job_queue.update_progress(scan.id, progress)
        
        # Run port scanner
        if 'ports' in checks_to_run and Config.PORT_SCAN_ENABLED:
            logger.info(f"Running port scan for {scan.target}")
            checker = OpenPortsChecker(
                ports=Config.COMMON_PORTS,
                timeout=Config.PORT_SCAN_TIMEOUT
            )
            findings, metadata = checker.check(scan.target)
            report.add_findings(findings)
            report.add_metadata('open_ports', metadata)
            
            checks_completed += 1
            progress = int((checks_completed / total_checks) * 90) + 5
            job_queue.update_progress(scan.id, progress)
        
        # Run OWASP Top 10 checker
        if 'owasp' in checks_to_run and Config.OWASP_CHECKS_ENABLED:
            logger.info(f"Running OWASP Top 10 check for {scan.target}")
            with OWASPTop10Checker(
                timeout=Config.HTTP_REQUEST_TIMEOUT,
                user_agent=Config.USER_AGENT
            ) as checker:
                findings, metadata = checker.check(scan.target)
                report.add_findings(findings)
                report.add_metadata('owasp', metadata)
            
            checks_completed += 1
            progress = int((checks_completed / total_checks) * 90) + 5
            job_queue.update_progress(scan.id, progress)
        
        # Calculate security score
        logger.info(f"Calculating security score for {scan.id}")
        calculator = ScoreCalculator(
            base_score=Config.BASE_SCORE,
            weights=Config.SCORE_WEIGHTS
        )
        score, breakdown = calculator.calculate_score(report.findings)
        
        # Update scan with results
        scan.complete(score=score, findings=report.summary)
        report.add_metadata('score_breakdown', breakdown)
        
        # Add recommendations
        recommendations = calculator.generate_recommendations(report.findings, score)
        report.add_metadata('recommendations', recommendations)
        
        # Update progress to 100%
        job_queue.update_progress(scan.id, 100)
        
        logger.info(f"Scan {scan.id} completed successfully with score {score}")
        
        # Return complete report
        return report.to_dict()
    
    except Exception as e:
        logger.error(f"Error executing scan {scan.id}: {e}")
        scan.fail(str(e))
        raise


@scan_bp.route('/types', methods=['GET'])
def get_scan_types():
    """
    Get available scan types and their configurations.
    
    Returns:
        {
            "scan_types": {
                "full": {
                    "name": "Full Scan",
                    "description": "...",
                    "estimated_time": 180
                },
                ...
            }
        }
    """
    return jsonify({
        'scan_types': Config.SCAN_TYPES
    }), 200


@scan_bp.route('/<scan_id>/findings', methods=['GET'])
def get_scan_findings(scan_id: str):
    """
    Get findings for a specific scan.
    
    Query parameters:
        severity: Filter by severity (optional)
        category: Filter by category (optional)
    
    Returns:
        {
            "scan_id": "scan-abc123",
            "findings": [...],
            "total": 25,
            "filtered": 10
        }
    """
    try:
        # Get scan results
        job_queue = get_job_queue()
        job_status = job_queue.get_job_status(scan_id)
        
        if not job_status:
            return jsonify({'error': 'Scan not found'}), 404
        
        if job_status['status'] != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400
        
        result = job_queue.get_job_result(scan_id)
        if not result:
            return jsonify({'error': 'Scan results not available'}), 404
        
        findings = result.get('findings', [])
        
        # Apply filters
        severity_filter = request.args.get('severity')
        category_filter = request.args.get('category')
        
        filtered_findings = findings
        
        if severity_filter:
            filtered_findings = [
                f for f in filtered_findings 
                if f.get('severity', '').lower() == severity_filter.lower()
            ]
        
        if category_filter:
            filtered_findings = [
                f for f in filtered_findings 
                if f.get('category', '').lower() == category_filter.lower()
            ]
        
        return jsonify({
            'scan_id': scan_id,
            'findings': filtered_findings,
            'total': len(findings),
            'filtered': len(filtered_findings)
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting findings for scan {scan_id}: {e}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500