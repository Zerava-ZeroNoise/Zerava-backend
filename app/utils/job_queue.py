"""
Zerava Security Scanner - Job Queue Manager

This module manages background scanning jobs using threading.
For production, consider using Celery with Redis or RabbitMQ.
"""

import logging
import threading
import time
from typing import Dict, Optional, Callable, Any
from queue import Queue, Empty
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import traceback

logger = logging.getLogger(__name__)


class JobQueue:
    """
    Manages background scan jobs.
    
    Provides a simple queue-based job system for running scans asynchronously.
    Jobs are stored in memory (not persistent across restarts).
    """
    
    def __init__(self, max_workers: int = 5, result_ttl: int = 3600):
        """
        Initialize the job queue.
        
        Args:
            max_workers: Maximum number of concurrent jobs
            result_ttl: Time to live for job results in seconds
        """
        self.max_workers = max_workers
        self.result_ttl = result_ttl
        
        # Thread pool for executing jobs
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Storage for job metadata and results
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        
        # Cleanup thread
        self.cleanup_thread = None
        self.cleanup_interval = 300  # 5 minutes
        self.running = False
        
        logger.info(f"Job queue initialized with {max_workers} workers")
    
    def start(self):
        """Start the job queue and cleanup thread."""
        if not self.running:
            self.running = True
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                daemon=True
            )
            self.cleanup_thread.start()
            logger.info("Job queue started")
    
    def stop(self):
        """Stop the job queue and cleanup thread."""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        self.executor.shutdown(wait=True)
        logger.info("Job queue stopped")
    
    def submit_job(self, job_id: str, func: Callable, *args, **kwargs) -> str:
        """
        Submit a job to the queue.
        
        Args:
            job_id: Unique identifier for the job
            func: Function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
        
        Returns:
            Job ID
        """
        with self.lock:
            # Check if job already exists
            if job_id in self.jobs:
                existing_status = self.jobs[job_id]['status']
                if existing_status in ['pending', 'running']:
                    logger.warning(f"Job {job_id} already exists with status {existing_status}")
                    return job_id
            
            # Create job metadata
            self.jobs[job_id] = {
                'job_id': job_id,
                'status': 'pending',
                'created_at': datetime.utcnow(),
                'started_at': None,
                'completed_at': None,
                'result': None,
                'error': None,
                'progress': 0
            }
        
        # Submit to executor
        future = self.executor.submit(self._execute_job, job_id, func, *args, **kwargs)
        
        with self.lock:
            self.jobs[job_id]['future'] = future
        
        logger.info(f"Job {job_id} submitted to queue")
        return job_id
    
    def _execute_job(self, job_id: str, func: Callable, *args, **kwargs):
        """
        Execute a job and handle its lifecycle.
        
        Args:
            job_id: Job identifier
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
        """
        try:
            # Update status to running
            with self.lock:
                if job_id in self.jobs:
                    self.jobs[job_id]['status'] = 'running'
                    self.jobs[job_id]['started_at'] = datetime.utcnow()
            
            logger.info(f"Job {job_id} started")
            
            # Execute the function
            result = func(*args, **kwargs)
            
            # Update with result
            with self.lock:
                if job_id in self.jobs:
                    self.jobs[job_id]['status'] = 'completed'
                    self.jobs[job_id]['completed_at'] = datetime.utcnow()
                    self.jobs[job_id]['result'] = result
                    self.jobs[job_id]['progress'] = 100
            
            logger.info(f"Job {job_id} completed successfully")
        
        except Exception as e:
            error_msg = str(e)
            error_trace = traceback.format_exc()
            
            # Update with error
            with self.lock:
                if job_id in self.jobs:
                    self.jobs[job_id]['status'] = 'failed'
                    self.jobs[job_id]['completed_at'] = datetime.utcnow()
                    self.jobs[job_id]['error'] = error_msg
                    self.jobs[job_id]['error_trace'] = error_trace
            
            logger.error(f"Job {job_id} failed: {error_msg}\n{error_trace}")
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of a job.
        
        Args:
            job_id: Job identifier
        
        Returns:
            Job metadata dictionary or None if not found
        """
        with self.lock:
            job = self.jobs.get(job_id)
            if job:
                # Return a copy without the future object
                job_copy = {k: v for k, v in job.items() if k != 'future'}
                
                # Convert datetime objects to ISO format
                for key in ['created_at', 'started_at', 'completed_at']:
                    if job_copy.get(key):
                        job_copy[key] = job_copy[key].isoformat() + 'Z'
                
                return job_copy
            return None
    
    def get_job_result(self, job_id: str) -> Optional[Any]:
        """
        Get the result of a completed job.
        
        Args:
            job_id: Job identifier
        
        Returns:
            Job result or None
        """
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job['status'] == 'completed':
                return job['result']
            return None
    
    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending or running job.
        
        Args:
            job_id: Job identifier
        
        Returns:
            True if cancelled, False otherwise
        """
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return False
            
            if job['status'] in ['pending', 'running']:
                # Try to cancel the future
                future = job.get('future')
                if future:
                    cancelled = future.cancel()
                    if cancelled:
                        job['status'] = 'cancelled'
                        job['completed_at'] = datetime.utcnow()
                        logger.info(f"Job {job_id} cancelled")
                        return True
                
                # If future couldn't be cancelled (already running)
                # We can't actually stop it, but mark it as cancelled
                if job['status'] == 'running':
                    logger.warning(f"Job {job_id} is already running and cannot be stopped")
                    return False
            
            return False
    
    def update_progress(self, job_id: str, progress: int):
        """
        Update the progress of a running job.
        
        Args:
            job_id: Job identifier
            progress: Progress percentage (0-100)
        """
        with self.lock:
            job = self.jobs.get(job_id)
            if job and job['status'] == 'running':
                job['progress'] = max(0, min(100, progress))
    
    def list_jobs(self, status: Optional[str] = None) -> list:
        """
        List all jobs, optionally filtered by status.
        
        Args:
            status: Filter by status (pending, running, completed, failed, cancelled)
        
        Returns:
            List of job metadata dictionaries
        """
        with self.lock:
            jobs = list(self.jobs.values())
            
            if status:
                jobs = [j for j in jobs if j['status'] == status]
            
            # Remove future objects and convert dates
            result = []
            for job in jobs:
                job_copy = {k: v for k, v in job.items() if k != 'future'}
                for key in ['created_at', 'started_at', 'completed_at']:
                    if job_copy.get(key):
                        job_copy[key] = job_copy[key].isoformat() + 'Z'
                result.append(job_copy)
            
            return result
    
    def _cleanup_loop(self):
        """Background thread to clean up old jobs."""
        while self.running:
            try:
                time.sleep(self.cleanup_interval)
                self._cleanup_old_jobs()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    def _cleanup_old_jobs(self):
        """Remove old completed/failed jobs based on TTL."""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.result_ttl)
        
        with self.lock:
            jobs_to_remove = []
            
            for job_id, job in self.jobs.items():
                # Only cleanup completed, failed, or cancelled jobs
                if job['status'] in ['completed', 'failed', 'cancelled']:
                    completed_at = job.get('completed_at')
                    if completed_at and completed_at < cutoff:
                        jobs_to_remove.append(job_id)
            
            for job_id in jobs_to_remove:
                del self.jobs[job_id]
                logger.debug(f"Cleaned up old job {job_id}")
            
            if jobs_to_remove:
                logger.info(f"Cleaned up {len(jobs_to_remove)} old jobs")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get queue statistics.
        
        Returns:
            Dictionary with queue statistics
        """
        with self.lock:
            total = len(self.jobs)
            pending = sum(1 for j in self.jobs.values() if j['status'] == 'pending')
            running = sum(1 for j in self.jobs.values() if j['status'] == 'running')
            completed = sum(1 for j in self.jobs.values() if j['status'] == 'completed')
            failed = sum(1 for j in self.jobs.values() if j['status'] == 'failed')
            cancelled = sum(1 for j in self.jobs.values() if j['status'] == 'cancelled')
            
            return {
                'total_jobs': total,
                'pending': pending,
                'running': running,
                'completed': completed,
                'failed': failed,
                'cancelled': cancelled,
                'max_workers': self.max_workers,
                'result_ttl': self.result_ttl
            }


# Global job queue instance
_job_queue: Optional[JobQueue] = None


def init_job_queue(app):
    """
    Initialize the global job queue.
    
    Args:
        app: Flask application instance
    """
    global _job_queue
    
    max_workers = app.config.get('MAX_CONCURRENT_SCANS', 5)
    result_ttl = app.config.get('JOB_RESULT_TTL', 3600)
    
    _job_queue = JobQueue(max_workers=max_workers, result_ttl=result_ttl)
    _job_queue.start()
    
    # Register cleanup on app teardown
    @app.teardown_appcontext
    def shutdown_job_queue(exception=None):
        if _job_queue:
            _job_queue.stop()
    
    logger.info("Job queue initialized")


def get_job_queue() -> JobQueue:
    """
    Get the global job queue instance.
    
    Returns:
        JobQueue instance
    
    Raises:
        RuntimeError: If job queue not initialized
    """
    if _job_queue is None:
        raise RuntimeError("Job queue not initialized. Call init_job_queue first.")
    return _job_queue