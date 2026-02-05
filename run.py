"""
Zerava Security Scanner - Application Entry Point

This module serves as the entry point for running the Flask application.
"""

import os
import logging
from app import create_app
from config import config

# Get environment from environment variable or default to development
env = os.environ.get('FLASK_ENV', 'development')
app = create_app(config.get(env, config['default']))

# Configure logging
logging.basicConfig(
    level=getattr(logging, app.config['LOG_LEVEL']),
    format=app.config['LOG_FORMAT']
)

logger = logging.getLogger(__name__)


if __name__ == '__main__':
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    logger.info(f"Starting Zerava Security Scanner on {host}:{port}")
    logger.info(f"Environment: {env}")
    logger.info(f"Debug mode: {app.config['DEBUG']}")
    logger.info(f"Scanning enabled: {app.config['SCANNING_ENABLED']}")
    
    app.run(
        host=host,
        port=port,
        debug=app.config['DEBUG']
    )