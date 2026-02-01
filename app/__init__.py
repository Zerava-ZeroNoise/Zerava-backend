"""
Zerava Security Scanner - Flask Application Factory

This module initializes the Flask application and registers all blueprints.
"""

from flask import Flask
from flask_cors import CORS
from config import Config


def create_app(config_class=Config):
    """
    Create and configure the Flask application.
    
    Args:
        config_class: Configuration class to use (default: Config)
    
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Enable CORS for all routes
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    })
    
    # Register blueprints
    from app.routes.scan_routes import scan_bp
    from app.routes.status_routes import status_bp
    
    app.register_blueprint(scan_bp, url_prefix='/api/scans')
    app.register_blueprint(status_bp, url_prefix='/api/status')
    
    # Initialize job queue
    from app.utils.job_queue import init_job_queue
    init_job_queue(app)
    
    @app.route('/health')
    def health_check():
        """Simple health check endpoint."""
        return {'status': 'healthy', 'service': 'zerava-scanner'}, 200
    
    return app