import os
from datetime import timedelta

class Config:
    """Flask application configuration"""
    
    # Secret key for session management and CSRF protection
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # Security settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # Zoho SMTP settings
    ZOHO_SMTP_SERVER = 'smtp.zoho.com'
    ZOHO_SMTP_PORT = 587
    
    # Rate limiting settings
    RATE_LIMIT_EMAILS_PER_MINUTE = 10
    RATE_LIMIT_EMAILS_PER_HOUR = 100
    
    # Logging settings
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'logs/app.log'
    
    # Email validation settings
    ALLOWED_EMAIL_DOMAINS = ['zoho.com', 'zohomail.com', 'gmail.com', 'outlook.com', 'yahoo.com']
    
    @staticmethod
    def init_app(app):
        """Initialize application with config"""
        pass

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Use environment variables in production
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}