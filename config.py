import os
from pathlib import Path

# Base directory of the application
BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-super-secret-key-change-in-prod')
    
    # Database Settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f"sqlite:///{BASE_DIR / 'soc_assistant.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT Settings
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-super-secret-key')
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    
    # Security Headers
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    ENV = 'development'
    SESSION_COOKIE_SECURE = False  # Allows HTTP during local testing

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    ENV = 'production'

# Configuration dictionary to easily load settings based on environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
