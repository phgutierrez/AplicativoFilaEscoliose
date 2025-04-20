import os
from datetime import timedelta

class Config:
    # Configurações básicas
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev_key_123')  # Alterar em produção!
    DATABASE = 'db.sqlite3'
    
    # Configurações de ambiente
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'False') == 'True'
    
    # Configurações de sessão
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Configurações de segurança
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max-limit
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'xlsx', 'xls'}