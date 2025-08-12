import os
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

load_dotenv()

class Config:
    """Configuration de l'application Flask"""
    logger.info("Loading configuration...")
    # Configuration Flask
    #SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Configuration WrenAI OSS
    WRENAI_BASE_URL = os.getenv('WRENAI_BASE_URL', 'http://localhost:8080')
    WRENAI_API_KEY = os.getenv('WRENAI_API_KEY', 'your-wrenai-api-key')
    
    # Configuration Keycloak
    OIDC_CLIENT_SECRETS = os.getenv('OIDC_CLIENT_SECRETS', 'client_secrets.json')
    OIDC_SCOPES = os.getenv('OIDC_SCOPES', 'openid email profile')
    OIDC_CLOCK_SKEW = int(os.getenv('OIDC_CLOCK_SKEW', '60'))
    OIDC_USER_INFO_ENABLED = os.getenv('OIDC_USER_INFO_ENABLED', 'True').lower() == 'true'
    OIDC_ENABLED = os.getenv('OIDC_ENABLED', 'True').lower() == 'true'
    
    # Configuration Keycloak (détails)
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'your-realm')
    KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'your-client-id')
    KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', 'your-client-secret')
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080/auth')
    
    # Configuration JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'RS256')
    JWT_EXPIRATION_HOURS = 24
    
    # Configuration d'authentification
    AUTH_ENABLED = os.getenv('AUTH_ENABLED', 'True').lower() == 'true' 
