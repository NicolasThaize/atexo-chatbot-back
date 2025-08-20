import os
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

load_dotenv()

class Config:
    """Configuration de l'application Flask"""
    logger.info("Loading configuration...")
    # Configuration Flask
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Configuration WrenAI OSS
    WRENAI_BASE_URL = os.getenv('WRENAI_BASE_URL', 'http://localhost:8080')
    WRENAI_API_KEY = os.getenv('WRENAI_API_KEY', 'your-wrenai-api-key')
    
    # Configuration Keycloak (détails)
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'your-realm')
    KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'your-client-id')
    KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', 'your-client-secret')
    KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080/auth')
    
    # Configuration JWT
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    JWT_PUBLIC_KEY = os.getenv('JWT_PUBLIC_KEY', '')  # Optional, will be auto-fetched from Keycloak if empty
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
    JWT_EXPIRATION_HOURS = 24
    
    # Configuration d'authentification
    AUTH_ENABLED = os.getenv('AUTH_ENABLED', 'True').lower() == 'true' 

    def __str__(self):
        """Return a string representation of all configuration attributes with their values."""
        config_str = "Config:\n"
        for attr_name in dir(self):
            # Skip private attributes and methods
            if not attr_name.startswith('_') and not callable(getattr(self, attr_name)):
                attr_value = getattr(self, attr_name)
                config_str += f"  {attr_name}: {attr_value}\n"
        return config_str 
