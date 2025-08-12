import jwt
import requests
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app, session, g
from flask_oidc import OpenIDConnect
from config import Config
import logging
import json

logger = logging.getLogger(__name__)

class AuthService:
    """Service de gestion de l'authentification via Keycloak avec Flask-OIDC"""
    
    def __init__(self):
        self.config = Config()
        logger.info("AuthService initialized")
        logger.info(f"Config: {self.config.__str__()}")
    
    def get_keycloak_public_key(self, kid):
        """
        Fetch the public key from Keycloak's JWKS endpoint
        
        Returns:
            str: PEM-formatted public key or None if failed
        """
        try:
            logger.info("Fetching public key from Keycloak JWKS endpoint...")
            jwks_url = f"{self.config.KEYCLOAK_SERVER_URL}/realms/{self.config.KEYCLOAK_REALM}/protocol/openid-connect/certs"
            logger.info(f"JWKS URL: {jwks_url}")
            
            response = requests.get(jwks_url, timeout=10)
            logger.info(f"JWKS response status: {response.status_code}")
            
            if response.status_code == 200:
                jwks = response.json()
                logger.info(f"JWKS keys count: {len(jwks.get('keys', []))}")
                
                # Get the key with the given kid
                if 'keys' in jwks and len(jwks['keys']) > 0:
                    key_data = next((key for key in jwks['keys'] if key.get('kid') == kid), None)
                    logger.info(f"Key data: {key_data}")
                    logger.info(f"Using key with kid: {key_data.get('kid', 'unknown')}")
                    logger.info(f"Key algorithm: {key_data.get('alg', 'unknown')}")
                    
                    # Convert JWK to PEM format
                    pem_key = self._jwk_to_pem(key_data)
                    if pem_key:
                        logger.info("Successfully converted JWK to PEM format")
                        return pem_key
                    else:
                        logger.error("Failed to convert JWK to PEM format")
                else:
                    logger.error("No keys found in JWKS response")
            else:
                logger.error(f"Failed to fetch JWKS: {response.status_code} - {response.text}")
            
            return None
        except requests.RequestException as e:
            logger.error(f"Request error fetching Keycloak public key: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching Keycloak public key: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return None
    
    def _jwk_to_pem(self, jwk):
        """
        Convert JWK (JSON Web Key) to PEM format
        
        Args:
            jwk (dict): JWK data
            
        Returns:
            str: PEM-formatted public key or None if failed
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import base64
            
            # Extract key components
            n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='), 'big')
            e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '=='), 'big')
            
            # Create RSA public key
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            
            # Serialize to PEM format
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error converting JWK to PEM: {e}")
            return None
    
    def detect_token_algorithm(self, token):
        """
        Detect the algorithm used in the JWT token
        
        Args:
            token (str): JWT token
            
        Returns:
            str: Algorithm name (RS256, HS256, etc.) or None if failed
        """
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get('alg', 'unknown')
            logger.info(f"Detected token algorithm: {algorithm}")
            return algorithm
        except Exception as e:
            logger.error(f"Error detecting token algorithm: {e}")
            return None
    
    def authenticate_user(self, username, password):
        """
        Authentifie un utilisateur via Keycloak
        
        Args:
            username (str): Nom d'utilisateur
            password (str): Mot de passe
            
        Returns:
            dict: Résultat de l'authentification
        """
        try:
            # Construction de l'URL de token Keycloak
            token_url = f"{self.config.KEYCLOAK_SERVER_URL}/realms/{self.config.KEYCLOAK_REALM}/protocol/openid-connect/token"
            
            # Données pour l'authentification
            token_data = {
                'grant_type': 'password',
                'client_id': self.config.KEYCLOAK_CLIENT_ID,
                'client_secret': self.config.KEYCLOAK_CLIENT_SECRET,
                'username': username,
                'password': password
            }
            
            # Appel à Keycloak
            response = requests.post(token_url, data=token_data)
            
            if response.status_code == 200:
                keycloak_data = response.json()
                
                # Debug: Log the Keycloak response
                logger.info(f"Keycloak response keys: {list(keycloak_data.keys())}")
                logger.info(f"Keycloak access_token exists: {'access_token' in keycloak_data}")
                
                # Debug: Decode the token header to see the algorithm
                import jwt
                try:
                    token_header = jwt.get_unverified_header(keycloak_data['access_token'])
                    logger.info(f"Keycloak token header: {token_header}")
                    logger.info(f"Keycloak token algorithm: {token_header.get('alg', 'unknown')}")
                except Exception as e:
                    logger.error(f"Error decoding token header: {e}")
                
                return {
                    'success': True,
                    'token': keycloak_data['access_token'],
                    'user': {
                        'username': username,
                        'email': username
                    }
                }
            else:
                logger.warning(f"Échec de l'authentification pour {username}: {response.status_code}")
                return {
                    'success': False,
                    'error': 'Identifiants invalides'
                }
                
        except requests.RequestException as e:
            logger.error(f"Erreur de connexion à Keycloak: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur de connexion au serveur d\'authentification'
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'authentification: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur interne du serveur'
            }
    
    def _create_jwt_token(self, username, keycloak_data):
        """
        Crée un token JWT personnalisé
        
        Args:
            username (str): Nom d'utilisateur
            keycloak_data (dict): Données de réponse de Keycloak
            
        Returns:
            str: Token JWT encodé
        """
        payload = {
            'username': username,
            'email': username,
            'exp': datetime.utcnow() + timedelta(hours=self.config.JWT_EXPIRATION_HOURS),
            'iat': datetime.utcnow(),
            'keycloak_access_token': keycloak_data.get('access_token', '')
        }
        
        return jwt.encode(payload, self.config.JWT_SECRET_KEY, algorithm=self.config.JWT_ALGORITHM)
    
    def verify_jwt_token(self, token):
        """
        Vérifie et décode un token JWT
        
        Args:
            token (str): Token JWT à vérifier
            
        Returns:
            dict: Données du token décodé ou None si invalide
        """
        logger.info(f"=== verify_jwt_token Debug ===")
        logger.info(f"Token length: {len(token)}")
        logger.info(f"Token preview: {token[:30]}...")
        
        # Detect token algorithm first
        token_algorithm = self.detect_token_algorithm(token)
        if not token_algorithm:
            logger.error("Could not detect token algorithm")
            return None
        
        logger.info(f"Token algorithm: {token_algorithm}")
        logger.info(f"Configured algorithm: {self.config.JWT_ALGORITHM}")
        
        # Check if token is valid JWT format
        try:
            import jwt
            header = jwt.get_unverified_header(token)
            logger.info(f"Token header: {header}")
            logger.info(f"Token algorithm in header: {header.get('alg', 'unknown')}")
            logger.info(f"Token type in header: {header.get('typ', 'unknown')}")
        except Exception as e:
            logger.error(f"Error reading token header: {e}")
        
        try:
            logger.info("Attempting to decode JWT token...")
            
            if token_algorithm == 'RS256':
                logger.info("Processing RS256 token...")
                
                # Try to get public key from config first
                public_key = getattr(self.config, 'JWT_PUBLIC_KEY', None)
                
                # If no public key in config, try to fetch from Keycloak
                if not public_key:
                    logger.info("No public key in config, fetching from Keycloak...")
                    if header.get('kid'):
                        public_key = self.get_keycloak_public_key(header.get('kid'))
                    else:
                        logger.error("No kid in token header, cannot fetch public key from Keycloak")
                        return None
                
                if not public_key:
                    logger.error("No public key available for RS256 verification")
                    return None
                
                logger.info(f"Public key length: {len(public_key)}")
                logger.info(f"Public key preview: {public_key[:50]}...")
                
                payload = jwt.decode(
                    token, 
                    public_key, 
                    algorithms=[token_algorithm],
                    options={
                        'verify_signature': True,
                        'verify_exp': True,
                        'verify_aud': False,  # Disable audience verification if not needed
                        'verify_iss': False   # Disable issuer verification if not needed
                    }
                )
                
            elif token_algorithm == 'HS256':
                logger.info("Processing HS256 token...")
                
                # Log the secret key details
                logger.info(f"Secret key type: {type(self.config.JWT_SECRET_KEY)}")
                logger.info(f"Secret key length: {len(self.config.JWT_SECRET_KEY)}")
                logger.info(f"Secret key preview: {self.config.JWT_SECRET_KEY[:20]}...")
                
                payload = jwt.decode(
                    token, 
                    self.config.JWT_SECRET_KEY, 
                    algorithms=[token_algorithm]
                )
                
            else:
                logger.error(f"Unsupported algorithm: {token_algorithm}")
                return None
            
            logger.info(f"Token decoded successfully! Payload keys: {list(payload.keys())}")
            logger.info(f"Token username: {payload.get('preferred_username', payload.get('username', 'N/A'))}")
            logger.info(f"Token expiration: {payload.get('exp', 'N/A')}")
            return payload
            
        except jwt.ExpiredSignatureError as e:
            logger.warning(f"Token JWT expiré: {e}")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token JWT invalide: {str(e)}")
            logger.warning(f"Invalid token error type: {type(e).__name__}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during token verification: {type(e).__name__}: {str(e)}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return None
    
    def get_user_info_from_oidc(self):
        """
        Récupère les informations utilisateur depuis Flask-OIDC
        
        Returns:
            dict: Informations utilisateur ou None si non connecté
        """
        try:
            from app import oidc
            
            if oidc.user_loggedin:
                # Utiliser les informations de session OIDC
                if 'oidc_auth_profile' in session:
                    return session['oidc_auth_profile']
                # Ou utiliser l'objet utilisateur sur g
                elif hasattr(g, 'oidc_user') and g.oidc_user.logged_in:
                    return g.oidc_user.profile
            return None
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des infos utilisateur OIDC: {str(e)}")
            return None
    
    def create_oidc_token(self, user_info):
        """
        Crée un token JWT à partir des informations OIDC
        
        Args:
            user_info (dict): Informations utilisateur depuis OIDC
            
        Returns:
            str: Token JWT encodé
        """
        payload = {
            'username': user_info.get('email', user_info.get('sub', '')),
            'email': user_info.get('email', ''),
            'sub': user_info.get('sub', ''),
            'exp': datetime.utcnow() + timedelta(hours=self.config.JWT_EXPIRATION_HOURS),
            'iat': datetime.utcnow(),
            'iss': 'flask-chatbot'
        }
        
        return jwt.encode(payload, self.config.JWT_SECRET_KEY, algorithm=self.config.JWT_ALGORITHM)

def require_jwt(f):
    """
    Décorateur pour protéger les routes avec authentification JWT
    
    Args:
        f: Fonction à décorer
        
    Returns:
        function: Fonction décorée
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.info(f"=== JWT Authentication Debug - Route: {f.__name__} ===")
        
        # Vérifier si l'authentification est désactivée
        auth_enabled = current_app.config.get('AUTH_ENABLED', True)
        logger.info(f"AUTH_ENABLED config: {auth_enabled}")
        
        if not auth_enabled:
            logger.info("Authentication disabled - creating anonymous user data")
            # Créer des données utilisateur par défaut
            request.token_data = {
                'username': 'anonymous',
                'email': 'anonymous@example.com',
                'sub': 'anonymous'
            }
            return f(*args, **kwargs)
        
        auth_header = request.headers.get('Authorization')
        logger.info(f"Authorization header present: {auth_header is not None}")
        
        if not auth_header:
            logger.warning("No Authorization header found")
            return jsonify({'error': 'Token d\'authentification manquant'}), 401
        
        logger.info(f"Authorization header: {auth_header[:20]}..." if len(auth_header) > 20 else f"Authorization header: {auth_header}")
        
        try:
            # Extraction du token Bearer
            if not auth_header.startswith('Bearer '):
                logger.error(f"Invalid token format - header doesn't start with 'Bearer ': {auth_header[:50]}...")
                return jsonify({'error': 'Format de token invalide'}), 401
            
            token = auth_header.split(' ')[1]
            logger.info(f"Extracted token length: {len(token)} characters")
            logger.info(f"Token preview: {token[:20]}...")
            
            # Vérification du token
            logger.info("Creating AuthService instance...")
            auth_service = AuthService()
            
            # Log configuration details
            logger.info(f"JWT_SECRET_KEY type: {type(auth_service.config.JWT_SECRET_KEY)}")
            logger.info(f"JWT_SECRET_KEY length: {len(auth_service.config.JWT_SECRET_KEY)}")
            logger.info(f"JWT_SECRET_KEY preview: {auth_service.config.JWT_SECRET_KEY[:10]}...")
            logger.info(f"JWT_ALGORITHM: {auth_service.config.JWT_ALGORITHM}")
            
            # Check if secret key looks like a PEM key
            if auth_service.config.JWT_SECRET_KEY.startswith('-----BEGIN'):
                logger.warning("JWT_SECRET_KEY appears to be a PEM-formatted key")
                logger.info(f"PEM key type detected: {auth_service.config.JWT_SECRET_KEY.split()[1] if len(auth_service.config.JWT_SECRET_KEY.split()) > 1 else 'unknown'}")
            
            logger.info("Calling verify_jwt_token...")
            token_data = auth_service.verify_jwt_token(token)
            
            if not token_data:
                logger.error("Token verification returned None/False")
                return jsonify({'error': 'Token invalide ou expiré'}), 401
            
            logger.info(f"Token verification successful - token_data keys: {list(token_data.keys())}")
            logger.info(f"Token username: {token_data.get('username', 'N/A')}")
            
            # Ajout des données du token à la requête
            request.token_data = token_data
            
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Exception during token verification: {type(e).__name__}: {str(e)}")
            logger.error(f"Exception details: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return jsonify({'error': 'Erreur de vérification du token'}), 401
    
    return decorated_function 