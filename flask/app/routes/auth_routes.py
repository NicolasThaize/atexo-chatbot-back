from flask import Blueprint, request, jsonify, session, g, redirect, url_for, current_app
from app.services.auth_service import AuthService
from app.services.auth_service import require_jwt
import logging

bp = Blueprint('auth', __name__, url_prefix='/auth')
logger = logging.getLogger(__name__)

@bp.route('/login', methods=['POST'])
def login():
    """
    Authentifie l'utilisateur via Keycloak
    
    Payload d'entrée:
    {
        "username": "user@example.com",
        "password": "password123"
    }
    
    Réponse:
    {
        "expires_in": 300,
        "refresh_token": "refresh_token_here",
        "token": "token_here",
        "user": {
            "email": "user@example.com",
            "username": "user@example.com"
        }
    }
    """
    try:
        data = request.get_json(force=True, silent=True)
        
        if not data:
            return jsonify({'error': 'Données JSON requises'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username et password requis'}), 400
        
        auth_service = AuthService()
        result = auth_service.authenticate_user(username, password)
        
        if result['success']:
            return jsonify({
                'token': result['token'],
                'refresh_token': result.get('refresh_token', ''),
                'expires_in': result.get('expires_in', 3600),
                'user': result['user']
            }), 200
        else:
            return jsonify({'error': result['error']}), 401
            
    except Exception as e:
        logger.error(f"Erreur lors de l'authentification: {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500

@bp.route('/verify', methods=['GET'])
@require_jwt
def verify_token():
    """
    Vérifie la validité du token JWT
    
    Headers requis:
    Authorization: Bearer <token>
    
    Réponse:
    {
        "valid": true,
        "user": {
            "username": "user@example.com",
            "email": "user@example.com"
        }
    }
    """
    try:
        # Le décorateur require_jwt a déjà vérifié le token
        # On peut récupérer les informations utilisateur depuis le token
        token_data = request.token_data
        return jsonify({
            'valid': True,
            'user': {
                'username': token_data.get('username'),
                'email': token_data.get('email')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du token: {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500

@bp.route('/status', methods=['GET'])
def auth_status():
    """
    Retourne le statut de l'authentification
    
    Réponse:
    {
        "auth_enabled": true/false,
        "message": "Description du statut"
    }
    """
    auth_enabled = current_app.config.get('AUTH_ENABLED', True)
    
    return jsonify({
        'auth_enabled': auth_enabled,
        'message': 'Authentification activée' if auth_enabled else 'Authentification désactivée'
    }), 200 

@bp.route('/refresh', methods=['POST'])
def refresh_token():
    """
    Rafraîchit le token d'accès en utilisant le refresh token
    
    Payload d'entrée:
    {
        "grant_type": "refresh_token",
        "refresh_token": "refr  esh_token_here",
        "client_id": "atexo-wrenai"
    }
    
    Réponse:
    {
        "access_token": "access_token_here",
        "expires_in": 300,
        "refresh_token": "refresh_token_here",
        "token_type": "Bearer"
    }
    """
    try:
        data = request.get_json(force=True, silent=True)
        
        if not data:
            return jsonify({'error': 'Données JSON requises'}), 400
        
        grant_type = data.get('grant_type')
        refresh_token = data.get('refresh_token')
        client_id = data.get('client_id')
        
        if not grant_type or not refresh_token or not client_id:
            return jsonify({'error': 'grant_type, refresh_token et client_id requis'}), 400
        
        if grant_type != 'refresh_token':
            return jsonify({'error': 'grant_type doit être "refresh_token"'}), 400
        
        auth_service = AuthService()
        result = auth_service.refresh_access_token(refresh_token, client_id)
        
        if result['success']:
            return jsonify({
                'access_token': result['access_token'],
                'refresh_token': result['refresh_token'],
                'expires_in': result['expires_in'],
                'token_type': 'Bearer'
            }), 200
        else:
            return jsonify({'error': result['error']}), 401
            
    except Exception as e:
        logger.error(f"Erreur lors du refresh token: {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500 