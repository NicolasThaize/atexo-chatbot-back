import pytest
import json
from unittest.mock import patch, MagicMock
from app import create_app
from app.services.auth_service import AuthService

@pytest.fixture
def client():
    """Fixture pour créer un client de test Flask"""
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_auth_service():
    """Fixture pour mocker le service d'authentification"""
    with patch('app.routes.auth_routes.AuthService') as mock:
        yield mock

class TestAuthRoutes:
    """Tests pour les routes d'authentification"""
    
    def test_login_success(self, client, mock_auth_service):
        """Test de connexion réussie"""
        # Mock de la réponse du service d'authentification
        mock_instance = MagicMock()
        mock_auth_service.return_value = mock_instance
        mock_instance.authenticate_user.return_value = {
            'success': True,
            'token': 'jwt_token_here',
            'user': {
                'username': 'test@example.com',
                'email': 'test@example.com'
            }
        }
        
        # Données de test
        login_data = {
            'username': 'test@example.com',
            'password': 'password123'
        }
        
        # Appel de l'endpoint
        response = client.post('/auth/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        
        # Vérifications
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'token' in data
        assert 'user' in data
        assert data['user']['username'] == 'test@example.com'
        
        # Vérification que le service a été appelé
        mock_instance.authenticate_user.assert_called_once_with(
            'test@example.com', 'password123'
        )
    
    def test_login_missing_data(self, client):
        """Test de connexion avec données manquantes"""
        # Test sans données
        response = client.post('/auth/login',
                             content_type='application/json')
        assert response.status_code == 400
        
        # Test avec données partielles
        response = client.post('/auth/login',
                             data=json.dumps({'username': 'test@example.com'}),
                             content_type='application/json')
        assert response.status_code == 400
    
    def test_login_failure(self, client, mock_auth_service):
        """Test de connexion échouée"""
        # Mock de l'échec d'authentification
        mock_instance = MagicMock()
        mock_auth_service.return_value = mock_instance
        mock_instance.authenticate_user.return_value = {
            'success': False,
            'error': 'Identifiants invalides'
        }
        
        login_data = {
            'username': 'wrong@example.com',
            'password': 'wrongpassword'
        }
        
        response = client.post('/auth/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_verify_token_success(self, client):
        """Test de vérification de token réussie"""
        # Mock du décorateur require_jwt
        with patch('app.routes.auth_routes.require_jwt') as mock_decorator:
            # Simuler un token valide
            mock_decorator.return_value = lambda f: f
            
            # Mock des données du token dans request
            with patch('flask.request') as mock_request:
                mock_request.token_data = {'username': 'test@example.com', 'email': 'test@example.com'}
                response = client.get('/auth/verify',
                                    headers={'Authorization': 'Bearer valid_token'})
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['valid'] is True
                assert 'user' in data
    
    def test_verify_token_missing_header(self, client):
        """Test de vérification sans header d'autorisation"""
        response = client.get('/auth/verify')
        assert response.status_code == 401
    
    def test_verify_token_invalid_format(self, client):
        """Test de vérification avec format de token invalide"""
        response = client.get('/auth/verify',
                            headers={'Authorization': 'InvalidFormat token'})
        assert response.status_code == 401

class TestAuthService:
    """Tests pour le service d'authentification"""
    
    def test_create_jwt_token(self):
        """Test de création de token JWT"""
        auth_service = AuthService()
        username = 'test@example.com'
        keycloak_data = {'access_token': 'keycloak_token'}
        
        token = auth_service._create_jwt_token(username, keycloak_data)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Vérification du décodage
        decoded = auth_service.verify_jwt_token(token)
        assert decoded is not None
        assert decoded['username'] == username
        assert decoded['email'] == username
    
    def test_verify_jwt_token_invalid(self):
        """Test de vérification de token JWT invalide"""
        auth_service = AuthService()
        
        # Token invalide
        result = auth_service.verify_jwt_token('invalid_token')
        assert result is None 