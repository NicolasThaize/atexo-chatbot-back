import pytest
import json
from unittest.mock import patch, MagicMock
from app import create_app
from app.services.chatbot_service import ChatbotService
from app.services.wrenai_client import WrenAIClient

@pytest.fixture
def client():
    """Fixture pour créer un client de test Flask"""
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_chatbot_service():
    """Fixture pour mocker le service du chatbot"""
    with patch('app.routes.chatbot_routes.ChatbotService') as mock:
        yield mock

@pytest.fixture
def valid_token_data():
    """Fixture pour des données de token valides"""
    return {
        'username': 'test@example.com',
        'email': 'test@example.com'
    }

class TestChatbotRoutes:
    """Tests pour les routes du chatbot"""
    
    def test_query_success(self, client, mock_chatbot_service, valid_token_data):
        """Test de requête réussie"""
        # Mock de la réponse du service du chatbot
        mock_instance = MagicMock()
        mock_chatbot_service.return_value = mock_instance
        mock_instance.process_query.return_value = {
            'success': True,
            'data': {
                'threadId': 'thread-123',
                'sql': 'SELECT * FROM clients;',
                'results': [{'id': 1, 'name': 'Client A'}],
                'summary': 'Il y a 1 client.',
                'explanation': 'La requête a sélectionné tous les clients.'
            }
        }
        
        # Mock du décorateur require_jwt
        with patch('app.routes.chatbot_routes.require_jwt') as mock_decorator:
            mock_decorator.return_value = lambda f: f
            
            # Mock des données du token
            with patch.object(client.application, 'token_data', valid_token_data):
                # Données de test
                query_data = {
                    'question': 'Quelle est la liste des clients ?'
                }
                
                # Appel de l'endpoint
                response = client.post('/chatbot/query',
                                     data=json.dumps(query_data),
                                     content_type='application/json',
                                     headers={'Authorization': 'Bearer valid_token'})
                
                # Vérifications
                assert response.status_code == 200
                data = json.loads(response.data)
                assert 'threadId' in data
                assert 'sql' in data
                assert 'results' in data
                assert 'summary' in data
                assert 'explanation' in data
                
                # Vérification que le service a été appelé
                mock_instance.process_query.assert_called_once_with(
                    'Quelle est la liste des clients ?',
                    None,
                    valid_token_data
                )
    
    def test_query_with_thread_id(self, client, mock_chatbot_service, valid_token_data):
        """Test de requête avec threadId"""
        mock_instance = MagicMock()
        mock_chatbot_service.return_value = mock_instance
        mock_instance.process_query.return_value = {
            'success': True,
            'data': {
                'threadId': 'thread-123',
                'sql': 'SELECT * FROM clients WHERE id > 1;',
                'results': [],
                'summary': 'Aucun client trouvé.',
                'explanation': 'La requête n\'a trouvé aucun client.'
            }
        }
        
        with patch('app.routes.chatbot_routes.require_jwt') as mock_decorator:
            mock_decorator.return_value = lambda f: f
            
            with patch.object(client.application, 'token_data', valid_token_data):
                query_data = {
                    'question': 'Montrez-moi les clients avec ID > 1',
                    'threadId': 'thread-123'
                }
                
                response = client.post('/chatbot/query',
                                     data=json.dumps(query_data),
                                     content_type='application/json',
                                     headers={'Authorization': 'Bearer valid_token'})
                
                assert response.status_code == 200
                
                # Vérification que le service a été appelé avec le threadId
                mock_instance.process_query.assert_called_once_with(
                    'Montrez-moi les clients avec ID > 1',
                    'thread-123',
                    valid_token_data
                )
    
    def test_query_missing_data(self, client):
        """Test de requête avec données manquantes"""
        # Test sans données
        response = client.post('/chatbot/query',
                             content_type='application/json')
        assert response.status_code == 400
        
        # Test sans question
        response = client.post('/chatbot/query',
                             data=json.dumps({'threadId': 'thread-123'}),
                             content_type='application/json')
        assert response.status_code == 400
    
    def test_query_failure(self, client, mock_chatbot_service, valid_token_data):
        """Test de requête échouée"""
        mock_instance = MagicMock()
        mock_chatbot_service.return_value = mock_instance
        mock_instance.process_query.return_value = {
            'success': False,
            'error': 'Erreur lors du traitement de la question'
        }
        
        with patch('app.routes.chatbot_routes.require_jwt') as mock_decorator:
            mock_decorator.return_value = lambda f: f
            
            with patch.object(client.application, 'token_data', valid_token_data):
                query_data = {
                    'question': 'Question invalide'
                }
                
                response = client.post('/chatbot/query',
                                     data=json.dumps(query_data),
                                     content_type='application/json',
                                     headers={'Authorization': 'Bearer valid_token'})
                
                assert response.status_code == 400
                data = json.loads(response.data)
                assert 'error' in data
    
    def test_history_success(self, client, mock_chatbot_service, valid_token_data):
        """Test de récupération de l'historique"""
        mock_instance = MagicMock()
        mock_chatbot_service.return_value = mock_instance
        mock_instance.get_conversation_history.return_value = {
            'success': True,
            'data': {
                'conversations': [
                    {
                        'threadId': 'thread-123',
                        'question': 'Quelle est la liste des clients ?',
                        'timestamp': '2024-01-01T12:00:00Z',
                        'summary': 'Il y a 10 clients.'
                    }
                ]
            }
        }
        
        with patch('app.routes.chatbot_routes.require_jwt') as mock_decorator:
            mock_decorator.return_value = lambda f: f
            
            with patch.object(client.application, 'token_data', valid_token_data):
                response = client.get('/chatbot/history',
                                    headers={'Authorization': 'Bearer valid_token'})
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert 'conversations' in data
                assert len(data['conversations']) == 1
                
                # Vérification que le service a été appelé
                mock_instance.get_conversation_history.assert_called_once_with(
                    valid_token_data, 10
                )
    
    def test_history_with_limit(self, client, mock_chatbot_service, valid_token_data):
        """Test de récupération de l'historique avec limite"""
        mock_instance = MagicMock()
        mock_chatbot_service.return_value = mock_instance
        mock_instance.get_conversation_history.return_value = {
            'success': True,
            'data': {'conversations': []}
        }
        
        with patch('app.routes.chatbot_routes.require_jwt') as mock_decorator:
            mock_decorator.return_value = lambda f: f
            
            with patch.object(client.application, 'token_data', valid_token_data):
                response = client.get('/chatbot/history?limit=5',
                                    headers={'Authorization': 'Bearer valid_token'})
                
                assert response.status_code == 200
                
                # Vérification que le service a été appelé avec la limite
                mock_instance.get_conversation_history.assert_called_once_with(
                    valid_token_data, 5
                )

class TestWrenAIClient:
    """Tests pour le client WrenAI"""
    
    @patch('app.services.wrenai_client.requests.post')
    def test_ask_question_success(self, mock_post):
        """Test d'appel réussi à WrenAI"""
        # Mock de la réponse de WrenAI
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'threadId': 'thread-123',
            'sql': 'SELECT * FROM clients;',
            'results': [{'id': 1, 'name': 'Client A'}],
            'summary': 'Il y a 1 client.',
            'explanation': 'La requête a sélectionné tous les clients.'
        }
        mock_post.return_value = mock_response
        
        client = WrenAIClient()
        result = client.ask_question('Quelle est la liste des clients ?')
        
        assert result['success'] is True
        assert 'threadId' in result['data']
        assert 'sql' in result['data']
        
        # Vérification de l'appel à l'API
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert 'language' in call_args[1]['json']
        assert call_args[1]['json']['language'] == 'fr'
    
    @patch('app.services.wrenai_client.requests.post')
    def test_ask_question_with_thread_id(self, mock_post):
        """Test d'appel à WrenAI avec threadId"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'threadId': 'thread-123',
            'sql': 'SELECT * FROM clients WHERE id > 1;',
            'results': [],
            'summary': 'Aucun client trouvé.',
            'explanation': 'La requête n\'a trouvé aucun client.'
        }
        mock_post.return_value = mock_response
        
        client = WrenAIClient()
        result = client.ask_question('Montrez-moi les clients avec ID > 1', 'thread-123')
        
        assert result['success'] is True
        
        # Vérification que le threadId a été envoyé
        call_args = mock_post.call_args
        assert call_args[1]['json']['threadId'] == 'thread-123'
    
    @patch('app.services.wrenai_client.requests.post')
    def test_ask_question_failure(self, mock_post):
        """Test d'échec d'appel à WrenAI"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_post.return_value = mock_response
        
        client = WrenAIClient()
        result = client.ask_question('Question invalide')
        
        assert result['success'] is False
        assert 'error' in result 