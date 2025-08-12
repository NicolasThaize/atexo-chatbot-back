from flask import Blueprint, request, jsonify, current_app
from app.services.chatbot_service import ChatbotService
from app.services.auth_service import require_jwt
from datetime import datetime
import logging

bp = Blueprint('chatbot', __name__, url_prefix='/chatbot')
logger = logging.getLogger(__name__)

@bp.route('/query', methods=['POST'])
@require_jwt
def query():
    """
    Traite une question utilisateur et retourne la réponse via WrenAI OSS
    
    Headers requis:
    Authorization: Bearer <token>
    
    Payload d'entrée:
    {
        "question": "Quelle est la liste des clients ?",
        "threadId": "optional-thread-id"
    }
    
    Réponse:
    {
        "threadId": "thread-id-here",
        "sql": "SELECT * FROM clients;",
        "results": [...],
        "summary": "Il y a 10 clients.",
        "explanation": "La requête a sélectionné tous les clients dans la table."
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Données JSON requises'}), 400
        
        question = data.get('question')
        thread_id = data.get('threadId')
        
        if not question:
            return jsonify({'error': 'Question requise'}), 400
        
        # Récupération des informations utilisateur depuis le token
        user_info = request.token_data
        
        chatbot_service = ChatbotService()
        result = chatbot_service.process_query(question, thread_id, user_info)
        
        if result['success']:
            return jsonify(result['data']), 200
        else:
            return jsonify({'error': result['error']}), 400
            
    except Exception as e:
        logger.error(f"Erreur lors du traitement de la question: {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500

@bp.route('/history', methods=['GET'])
@require_jwt
def get_history():
    """
    Récupère l'historique des conversations de l'utilisateur
    
    Headers requis:
    Authorization: Bearer <token>
    
    Paramètres de requête:
    - limit: nombre maximum de conversations (optionnel, défaut: 10)
    
    Réponse:
    {
        "conversations": [
            {
                "threadId": "thread-id-1",
                "question": "Quelle est la liste des clients ?",
                "timestamp": "2024-01-01T12:00:00Z",
                "summary": "Il y a 10 clients."
            }
        ]
    }
    """
    try:
        limit = request.args.get('limit', 10, type=int)
        user_info = request.token_data
        
        chatbot_service = ChatbotService()
        result = chatbot_service.get_conversation_history(user_info, limit)
        
        if result['success']:
            return jsonify(result['data']), 200
        else:
            return jsonify({'error': result['error']}), 400
            
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'historique: {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500

@bp.route('/test', methods=['GET'])
def test_endpoint():
    """
    Point de terminaison de test qui fonctionne sans authentification
    
    Réponse:
    {
        "message": "Test endpoint accessible",
        "auth_enabled": true/false
    }
    """
    auth_enabled = current_app.config.get('AUTH_ENABLED', True)
    
    return jsonify({
        'message': 'Test endpoint accessible',
        'auth_enabled': auth_enabled,
        'timestamp': datetime.now().isoformat()
    }), 200 