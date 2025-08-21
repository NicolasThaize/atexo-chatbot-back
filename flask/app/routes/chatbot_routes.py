from flask import Blueprint, request, jsonify
from app.services.chatbot_service import ChatbotService
from app.services.auth_service import require_jwt
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
        
        chatbot_service = ChatbotService()
        result = chatbot_service.process_query(question, thread_id)
        
        if result['success']:
            return jsonify(result['data']), 200
        else:
            return jsonify({'error': result['error']}), 400
            
    except Exception as e:
        logger.error(f"Erreur lors du traitement de la question: {str(e)}")
        return jsonify({'error': 'Erreur interne du serveur'}), 500
