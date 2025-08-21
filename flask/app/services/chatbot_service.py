from app.services.wrenai_client import WrenAIClient
import logging

logger = logging.getLogger(__name__)

class ChatbotService:
    """Service principal du chatbot qui gère les interactions avec WrenAI OSS"""
    
    def __init__(self):
        self.wrenai_client = WrenAIClient()
        logger.info("ChatbotService initialized")
        logger.info(f"WrenAIClient: {self.wrenai_client}")
    
    def process_query(self, question, thread_id=None):
        """
        Traite une question utilisateur et retourne la réponse
        
        Args:
            question (str): Question en langage naturel
            thread_id (str, optional): ID du thread de conversation
            
        Returns:
            dict: Résultat du traitement
        """
        try:
            logger.info(f"Traitement de la question: {question}")
            
            # Appel à WrenAI OSS
            wrenai_response = self.wrenai_client.ask_question(question, thread_id)
            
            if not wrenai_response['success']:
                return {
                    'success': False,
                    'error': wrenai_response['error']
                }
            
            # Extraction des données de réponse
            wrenai_data = wrenai_response['data']
            
            # Préparation de la réponse
            response_data = {
                'threadId': wrenai_data.get('threadId'),
                'sql': wrenai_data.get('sql', ''),
                'results': wrenai_data.get('results', []),
                'summary': wrenai_data.get('summary', ''),
                'explanation': wrenai_data.get('explanation', '')
            }
            
            logger.info(f"Question traitée avec succès, threadId: {response_data['threadId']}")
            
            return {
                'success': True,
                'data': response_data
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement de la question: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur interne lors du traitement de la question'
            }
    