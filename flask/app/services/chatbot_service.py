from app.services.wrenai_client import WrenAIClient
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ChatbotService:
    """Service principal du chatbot qui gère les interactions avec WrenAI OSS"""
    
    def __init__(self):
        self.wrenai_client = WrenAIClient()
        # En production, on utiliserait une base de données pour stocker l'historique
        self.conversation_history = {}
        logger.info("ChatbotService initialized")
        logger.info(f"WrenAIClient: {self.wrenai_client}")
    
    def process_query(self, question, thread_id=None, user_info=None):
        """
        Traite une question utilisateur et retourne la réponse
        
        Args:
            question (str): Question en langage naturel
            thread_id (str, optional): ID du thread de conversation
            user_info (dict): Informations de l'utilisateur
            
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
            
            # Sauvegarde de la conversation (en production, dans une DB)
            self._save_conversation(
                wrenai_data.get('threadId'),
                question,
                wrenai_data.get('summary', ''),
                user_info
            )
            
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
    
    def get_conversation_history(self, user_info, limit=10):
        """
        Récupère l'historique des conversations de l'utilisateur
        
        Args:
            user_info (dict): Informations de l'utilisateur
            limit (int): Nombre maximum de conversations à retourner
            
        Returns:
            dict: Historique des conversations
        """
        try:
            username = user_info.get('username', 'unknown')
            
            # En production, on récupérerait depuis une base de données
            user_conversations = self.conversation_history.get(username, [])
            
            # Tri par timestamp décroissant et limitation
            sorted_conversations = sorted(
                user_conversations,
                key=lambda x: x.get('timestamp', ''),
                reverse=True
            )[:limit]
            
            return {
                'success': True,
                'data': {
                    'conversations': sorted_conversations
                }
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'historique: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur lors de la récupération de l\'historique'
            }
    
    def _save_conversation(self, thread_id, question, summary, user_info):
        """
        Sauvegarde une conversation (simulation - en production, dans une DB)
        
        Args:
            thread_id (str): ID du thread
            question (str): Question posée
            summary (str): Résumé de la réponse
            user_info (dict): Informations de l'utilisateur
        """
        try:
            username = user_info.get('username', 'unknown')
            
            conversation_entry = {
                'threadId': thread_id,
                'question': question,
                'summary': summary,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            if username not in self.conversation_history:
                self.conversation_history[username] = []
            
            self.conversation_history[username].append(conversation_entry)
            
            logger.info(f"Conversation sauvegardée pour {username}, threadId: {thread_id}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la conversation: {str(e)}")
    
    def get_conversation_by_thread_id(self, thread_id, user_info):
        """
        Récupère une conversation spécifique par threadId
        
        Args:
            thread_id (str): ID du thread
            user_info (dict): Informations de l'utilisateur
            
        Returns:
            dict: Détails de la conversation
        """
        try:
            # En production, on récupérerait depuis une base de données
            # Pour l'instant, on simule avec l'historique en mémoire
            username = user_info.get('username', 'unknown')
            user_conversations = self.conversation_history.get(username, [])
            
            conversation = next(
                (conv for conv in user_conversations if conv.get('threadId') == thread_id),
                None
            )
            
            if conversation:
                return {
                    'success': True,
                    'data': conversation
                }
            else:
                return {
                    'success': False,
                    'error': 'Conversation non trouvée'
                }
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la conversation: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur lors de la récupération de la conversation'
            } 