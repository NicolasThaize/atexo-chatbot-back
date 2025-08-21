import requests
from config import Config
import logging

logger = logging.getLogger(__name__)

class WrenAIClient:
    """Client pour interagir avec l'API WrenAI OSS"""
    
    def __init__(self):
        self.config = Config()
        self.base_url = self.config.WRENAI_BASE_URL
        self.api_key = self.config.WRENAI_API_KEY
        self.mistral_preprompt = self.config.MISTRAL_PREPROMPT
        logger.info("WrenAIClient initialized")
        logger.info(f"Base URL: {self.base_url}")
        logger.info(f"API Key: {self.api_key}")
        
    def ask_question(self, question, thread_id=None):
        """
        Envoie une question à l'API WrenAI OSS
        
        Args:
            question (str): Question en langage naturel
            thread_id (str, optional): ID du thread de conversation
            
        Returns:
            dict: Réponse de WrenAI OSS
        """
        try:
            url = f"{self.base_url}/ask"
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'question': self.mistral_preprompt + question,
                'language': 'fr'  # Forcer la langue en français
            }
            
            # Ajouter le threadId si fourni
            if thread_id:
                payload['threadId'] = thread_id
            
            logger.info(f"Envoi de la question à WrenAI: {question}")
            
            response = requests.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Réponse reçue de WrenAI avec threadId: {data.get('threadId')}")
                return {
                    'success': True,
                    'data': data
                }
            else:
                logger.error(f"Erreur WrenAI API: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f'Erreur API WrenAI: {response.status_code}',
                    'details': response.text
                }
                
        except requests.RequestException as e:
            logger.error(f"Erreur de connexion à WrenAI: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur de connexion à WrenAI OSS'
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'appel à WrenAI: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur interne lors de l\'appel à WrenAI'
            }
    
    def get_conversation_history(self, thread_id):
        """
        Récupère l'historique d'une conversation
        
        Args:
            thread_id (str): ID du thread de conversation
            
        Returns:
            dict: Historique de la conversation
        """
        try:
            url = f"{self.base_url}/conversation/{thread_id}"
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'data': response.json()
                }
            else:
                logger.error(f"Erreur lors de la récupération de l'historique: {response.status_code}")
                return {
                    'success': False,
                    'error': f'Erreur lors de la récupération de l\'historique: {response.status_code}'
                }
                
        except requests.RequestException as e:
            logger.error(f"Erreur de connexion pour l'historique: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur de connexion à WrenAI OSS'
            }
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'historique: {str(e)}")
            return {
                'success': False,
                'error': 'Erreur interne lors de la récupération de l\'historique'
            } 