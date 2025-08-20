from flask import Flask
from config import Config
from flask_cors import CORS


def create_app(config_class=Config):
    """Factory pattern pour créer l'application Flask"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configuration des CORS, modifiez l'origine selon votre application frontend
    CORS(app, origins=["http://localhost:4200"], supports_credentials=True)
    
    with app.app_context():
        # Enregistrement des blueprints
        from app.routes import auth_routes, chatbot_routes


        app.register_blueprint(auth_routes.bp)
        app.register_blueprint(chatbot_routes.bp)
    
    return app 