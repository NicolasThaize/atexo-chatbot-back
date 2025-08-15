from flask import Flask
from flask_oidc import OpenIDConnect
from config import Config
from flask_cors import CORS

# Initialisation des extensions
oidc = OpenIDConnect()

def create_app(config_class=Config):
    """Factory pattern pour créer l'application Flask"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configuration des CORS, modifiez l'origine selon votre application frontend
    CORS(app, origins=["http://localhost:4200"], supports_credentials=True)
    
    with app.app_context():
    
        # Initialisation des extensions (seulement si l'authentification est activée)
        if app.config.get('AUTH_ENABLED', True) and app.config.get('OIDC_ENABLED', True):
            try:
                oidc.init_app(app)
            except Exception as e:
                print(f"Warning: OIDC initialization failed: {e}")
                print("Continuing without OIDC support")

        # Enregistrement des blueprints
        from app.routes import auth_routes, chatbot_routes


        app.register_blueprint(auth_routes.bp)
        app.register_blueprint(chatbot_routes.bp)
    
    return app 