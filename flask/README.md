# 🎉 Backend Flask Chatbot avec WrenAI OSS

## ✅ Fonctionnalités Implémentées

### 🔐 Authentification
- **Flask-OIDC 2.4.0** intégré avec Keycloak
- **Deux méthodes d'authentification** :
  - Méthode directe : `POST /auth/login` (username/password)
  - Méthode OIDC : `GET /auth/oidc/login` (recommandée)
- **Tokens JWT** avec expiration configurable
- **Décorateur `@require_jwt`** pour protéger les routes
- **Gestion complète OIDC** : login, logout, callback, userinfo

### 🤖 Chatbot avec WrenAI OSS
- **Client WrenAI** pour appels API `/ask`
- **Transformation questions → SQL** en français
- **Gestion des threads** de conversation
- **Historique des conversations** par utilisateur
- **Endpoints complets** :
  - `POST /chatbot/query` : Traitement des questions
  - `GET /chatbot/history` : Historique des conversations

### 🏗️ Architecture Modulaire
```
/app
   /routes          # Endpoints REST
       auth_routes.py      # Authentification
       chatbot_routes.py   # Chatbot
   /services        # Logique métier
       auth_service.py     # Service d'auth
       chatbot_service.py  # Service chatbot
       wrenai_client.py    # Client WrenAI
   /tests           # Tests unitaires
       test_auth.py        # Tests auth
       test_chatbot.py     # Tests chatbot
```

### 🧪 Tests Unitaires
- **Tests complets** pour toutes les routes principales
- **Mocks** pour les services externes (Keycloak, WrenAI)
- **Configuration pytest** avec couverture
- **Tests d'intégration** Flask-OIDC

### ⚙️ Configuration
- **Variables d'environnement** centralisées
- **Support Keycloak** complet
- **Configuration Flask-OIDC** optimisée
- **Fichier client_secrets.json** pour Keycloak

## 📋 Endpoints API Disponibles

### Authentification
- `POST /auth/login` - Authentification directe
- `GET /auth/oidc/login` - Authentification OIDC
- `GET /auth/oidc/callback` - Callback OIDC
- `GET /auth/oidc/logout` - Déconnexion OIDC
- `GET /auth/oidc/userinfo` - Infos utilisateur OIDC
- `GET /auth/verify` - Vérification token JWT

### Chatbot
- `POST /chatbot/query` - Traitement questions
- `GET /chatbot/history` - Historique conversations

### Routes OIDC par défaut
- `/login` - Login OIDC
- `/authorize` - Autorisation OIDC
- `/logout` - Logout OIDC
- `/oidc_callback` - Callback OIDC

## 🚀 Installation et Lancement

### 1. Installation des dépendances
```bash
pip install -r requirements.txt
```

### 2. Configuration
```bash
cp env.example .env
# Éditer .env avec vos valeurs
```

### 3. Configuration Keycloak
- Créer un realm
- Créer un client OIDC
- Configurer `client_secrets.json`
- Créer des utilisateurs de test

### 4. Lancement
```bash
python main.py
```

## 🔧 Technologies Utilisées

- **Flask 2.3.3** - Framework web
- **Flask-OIDC 2.4.0** - Authentification OpenID Connect
- **Authlib 1.6.1** - Bibliothèque OAuth/OIDC
- **PyJWT 2.8.0** - Tokens JWT
- **Requests 2.31.0** - Appels HTTP
- **Pytest 7.4.2** - Tests unitaires
- **Python-dotenv 1.0.0** - Variables d'environnement

## 📚 Documentation

- **README.md** - Documentation complète
- **Docstrings** dans tous les fichiers
- **Exemples de payloads** dans les routes
- **Configuration Keycloak** détaillée

## 🎯 Fonctionnalités Clés

### ✅ Authentification Sécurisée
- Intégration complète Keycloak
- Tokens JWT avec expiration
- Protection des routes sensibles
- Gestion des erreurs d'auth

### ✅ Chatbot Intelligent
- Transformation questions → SQL
- Support multilingue (français)
- Gestion des conversations
- Historique utilisateur

### ✅ Architecture Robuste
- Séparation des responsabilités
- Services modulaires
- Gestion d'erreurs complète
- Logging détaillé

### ✅ Tests Complets
- Tests unitaires pour tous les endpoints
- Mocks pour services externes
- Configuration pytest optimisée

## 🔒 Sécurité

- **Authentification JWT** avec expiration
- **Intégration Keycloak** pour la gestion des utilisateurs
- **Validation des tokens** sur chaque requête protégée
- **Gestion sécurisée** des secrets via variables d'environnement
- **Protection CSRF** via Flask-OIDC
