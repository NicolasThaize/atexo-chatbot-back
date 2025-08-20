# Backend de Chatbot Flask
### Fonctionnement global
- Application Flask structurée en blueprints : `auth` (authentification) et `chatbot` (questions / historique).
- Auth via Keycloak. Les routes protégées exigent `Authorization: Bearer <token>`.
- CORS autorise `http://localhost:4200` (frontend Angular). API par défaut : `http://localhost:5000`.

### Endpoints

#### Auth (`/auth`)
- POST `/auth/login`
  - JSON : `{ "username": "...", "password": "..." }`
  - 200 : `{ "token", "refresh_token", "expires_in", "user" }`
- GET `/auth/verify` (protégé)
  - Vérifie le JWT.
  - 200 : `{ "valid": true, "user": { "username", "email" } }`
- POST `/auth/refresh`
  - JSON : `{ "grant_type": "refresh_token", "refresh_token": "...", "client_id": "..." }`
  - 200 : `{ "access_token", "refresh_token", "expires_in", "token_type": "Bearer" }`
- GET `/auth/status`
  - 200 : `{ "auth_enabled": true|false, "message": "..." }`

#### Chatbot (`/chatbot`)
- POST `/chatbot/query` (protégé)
  - JSON : `{ "question": "...", "threadId": "optionnel" }`
  - 200 : `{ "threadId", "sql", "results", "summary", "explanation" }`
- GET `/chatbot/history?limit=10` (protégé)
  - 200 : `{ "conversations": [ { "threadId", "question", "timestamp", "summary" } ] }`
- GET `/chatbot/test`
  - Non protégé. 200 : `{ "message", "auth_enabled", "timestamp" }`


## Configuration de l'authentification
Cette application Flask prend en charge les jetons JWT HS256 et RS256 avec détection automatique de l'algorithme et récupération de la clé publique depuis Keycloak.

### Fonctionnalités
- **Détection automatique de l'algorithme du jeton** : Le service détecte automatiquement si un jeton utilise RS256 ou HS256
- **Récupération automatique de la clé publique** : Pour les jetons RS256, le service peut automatiquement récupérer la clé publique depuis le point de terminaison JWKS de Keycloak
- **Configuration flexible** : Prend en charge la configuration manuelle de la clé publique et la récupération automatique
- **Débogage complet** : Journalisation étendue pour un dépannage facile

### Configuration
#### Variables d'environnement
Créez un fichier `.env` dans le répertoire `flask` `cp env.example .env` et remplacer le contenu des variables :
```bash
FLASK_DEBUG=False #

# Configuration WrenAI OSS
WRENAI_BASE_URL=http://localhost:8080
WRENAI_API_KEY=votre-clé-api-wrenai
# Configuration Keycloak
KEYCLOAK_REALM=votre-realm
KEYCLOAK_CLIENT_ID=votre-id-client
KEYCLOAK_CLIENT_SECRET=votre-secret-client
KEYCLOAK_SERVER_URL=http://localhost:7080 

JWT_SECRET_KEY=clé-secrète-jwt
JWT_PUBLIC_KEY=  # Optionnel : Laissez vide pour une récupération automatique depuis Keycloak, ou fournissez une clé publique au format PEM
JWT_ALGORITHM=HS256  # Algorithme par défaut (sera remplacé par la détection du jeton)

AUTH_ENABLED=True # Active la protection des endpoints de l'API via tokens JWT fournis par Keycloak
```

#### Options de configuration JWT
1. **HS256 (Symétrique)** : Utilisez une clé secrète simple
   ```bash
   JWT_ALGORITHM=HS256
   JWT_SECRET_KEY=votre-super-clé-secrète-d'au-moins-32-caractères
   JWT_PUBLIC_KEY=  # Laissez vide pour HS256
   ```

2. **RS256 (Asymétrique)** : Utilisez une clé publique RSA
   ```bash
   JWT_ALGORITHM=RS256
   JWT_SECRET_KEY=clé-secrète-jwt  # Non utilisée pour la vérification RS256
   JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
   -----END PUBLIC KEY-----
   ```

3. **RS256 avec récupération automatique** : Laissez le service récupérer la clé publique depuis Keycloak
   ```bash
   JWT_ALGORITHM=RS256
   JWT_SECRET_KEY=clé-secrète-jwt
   JWT_PUBLIC_KEY=  # Laissez vide pour une récupération automatique depuis Keycloak
   ```

### Fonctionnement
1. **Détection de l'algorithme du jeton** : Lorsqu'un jeton est reçu, le service lit d'abord l'en-tête JWT pour déterminer l'algorithme (RS256 ou HS256)
2. **Traitement RS256** :
   - Si `JWT_PUBLIC_KEY` est fourni dans la configuration, l'utiliser
   - Si `JWT_PUBLIC_KEY` est vide, récupérer automatiquement depuis le point de terminaison JWKS de Keycloak
   - Convertir JWK en format PEM si nécessaire
   - Vérifier le jeton avec la clé publique
3. **Traitement HS256** :
   - Utiliser la `JWT_SECRET_KEY` pour la vérification
   - Vérification simple avec une clé symétrique
