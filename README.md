# Atexo Backend - Docker Compose Principal

Ce docker-compose principal orchestre tous les services de l'application Atexo en un seul déploiement.

## Services inclus

- **Flask Backend** (port 5000) - API principale de l'application
- **Keycloak** (ports 7080, 7443) - Service d'authentification et d'autorisation
- **HAProxy** (ports 3000, 8000, 8001, 8002, 8404) - Reverse proxy et load balancer
- **WrenAI Services** - Suite complète de services d'IA :
  - Wren Bootstrap
  - Wren Engine (port 8001)
  - Wren AI Service (port 8000)
  - Wren UI (port 3000)
  - Ibis Server (port 8002)
  - Qdrant (base de données vectorielle)

## Prérequis

- Docker et Docker Compose installés
- Au moins 8GB de RAM disponible
- 10GB d'espace disque libre

## Configuration

1. Copiez le fichier d'environnement :
   ```bash
   cp env.example .env
   ```

2. Modifiez le fichier `.env` selon vos besoins :
   - Ajustez les versions des images WrenAI
   - Configurez les ports si nécessaire
   - Définissez vos clés API pour les services externes

3. Assurez-vous que les fichiers de configuration suivants existent :
   - `./wrenai/config.yaml`
   - `./wrenai/.env`
   - `./reverse-proxy/.env`

## Déploiement

### Démarrage
```bash
docker-compose up -d
```

## Ordre de démarrage

Les services démarrent dans l'ordre suivant pour respecter les dépendances :

1. **Keycloak** - Service d'authentification
2. **WrenAI Bootstrap** - Initialisation des données
3. **Qdrant** - Base de données vectorielle
4. **WrenAI Engine** - Moteur principal
5. **Ibis Server** - Serveur de requêtes
6. **WrenAI AI Service** - Service d'IA
7. **WrenAI UI** - Interface utilisateur
8. **Flask App** - API backend
9. **HAProxy** - Reverse proxy

## Dépannage

### Problèmes courants

1. **Ports déjà utilisés** : Vérifiez qu'aucun autre service n'utilise les ports 3000, 5000, 7080, 8000, 8001, 8002, 8404

2. **Mémoire insuffisante** : Augmentez la mémoire allouée à Docker

3. **Problèmes de permissions** : Assurez-vous que les dossiers `./wrenai/data` et `./flask` ont les bonnes permissions

4. **Services qui ne démarrent pas** : Consultez les logs avec `docker-compose logs [service-name]`

### Redémarrage d'un service spécifique
```bash
docker-compose restart [service-name]
```

### Reconstruction d'un service
```bash
docker-compose build [service-name]
docker-compose up -d [service-name]
```

## Tests

### Test de l'authentification

Un script de test est fourni pour vérifier le fonctionnement de l'authentification :

```bash
# Test avec authentification activée
python test_auth.py

# Test avec authentification désactivée
AUTH_ENABLED=false docker-compose up -d flask-app
python test_auth.py
```

### Test manuel des endpoints

```bash
# Vérifier le statut d'authentification
curl http://localhost:5000/auth/status

# Test endpoint sans authentification
curl http://localhost:5000/chatbot/test

# Test endpoint avec authentification (requiert un token)
curl -X POST http://localhost:5000/chatbot/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"question": "Test question"}'
```

### Désactiver l'authentification

Pour désactiver l'authentification Flask (mode développement/test) :

```bash
# Dans le fichier .env
AUTH_ENABLED=false
```