# Reverse proxy avec authentification Keycloak complète
Cette configuration de reverse proxy assure une protection complète pour tous les services du réseau Docker `atexo_chatbot` en utilisant HAProxy avec authentification Keycloak. Elle met en œuvre un **routage basé sur les ports** pour l'architecture multi-services WrenAI.

## Aperçu de l'architecture
Le reverse proxy utilise un **routage basé sur les ports**, où chaque port correspond à un service spécifique de WrenAI (les service à protéger) :
- **Port 3000** → WrenAI UI (Interface Web)
- **Port 8000** → WrenAI AI Service (points de terminaison IA/ML)
- **Port 8001** → WrenAI Engine (service principal du moteur)
- **Port 8002** → WrenAI Ibis Server (points de terminaison du serveur Ibis)

## Configuration
### Variables d'environnement
Toute la configuration se fait via des variables d'environnement. Copiez `env.example` vers `.env` et personnalisez-le :
```bash
cp env.example .env
```

#### Configuration Keycloak
- `KEYCLOAK_URL` : URL du serveur Keycloak (par défaut : `http://keycloak:7080`)
- `KEYCLOAK_REALM` : Nom du realm Keycloak (par défaut : `atexo`)
- `KEYCLOAK_CLIENT_ID` : ID du client Keycloak (par défaut : `atexo-wrenai`)
- `KEYCLOAK_CLIENT_SECRET` : Secret du client Keycloak (optionnel)

#### Configuration HAProxy
- `HAPROXY_STATS_USER` : Nom d'utilisateur pour la page de statistiques HAProxy (par défaut : `admin`)
- `HAPROXY_STATS_PASSWORD` : Mot de passe pour la page de statistiques HAProxy (par défaut : `admin123`)
- `HAPROXY_MAX_CONNECTIONS` : Nombre maximum de connexions (par défaut : `4096`)

#### Paramètres de validation JWT
- `JWT_CACHE_DURATION` : Durée de cache de la clé publique en secondes (par défaut : `300`)
- `JWT_VALIDATION_ENABLED` : Activer/désactiver la validation JWT (par défaut : `true`)

#### Services backend
- `KEYCLOAK_SERVICE_HOST` : Nom d'hôte du service Keycloak (par défaut : `keycloak`)
- `KEYCLOAK_SERVICE_PORT` : Port du service Keycloak (par défaut : `7080`)

#### Architecture multi-services WrenAI
- `WREN_AI_SERVICE_PORT` : Port interne du service WrenAI AI (par défaut : `8080`)
- `WREN_ENGINE_PORT` : Port interne du moteur WrenAI (par défaut : `8081`)
- `IBIS_SERVER_PORT` : Port interne du serveur Ibis WrenAI (par défaut : `8082`)

#### Configuration réseau
- `PROXY_TRUSTED_ADDRESSES` : Plages d'adresses IP de confiance pour le proxy (par défaut : `172.16.0.0/12,192.168.0.0/16,10.0.0.0/8`)
- `PROXY_HEADERS_TYPE` : Type d'en-têtes proxy (par défaut : `xforwarded`)

#### Paramètres de sécurité
- `ALLOW_STATIC_RESOURCES` : Autoriser les ressources statiques sans authentification (par défaut : `true`)
- `ALLOW_AUTH_ENDPOINTS` : Autoriser les points de terminaison d'authentification sans authentification (par défaut : `true`)
- `STATIC_RESOURCE_PATHS` : Chemins considérés comme des ressources statiques (par défaut : `/_next,/static`)
- `AUTH_ENDPOINT_PATHS` : Chemins considérés comme des points de terminaison d'authentification (par défaut : `/api/auth,/realms,/resources,/admin`)

#### Journalisation
- `HAPROXY_LOG_LEVEL` : Niveau de journalisation HAProxy (par défaut : `info`)
- `JWT_LOG_LEVEL` : Niveau de journalisation de la validation JWT (par défaut : `info`)

## Routage basé sur les ports
### Ports des services et routage
| Port externe | Service | Service interne | Port interne | Objectif |
|---------------|---------|------------------|---------------|---------|
| 3000 | WrenAI UI | `atexo_wren_ui` | 3000 | Interface Web |
| 8000 | WrenAI AI Service | `atexo_wren_ai_service` | 8080 | Points de terminaison IA/ML |
| 8001 | WrenAI Engine | `atexo_wren_engine` | 8081 | Moteur principal |
| 8002 | WrenAI Ibis Server | `atexo_ibis_server` | 8082 | Serveur Ibis |
| 8404 | Statistiques HAProxy | - | - | Surveillance |

### Exemples de routage
- **UI Web** : `http://localhost:3000` → Achemine vers le service WrenAI UI
- **API IA** : `http://localhost:8000/api/chat` → Achemine vers le service WrenAI AI
- **API Moteur** : `http://localhost:8001/v1/query` → Achemine vers le moteur WrenAI
- **API Ibis** : `http://localhost:8002/sql` → Achemine vers le serveur Ibis WrenAI

## Modèle de sécurité
### Routes protégées (nécessitent un jeton JWT Bearer valide)
- **Toutes les routes sur tous les ports**, sauf celles explicitement listées comme non protégées ci-dessous
- **Approche par liste blanche** : Tout est protégé par défaut

### Routes non protégées (pas d'authentification requise)
- **Points de terminaison Keycloak** : `/realms/*`, `/resources/*`, `/admin/*`
- **Vérifications de santé** : `/health`
- **Points de terminaison d'authentification** : `/auth/*`
- **Ressources statiques** : `/_next/*`, `/static/*` (configurable via `STATIC_RESOURCE_PATHS`)
- **Chemins des points de terminaison d'authentification** : `/api/auth/*` (configurable via `AUTH_ENDPOINT_PATHS`)

### Validation JWT
Le script Lua valide les jetons JWT pour toutes les routes protégées. Les jetons invalides ou manquants renvoient **401 Non autorisé**.

## Utilisation
1. Copiez et personnalisez le fichier d'environnement :
```bash
cp env.example .env
# Modifiez .env avec vos paramètres
```
2. Démarrez les services :
```bash
docker build --tag 'atexo-haproxy' .
docker run --detach 'atexo-haproxy'
```
3. Accédez aux services via leurs ports respectifs :
   - **UI Web** : `http://localhost:3000`
   - **Service IA** : `http://localhost:8000`
   - **Moteur** : `http://localhost:8001`
   - **Serveur Ibis** : `http://localhost:8002`
   - **Statistiques HAProxy** : `http://localhost:8404`
4. Les requêtes non authentifiées vers les routes protégées renverront **401 Non autorisé**
5. Après avoir obtenu un jeton JWT valide de Keycloak, incluez-le dans l'en-tête Authorization :
   ```
   Authorization: Bearer <votre-jeton-jwt>
   ```

## Notes
- **Modèle de sécurité par liste blanche** : Toutes les routes sont protégées par défaut, sauf celles explicitement non protégées
- **Isolation par port** : Chaque service est isolé sur son propre port avec un frontend/backend dédié
- **Validation JWT** : Le reverse proxy valide les jetons JWT avant de transmettre les requêtes à un backend
- **En-têtes proxy** : Correctement configurés pour Keycloak selon la [documentation Keycloak](https://www.keycloak.org/server/reverseproxy)
- **Proxys de confiance** : Les adresses de proxy de confiance sont configurées pour la sécurité
- **Mode développement** : La validation JWT peut être désactivée pour le développement/test via `JWT_VALIDATION_ENABLED=false`
