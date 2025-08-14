# Atexo Backend - Docker Compose Principal

Ce docker compose principal orchestre tous les services de l'application Atexo en un seul déploiement.

## Services inclus

  - **Flask Backend** (port 5000) - API principale de l'application
  - **Keycloak** (ports 7080, 7443) - Service d'authentification et d'autorisation. Le déploiement de ce service est désactivable en utilisant le Mode 1. 
  - **HAProxy** (ports 3000, 8000, 8001, 8002, 8404) - Reverse proxy (authentification sur les services de Wrenai)
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

  2. Modifiez le fichier `.env` selon vos besoins
  ```
  KEYCLOAK_REALM=atexo
  KEYCLOAK_CLIENT_ID=atexo-wrenai
  KEYCLOAK_CLIENT_SECRET=Secret du client KEYCLOAK_CLIENT_ID
  KEYCLOAK_SERVER_URL=Url du serveur keycloak à utiliser
  MISTRAL_API_KEY=Mistral Api key
  LOCAL_AUTH_ENABLED=Si docker doit déployer un keycloak (environnement de développement)
  ```
## Déploiement

### Modes de déploiement

#### Mode 1 : Sans Keycloak local (par défaut)
  ```bash
  # Utilise uniquement docker-compose.yml
  docker compose -f docker-compose.yml up -d
  docker cp db.sqlite3 atexo_wren_bootstrap:/app/data/db.sqlite3
  ```
  L'interface web du chatbot est accessible sur http://localhost:4200/.


#### Mode 2 : Avec Keycloak déployé en local (environnemnt de développement)
  L'application utilise une architecture flexible permettant de déployer Keycloak de manière conditionnelle.
  - **`docker-compose.yml`** : Configuration de base sans Keycloak
    - Flask Backend avec authentification activée (utilise une instance Keycloak externe, bien penser à mettre à jour les variables du `.env`)
    - HAProxy avec authentification activée
    - Tous les services WrenAI

  - **`docker-compose.override.yml`** : Ajoute Keycloak local et ses dépendances
    - Service Keycloak complet
    - Dépendances Flask et HAProxy vers Keycloak local


  ```bash
  # Utilise docker-compose.yml + docker-compose.override.yml
  docker compose -f docker-compose.yml -f docker-compose.override.yml up -d
  docker cp db.sqlite3 atexo_wren_bootstrap:/app/data/db.sqlite3
  docker exec -it atexo_keycloak bash -c "cd /opt/keycloak/bin && ./kcadm.sh config credentials --server http://localhost:7080 --realm master --user admin && ./kcadm.sh update realms/master -s sslRequired=NONE" # Entrer le mot de passe `admin` lorsque demandé
  ```

##### Configuration Keycloak (lorsque le Mode 2 est utilisé)

  > **Note :** Ces étapes simplifient l'accès à la version locale du chatbot. En production, utilisez le Mode 1.

###### 1. Accès à l'interface Keycloak
  - Ouvrir http://localhost:7080/ dans votre navigateur
  - S'authentifier avec : `admin` / `admin`

###### 2. Création du realm
  - Cliquer sur **Manage realms** → **Create realm** ![1](assets/1.png)
  - Nommer le realm : `atexo` ![2](assets/2.png)

###### 3. Configuration du client
- Cliquer sur **Clients** → **Create client** ![3](assets/3.png)
- Nommer le client : `atexo-wrenai` ![4](assets/4.png)
- Cocher les options suivantes :
  - ✅ Client authentification
  - ✅ Standard flow  
  - ✅ Direct access grants ![5](assets/5.png)
- Dans **Valid redirect URIs** : `http://localhost/*`
- Dans **Web origins** : `http://localhost`![6](assets/6.png)
- Sauvegarder

###### 4. Création d'un utilisateur
  - Cliquer sur **Users** → **Create new user** ![7](assets/7.png)
  - Renseigner le nom d'utilisateur souhaité ![8](assets/8.png)
  - Cliquer sur **Credentials** → **Set password** ![9](assets/9.png)
  - Définir le mot de passe souhaité
  - Sauvegarder

###### 5. Configuration de l'authentification
  - Cliquer sur **Authentication** 
  - Décocher toutes les cases bleues **Enabled** ![10](assets/10.png)

###### 6. Récupération du secret client
  - Cliquer sur **Clients** → **atexo-wrenai** → **Credentials**
  - Copier le **Client Secret** ![11](assets/11.png)
  - Coller dans le fichier `.env` : `KEYCLOAK_CLIENT_SECRET=votre_secret`

###### 7. Redémarrage des services
  ```bash
  docker compose build flask-app haproxy
  docker compose -f docker-compose.yml -f docker-compose.override.yml up -d
  ```