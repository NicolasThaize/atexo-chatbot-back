# Atexo Chatbot - Application Frontend

## Description

Application Angular moderne pour l'interface utilisateur du chatbot Atexo. Cette application permet aux utilisateurs de s'authentifier via Keycloak et d'interagir avec un chatbot intelligent basé sur WrenAI, capable de traiter des requêtes en langage naturel et de retourner des réponses en français, incluant des résultats SQL formatés.

## Architecture

### Structure de l'Application

```
src/
├── app/
│   ├── components/
│   │   ├── login/          # Page de connexion
│   │   └── chat/           # Interface de chat
│   ├── services/
│   │   ├── auth.service.ts # Service d'authentification
│   │   └── chat.service.ts # Service de communication avec WrenAI
│   ├── guards/
│   │   └── auth.guard.ts   # Protection des routes
│   ├── app.component.ts    # Composant principal
│   ├── app.module.ts       # Module principal
│   └── app-routing.module.ts # Configuration des routes
├── environments/
│   ├── environment.ts      # Configuration développement
│   └── environment.prod.ts # Configuration production
```

### Composants Principaux

#### 1. Page de Connexion (`LoginComponent`)
- **Fonctionnalités** :
  - Authentification via Keycloak
  - Gestion des formulaires avec validation
  - Redirection automatique après connexion
  - Gestion des erreurs d'authentification
- **Technologies** : Angular Reactive Forms, Material Design

#### 2. Page de Chat (`ChatComponent`)
- **Fonctionnalités** :
  - Interface de chat en temps réel
  - Gestion du contexte de conversation avec threadId
  - Affichage dynamique des messages
  - Support des requêtes SQL et réponses en langage naturel
  - Affichage formaté du SQL généré
  - Gestion des erreurs et questions non-SQL
- **Technologies** : Angular Material, RxJS, WrenAI API

### Services

#### 1. Service d'Authentification (`AuthService`)
- Gestion des tokens JWT
- Intégration avec Keycloak
- Stockage sécurisé des informations utilisateur
- Rafraîchissement automatique des tokens

#### 2. Service de Chat (`ChatService`)
- Communication HTTP avec l'API WrenAI
- Gestion du threadId pour maintenir le contexte de conversation
- Gestion des requêtes et réponses
- Gestion des erreurs réseau et SQL

### Sécurité

#### Guard d'Authentification (`AuthGuard`)
- Protection des routes sensibles
- Vérification automatique de l'authentification
- Redirection vers la page de connexion si nécessaire

## Intégration WrenAI

L'application utilise l'API WrenAI pour traiter les questions en langage naturel et générer des requêtes SQL. Selon la [documentation WrenAI](https://wrenai.readme.io/reference/post_ask), l'endpoint `/api/v1/ask` :

1. **Convertit** les questions en langage naturel en SQL
2. **Exécute** automatiquement les requêtes SQL
3. **Résume** les résultats en français
4. **Maintient** le contexte de conversation via threadId

### Types de Réponses Supportées

- **Requêtes SQL** : Génération et exécution automatique
- **Questions non-SQL** : Réponses explicatives
- **Erreurs SQL** : Affichage des erreurs avec le SQL généré
- **Conversation continue** : Maintien du contexte via threadId

## Configuration

### Variables d'Environnement

L'application utilise des variables d'environnement pour la configuration :

#### Développement (`src/environments/environment.ts`)
```typescript
export const environment = {
  production: false,
  apiUrl: 'http://localhost:8080',
  keycloak: {
    clientId: 'atexo-chatbot-client',
    realm: 'atexo-realm',
    authServerUrl: 'http://localhost:8081/auth'
  }
};
```

#### Production (`src/environments/environment.prod.ts`)
```typescript
export const environment = {
  production: true,
  apiUrl: 'https://your-production-backend.com',
  keycloak: {
    clientId: 'atexo-chatbot-client',
    realm: 'atexo-realm',
    authServerUrl: 'https://your-keycloak-server.com/auth'
  }
};
```

## Installation et Configuration

### Prérequis

- Node.js (version 16 ou supérieure)
- Angular CLI (version 13 ou supérieure)
- Backend WrenAI en cours d'exécution
- Instance Keycloak configurée

### Installation

1. **Cloner le repository**
   ```bash
   git clone <repository-url>
   cd atexo-chatbot-stagiaires
   ```

2. **Installer les dépendances**
   ```bash
   npm install
   ```

3. **Configuration des variables d'environnement**
   - Modifier `src/environments/environment.ts` pour le développement
   - Modifier `src/environments/environment.prod.ts` pour la production
   - Adapter les URLs selon votre infrastructure

### Démarrage

```bash
# Développement
ng serve

# Production
ng build --prod
```

L'application sera accessible sur `http://localhost:4200`

## Fonctionnalités

### Authentification
- Connexion sécurisée via Keycloak
- Gestion des tokens JWT
- Déconnexion automatique
- Protection des routes

### Interface de Chat
- **Conversation continue** : Maintien du contexte via threadId
- **Interface responsive** : Adaptation mobile et desktop
- **Messages en temps réel** : Affichage instantané des messages
- **Affichage SQL** : Code SQL formaté et coloré
- **Gestion d'erreurs** : Affichage clair des erreurs SQL
- **Nouvelle conversation** : Bouton pour démarrer une nouvelle session

### Gestion du Contexte
- **ThreadId automatique** : Généré automatiquement par WrenAI
- **Conversation persistante** : Le chatbot garde trace de l'historique
- **Questions de suivi** : Possibilité de poser des questions relatives aux réponses précédentes
- **Nouvelle session** : Possibilité de démarrer une nouvelle conversation

## API Endpoints

### Authentification
- `POST /auth/login` - Connexion utilisateur
- `POST /auth/refresh` - Rafraîchissement du token

### Chat (WrenAI)
- `POST /api/v1/ask` - Envoi d'une question avec gestion du threadId

## Technologies Utilisées

### Frontend
- **Angular 13** : Framework principal
- **Angular Material** : Composants UI
- **RxJS** : Gestion des observables
- **TypeScript** : Langage de programmation

### Backend Integration
- **WrenAI API** : Traitement des questions en langage naturel
- **SQL Generation** : Génération automatique de requêtes SQL
- **Thread Management** : Gestion du contexte de conversation

### Styling
- **CSS3** : Styles personnalisés
- **Flexbox/Grid** : Layout responsive
- **Material Design** : Design system

### Outils de Développement
- **Angular CLI** : Outils de développement
- **Karma/Jasmine** : Tests unitaires
- **ESLint** : Linting du code

## Structure des Données

### Interface User
```typescript
interface User {
  id: string;
  username: string;
  email: string;
  roles: string[];
  exp?: number;
}
```

### Interface ChatMessage
```typescript
interface ChatMessage {
  id?: string;
  content: string;
  timestamp: Date;
  isUser: boolean;
}
```

### Interface ChatResponse (WrenAI)
```typescript
interface ChatResponse {
  id: string;
  sql?: string;
  summary?: string;
  type?: string;
  explanation?: string;
  error?: string;
  invalidSql?: string;
  threadId: string;
}
```

### Interface ChatRequest
```typescript
interface ChatRequest {
  question: string;
  threadId?: string;
}
```

## Exemples d'Utilisation

### Question Simple
```
Utilisateur: "Liste les 5 clients les plus importants"
Bot: Génère et exécute le SQL, affiche le résumé en français
```

### Question de Suivi
```
Utilisateur: "Montre-moi les 3 premiers à la place"
Bot: Utilise le threadId pour maintenir le contexte et modifier la requête
```

### Question Non-SQL
```
Utilisateur: "Bonjour"
Bot: Répond avec une explication sur ses capacités
```

## Déploiement

### Build de Production
```bash
ng build --configuration production
```

### Serveur Web
L'application peut être déployée sur n'importe quel serveur web statique :
- Nginx
- Apache
- Serveurs cloud (AWS S3, Azure Blob Storage, etc.)

## Maintenance et Support

### Logs
- Les erreurs sont loggées dans la console du navigateur
- Utiliser les outils de développement pour le debugging

### Performance
- Optimisation des bundles
- Compression des assets
- Gestion efficace du contexte de conversation

### Sécurité
- Validation côté client et serveur
- Protection CSRF
- Headers de sécurité appropriés
- Gestion sécurisée des tokens JWT

## Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit les changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## Licence

Ce projet est sous licence [MIT](LICENSE).

## Contact

Pour toute question ou support, contactez l'équipe de développement Atexo.
