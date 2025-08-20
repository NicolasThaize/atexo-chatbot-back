## Service
- `wren-engine`: le service moteur. Consultez un exemple ici: [wren-engine/example](https://github.com/Canner/wren-engine/tree/main/example)
- `wren-ai-service`: le service IA.
- `qdrant`: le service de stockage vectoriel utilisé par le service IA.
- `wren-ui`: le service UI.
- `bootstrap`: place les fichiers requis dans le volume pour le service moteur.

## Volume
Données partagées via le volume `data`.
Structure des chemins :
- `/mdl`
  - `*.json` (le fichier `sample.json` sera placé pendant le bootstrap)
- `accounts`
- `config.properties`

## Comment démarrer avec MistralAI
1. Copiez `.env.example` vers `.env` et modifiez la clé API MistralAI `MISTRAL_API_KEY`.
2. Copiez `config.example.yaml` vers `config.yaml` pour la configuration du service IA, vous pourrez modifier d'ici le modèle génératif et d'embedding que WrenAI utilisera.
3. Démarrez tous les services: ``docker-compose --env-file .env up -d``.
4. Arrêtez tous les services: ``docker-compose --env-file .env down``.

### Optionnel
- Si votre port 3000 est occupé, vous pouvez modifier `HOST_PORT` dans `.env`.