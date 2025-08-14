export const environment = {
  production: true,
  // Configuration du backend (à adapter selon votre environnement de production)
  apiUrl: 'https://your-production-backend.com',
  // Configuration Keycloak (à adapter selon votre environnement de production)
  keycloak: {
    clientId: 'atexo-chatbot-client',
    realm: 'atexo-realm',
    authServerUrl: 'https://your-keycloak-server.com/auth'
  }
};
