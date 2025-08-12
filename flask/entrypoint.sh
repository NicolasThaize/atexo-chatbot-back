#!/bin/bash
set -e

# Generate client_secrets.json from environment variables
cat > ./client_secrets.json << EOF
{
  "web": {
    "client_id": "${KEYCLOAK_CLIENT_ID}",
    "client_secret": "${KEYCLOAK_CLIENT_SECRET}",
    "auth_uri": "${KEYCLOAK_SERVER_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth",
    "token_uri": "${KEYCLOAK_SERVER_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token",
    "userinfo_uri": "${KEYCLOAK_SERVER_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo",
    "issuer": "${KEYCLOAK_SERVER_URL}/realms/${KEYCLOAK_REALM}",
    "redirect_uris": ["http://localhost:5000/authorize"]
  }
}
EOF

echo "Generated client_secrets.json"

# Start the Flask application
exec python main.py