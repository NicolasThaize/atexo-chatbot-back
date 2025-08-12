# Flask Chatbot Backend

## Authentication Setup

This Flask application supports both HS256 and RS256 JWT tokens with automatic algorithm detection and public key fetching from Keycloak.

### Features

- **Automatic Token Algorithm Detection**: The service automatically detects whether a token uses RS256 or HS256
- **Auto-Fetch Public Key**: For RS256 tokens, the service can automatically fetch the public key from Keycloak's JWKS endpoint
- **Flexible Configuration**: Supports both manual public key configuration and automatic fetching
- **Comprehensive Debugging**: Extensive logging for easy troubleshooting

### Configuration

#### Environment Variables

Create a `.env` file in the `flask` directory:

```bash
# Configuration Flask
SECRET_KEY=your-secret-key-change-in-production
FLASK_DEBUG=False

# Configuration WrenAI OSS
WRENAI_BASE_URL=http://localhost:8080
WRENAI_API_KEY=your-wrenai-api-key

# Configuration Keycloak
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-client-id
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_SERVER_URL=http://localhost:7080

# Configuration JWT
JWT_SECRET_KEY=jwt-secret-key
JWT_PUBLIC_KEY=  # Optional: Leave empty to auto-fetch from Keycloak, or provide PEM-formatted public key
JWT_ALGORITHM=HS256  # Default algorithm (will be overridden by token detection)

# Configuration d'authentification
AUTH_ENABLED=True
```

#### JWT Configuration Options

1. **HS256 (Symmetric)**: Use a simple secret key
   ```bash
   JWT_ALGORITHM=HS256
   JWT_SECRET_KEY=your-super-secret-key-at-least-32-chars-long
   JWT_PUBLIC_KEY=  # Leave empty for HS256
   ```

2. **RS256 (Asymmetric)**: Use RSA public key
   ```bash
   JWT_ALGORITHM=RS256
   JWT_SECRET_KEY=jwt-secret-key  # Not used for RS256 verification
   JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
   -----END PUBLIC KEY-----
   ```

3. **RS256 with Auto-Fetch**: Let the service fetch the public key from Keycloak
   ```bash
   JWT_ALGORITHM=RS256
   JWT_SECRET_KEY=jwt-secret-key
   JWT_PUBLIC_KEY=  # Leave empty to auto-fetch from Keycloak
   ```

### How It Works

1. **Token Algorithm Detection**: When a token is received, the service first reads the JWT header to determine the algorithm (RS256 or HS256)

2. **RS256 Processing**:
   - If `JWT_PUBLIC_KEY` is provided in config, use it
   - If `JWT_PUBLIC_KEY` is empty, automatically fetch from Keycloak's JWKS endpoint
   - Convert JWK to PEM format if needed
   - Verify token with the public key

3. **HS256 Processing**:
   - Use the `JWT_SECRET_KEY` for verification
   - Simple symmetric key verification

### Testing

Run the test script to verify your Keycloak setup:

```bash
cd flask
python test_keycloak_connection.py
```

This will test:
- Keycloak connectivity
- JWKS endpoint access
- Public key fetching and conversion
- AuthService functionality

### Debugging

The service provides extensive logging for debugging:

- Token algorithm detection
- Public key fetching process
- JWK to PEM conversion
- Token verification steps
- Error details with full tracebacks

Check the logs to see exactly what's happening during token verification.

### Keycloak Setup

Make sure your Keycloak instance is running and accessible:

```bash
cd keycloak
docker-compose up -d
```

The service will automatically work with Keycloak's default RS256 tokens without any additional configuration needed.
