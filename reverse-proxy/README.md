# Reverse Proxy with Comprehensive Keycloak Authentication

This reverse proxy setup provides comprehensive protection for all services in the `atexo_chatbot` docker network using HAProxy with Keycloak authentication. It implements **port-based routing** for the multi-service WrenAI architecture.

## Architecture Overview

The reverse proxy uses **port-based routing** where each port maps to a specific WrenAI service:

- **Port 3000** → WrenAI UI (Web Interface)
- **Port 8000** → WrenAI AI Service (AI/ML endpoints)
- **Port 8001** → WrenAI Engine (Core engine service)
- **Port 8002** → WrenAI Ibis Server (Ibis server endpoints)

## Configuration

### Environment Variables

All configuration is done through environment variables. Copy `env.example` to `.env` and customize:

```bash
cp env.example .env
```

#### Keycloak Configuration
- `KEYCLOAK_URL`: Keycloak server URL (default: `http://keycloak:7080`)
- `KEYCLOAK_REALM`: Keycloak realm name (default: `atexo`)
- `KEYCLOAK_CLIENT_ID`: Keycloak client ID (default: `atexo-wrenai`)
- `KEYCLOAK_CLIENT_SECRET`: Keycloak client secret (optional)

#### HAProxy Configuration
- `HAPROXY_STATS_USER`: Username for HAProxy stats page (default: `admin`)
- `HAPROXY_STATS_PASSWORD`: Password for HAProxy stats page (default: `admin123`)
- `HAPROXY_MAX_CONNECTIONS`: Maximum connections (default: `4096`)

#### JWT Validation Settings
- `JWT_CACHE_DURATION`: Public key cache duration in seconds (default: `300`)
- `JWT_VALIDATION_ENABLED`: Enable/disable JWT validation (default: `true`)

#### Backend Services
- `KEYCLOAK_SERVICE_HOST`: Keycloak service hostname (default: `keycloak`)
- `KEYCLOAK_SERVICE_PORT`: Keycloak service port (default: `7080`)

#### WrenAI Multi-Service Architecture
- `WREN_AI_SERVICE_PORT`: WrenAI AI Service internal port (default: `8080`)
- `WREN_ENGINE_PORT`: WrenAI Engine internal port (default: `8081`)
- `IBIS_SERVER_PORT`: WrenAI Ibis Server internal port (default: `8082`)

#### Network Configuration
- `PROXY_TRUSTED_ADDRESSES`: Trusted proxy IP ranges (default: `172.16.0.0/12,192.168.0.0/16,10.0.0.0/8`)
- `PROXY_HEADERS_TYPE`: Proxy headers type (default: `xforwarded`)

#### Security Settings
- `ALLOW_STATIC_RESOURCES`: Allow static resources without auth (default: `true`)
- `ALLOW_AUTH_ENDPOINTS`: Allow auth endpoints without auth (default: `true`)
- `STATIC_RESOURCE_PATHS`: Paths considered static resources (default: `/_next,/static`)
- `AUTH_ENDPOINT_PATHS`: Paths considered auth endpoints (default: `/api/auth,/realms,/resources,/admin`)

#### Logging
- `HAPROXY_LOG_LEVEL`: HAProxy log level (default: `info`)
- `JWT_LOG_LEVEL`: JWT validation log level (default: `info`)

### Keycloak Setup

1. Start the services:
```bash
docker-compose up -d
```

2. Access Keycloak admin console at `http://localhost:7080`
   - Username: `admin`
   - Password: `admin`

3. Create a new realm called `atexo` (or match your `KEYCLOAK_REALM` setting)

4. Create a new client:
   - Client ID: `atexo-wrenai` (or match your `KEYCLOAK_CLIENT_ID` setting)
   - Client Protocol: `openid-connect`
   - Access Type: `public`
   - Valid Redirect URIs: `http://localhost/*`
   - Web Origins: `http://localhost`

5. Create users in the realm for testing

## Port-Based Routing

### Service Ports and Routing

| External Port | Service | Internal Service | Internal Port | Purpose |
|---------------|---------|------------------|---------------|---------|
| 3000 | WrenAI UI | `atexo_wren_ui` | 3000 | Web interface |
| 8000 | WrenAI AI Service | `atexo_wren_ai_service` | 8080 | AI/ML endpoints |
| 8001 | WrenAI Engine | `atexo_wren_engine` | 8081 | Core engine |
| 8002 | WrenAI Ibis Server | `atexo_ibis_server` | 8082 | Ibis server |
| 8404 | HAProxy Stats | - | - | Monitoring |

### Routing Examples

- **Web UI**: `http://localhost:3000` → Routes to WrenAI UI service
- **AI API**: `http://localhost:8000/api/chat` → Routes to WrenAI AI Service
- **Engine API**: `http://localhost:8001/v1/query` → Routes to WrenAI Engine
- **Ibis API**: `http://localhost:8002/sql` → Routes to WrenAI Ibis Server

## Security Model

### Protected Routes (Require Valid JWT Bearer Token)
- **All routes on all ports** except those explicitly listed as unprotected below
- **Whitelist approach**: Everything is protected by default

### Unprotected Routes (No Authentication Required)
- **Keycloak endpoints**: `/realms/*`, `/resources/*`, `/admin/*`
- **Health checks**: `/health`
- **Auth endpoints**: `/auth/*`
- **Static resources**: `/_next/*`, `/static/*` (configurable via `STATIC_RESOURCE_PATHS`)
- **Auth endpoint paths**: `/api/auth/*` (configurable via `AUTH_ENDPOINT_PATHS`)

### JWT Validation

The Lua script validates JWT tokens for all protected routes. Invalid or missing tokens return **401 Unauthorized**.

## Usage

1. Copy and customize the environment file:
```bash
cp env.example .env
# Edit .env with your settings
```

2. Start the services:
```bash
docker-compose up -d
```

3. Access services through their respective ports:
   - **Web UI**: `http://localhost:3000`
   - **AI Service**: `http://localhost:8000`
   - **Engine**: `http://localhost:8001`
   - **Ibis Server**: `http://localhost:8002`
   - **HAProxy Stats**: `http://localhost:8404`

4. Unauthenticated requests to protected routes will return **401 Unauthorized**

5. After obtaining a valid JWT token from Keycloak, include it in the Authorization header:
   ```
   Authorization: Bearer <your-jwt-token>
   ```

## Security Notes

- **Whitelist Security Model**: All routes are protected by default except explicitly unprotected ones
- **Port-Based Isolation**: Each service is isolated on its own port with dedicated frontend/backend
- **JWT Validation**: The reverse proxy validates JWT tokens before forwarding requests to any backend
- **Static Resources**: Static resources and auth endpoints are excluded from authentication to allow proper functioning
- **Proxy Headers**: Properly configured for Keycloak as per the [Keycloak documentation](https://www.keycloak.org/server/reverseproxy)
- **Trusted Proxies**: Trusted proxy addresses are configured for security
- **Development Mode**: JWT validation can be disabled for development/testing via `JWT_VALIDATION_ENABLED=false`

## Troubleshooting

### Common Issues

1. **Service not accessible**: Ensure the target WrenAI service is running and healthy
2. **401 Unauthorized**: Verify JWT token is valid and properly formatted
3. **Port conflicts**: Check that the external ports (3000, 8000, 8001, 8002) are not in use
4. **Keycloak connection**: Verify Keycloak is running and accessible at the configured URL

### Monitoring

- **HAProxy Stats**: Access `http://localhost:8404` for real-time monitoring
- **Logs**: Check container logs for detailed error information
- **Health Checks**: Each backend includes health checks for service availability
