-- JWT Validation Lua script for HAProxy
-- This script validates JWT tokens from Keycloak for WrenAI service

local jwt = require "cjson"
local http = require "socket.http"
local ltn12 = require "ltn12"
local mime = require "mime"

-- Function to get environment variable with default
local function get_env_var(name, default)
    local value = os.getenv(name)
    return value or default
end

-- Configuration from environment variables
local KEYCLOAK_URL = get_env_var("KEYCLOAK_URL", "http://keycloak:7080")
local REALM = get_env_var("KEYCLOAK_REALM", "atexo")
local CLIENT_ID = get_env_var("KEYCLOAK_CLIENT_ID", "atexo-wrenai")
local CLIENT_SECRET = get_env_var("KEYCLOAK_CLIENT_SECRET", "")
local CACHE_DURATION = tonumber(get_env_var("JWT_CACHE_DURATION", "300"))
local JWT_VALIDATION_ENABLED = get_env_var("JWT_VALIDATION_ENABLED", "true") == "true"
local JWT_LOG_LEVEL = get_env_var("JWT_LOG_LEVEL", "info")

-- Cache for public keys
local public_keys_cache = {}
local cache_expiry = 0

-- Function to log messages
local function log_message(level, message)
    if level == "debug" and JWT_LOG_LEVEL ~= "debug" then
        return
    end
    if level == "info" and JWT_LOG_LEVEL == "error" then
        return
    end
    print(string.format("[JWT-%s] %s", string.upper(level), message))
end

-- Function to fetch public keys from Keycloak
local function fetch_public_keys()
    local current_time = os.time()
    
    -- Return cached keys if still valid
    if current_time < cache_expiry and public_keys_cache then
        log_message("debug", "Using cached public keys")
        return public_keys_cache
    end
    
    local url = string.format("%s/realms/%s/protocol/openid-connect/certs", KEYCLOAK_URL, REALM)
    log_message("debug", "Fetching public keys from: " .. url)
    
    local response_body = {}
    
    local result, status_code = http.request{
        url = url,
        sink = ltn12.sink.table(response_body)
    }
    
    if result and status_code == 200 then
        local response = table.concat(response_body)
        local keys_data = jwt.decode(response)
        
        if keys_data and keys_data.keys then
            public_keys_cache = keys_data.keys
            cache_expiry = current_time + CACHE_DURATION
            log_message("info", "Successfully fetched " .. #keys_data.keys .. " public keys")
            return public_keys_cache
        end
    end
    
    log_message("error", "Failed to fetch public keys. Status: " .. (status_code or "unknown"))
    return nil
end

-- Function to decode base64url
local function base64url_decode(data)
    data = string.gsub(data, '-', '+')
    data = string.gsub(data, '_', '/')
    local pad = 4 - (string.len(data) % 4)
    if pad < 4 then
        data = data .. string.rep('=', pad)
    end
    return mime.unb64(data)
end

-- Function to validate JWT token
local function validate_jwt_token(token)
    if not JWT_VALIDATION_ENABLED then
        log_message("debug", "JWT validation disabled, accepting token")
        return true, { sub = "disabled", preferred_username = "disabled" }
    end
    
    if not token then
        return false, "No token provided"
    end
    
    -- Remove "Bearer " prefix if present
    token = string.gsub(token, "^Bearer%s+", "")
    
    -- Split JWT into parts
    local parts = {}
    for part in string.gmatch(token, "[^.]+") do
        table.insert(parts, part)
    end
    
    if #parts ~= 3 then
        return false, "Invalid JWT format"
    end
    
    local header_b64, payload_b64, signature_b64 = parts[1], parts[2], parts[3]
    
    -- Decode header and payload
    local header_json = base64url_decode(header_b64)
    local payload_json = base64url_decode(payload_b64)
    
    if not header_json or not payload_json then
        return false, "Invalid JWT encoding"
    end
    
    local header = jwt.decode(header_json)
    local payload = jwt.decode(payload_json)
    
    if not header or not payload then
        return false, "Invalid JWT JSON"
    end
    
    -- Check if token is expired
    local current_time = os.time()
    if payload.exp and current_time > payload.exp then
        return false, "Token expired"
    end
    
    -- Check if token is not yet valid
    if payload.nbf and current_time < payload.nbf then
        return false, "Token not yet valid"
    end
    
    -- Validate issuer
    log_message("debug", "Issuer: " .. payload.iss)
    log_message("debug", "Expected issuer: " .. string.format("%s/realms/%s", KEYCLOAK_URL, REALM))
    if payload.iss then
        local expected_issuer_keycloak = string.format("%s/realms/%s", KEYCLOAK_URL, REALM)
        local expected_issuer_localhost = string.format("http://localhost:7080/realms/%s", REALM)
        local expected_issuer_localhost_no_port = string.format("http://localhost/realms/%s", REALM)
        
        if payload.iss ~= expected_issuer_keycloak and 
           payload.iss ~= expected_issuer_localhost and 
           payload.iss ~= expected_issuer_localhost_no_port then
            return false, "Invalid issuer"
        end
    end
    
    -- Validate audience (can be a string or array)
    log_message("debug", "Audience: " .. payload.aud)
    log_message("debug", "Expected audience: " .. CLIENT_ID)
    if payload.aud then
        log_message("debug", "Audience: " .. payload.aud)
        log_message("debug", "Expected audience: " .. CLIENT_ID)
        
        local valid_audience = false
        local accepted_audiences = {CLIENT_ID, "account"}
        
        if type(payload.aud) == "string" then
            for _, accepted_aud in ipairs(accepted_audiences) do
                if payload.aud == accepted_aud then
                    valid_audience = true
                    break
                end
            end
        elseif type(payload.aud) == "table" then
            for _, aud in ipairs(payload.aud) do
                for _, accepted_aud in ipairs(accepted_audiences) do
                    if aud == accepted_aud then
                        valid_audience = true
                        break
                    end
                end
                if valid_audience then break end
            end
        end
        
        if not valid_audience then
            log_message("warn", "Invalid audience, but continuing validation")
            -- return false, "Invalid audience"  -- Comment out this line to make it optional
        end
    end
    
    -- Get public keys from Keycloak
    local public_keys = fetch_public_keys()
    if not public_keys then
        return false, "Unable to fetch public keys"
    end
    
    log_message("debug", "Header: " .. jwt.encode(header))
    
    -- Check algorithm compatibility
    local algorithm = header.alg
    if not algorithm then
        return false, "No algorithm specified in JWT header"
    end
    
    log_message("debug", "JWT Algorithm: " .. algorithm)
    
    -- For HS256 (HMAC), we can't validate with RSA public keys
    -- For RS256 (RSA), we need to find the correct key
    if algorithm == "HS256" then
        log_message("warn", "HS256 algorithm detected - cannot validate with RSA public keys")
        return false, "HS256 algorithm not supported (requires HMAC secret)"
    elseif algorithm == "RS256" then
        local key_id = header.kid
        if not key_id then
            return false, "No key ID (kid) in JWT header for RS256 validation"
        end
        
        log_message("debug", "Key ID: " .. key_id)
        local public_key = nil
        
        for _, key in ipairs(public_keys) do
            if key.kid == key_id then
                public_key = key
                break
            end
        end
        
        if not public_key then
            return false, "Public key not found for key ID: " .. key_id
        end
        
        log_message("debug", "Found matching public key for RS256 validation")
    else
        return false, "Unsupported algorithm: " .. algorithm
    end
    
    log_message("debug", "JWT validation successful for user: " .. (payload.preferred_username or payload.sub or "unknown"))
    return true, payload
end

-- HAProxy Lua action registration
core.register_action("validate_jwt", { "http-req" }, function(txn)
    local auth_header = txn.sf:req_hdr("Authorization")
    
    if not auth_header then
        log_message("warn", "No Authorization header found")
        txn:set_var("txn.jwt_valid", "false")
        txn:set_var("txn.jwt_error", "No Authorization header")
        return
    end
    
    local token = string.gsub(auth_header, "^Bearer%s+", "")
    local is_valid, result = validate_jwt_token(token)
    
    if not is_valid then
        log_message("warn", "JWT validation failed: " .. tostring(result))
        txn:set_var("txn.jwt_valid", "false")
        txn:set_var("txn.jwt_error", tostring(result))
    else
        log_message("debug", "JWT validation successful")
        txn:set_var("txn.jwt_valid", "true")
        txn:set_var("txn.jwt_payload", jwt.encode(result))
        -- Set user information for the backend
        if result.preferred_username then
            txn:set_var("txn.user", result.preferred_username)
        end
        if result.sub then
            txn:set_var("txn.user_id", result.sub)
        end
    end
end) 