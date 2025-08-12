#!/usr/bin/env python3
"""
Test script to verify Keycloak connection and public key fetching
"""

import os
import sys
import requests
import json
from dotenv import load_dotenv

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config

def test_keycloak_connection():
    """Test connection to Keycloak and fetch public key"""
    
    # Load configuration
    load_dotenv()
    config = Config()
    
    print("=== Keycloak Connection Test ===")
    print(f"Keycloak URL: {config.KEYCLOAK_SERVER_URL}")
    print(f"Realm: {config.KEYCLOAK_REALM}")
    print(f"Client ID: {config.KEYCLOAK_CLIENT_ID}")
    print()
    
    # Test 1: Check if Keycloak is reachable
    print("1. Testing Keycloak connectivity...")
    try:
        health_url = f"{config.KEYCLOAK_SERVER_URL}/health"
        response = requests.get(health_url, timeout=5)
        print(f"   Health check status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Keycloak is reachable")
        else:
            print("   ⚠️  Keycloak responded but not healthy")
    except Exception as e:
        print(f"   ❌ Cannot reach Keycloak: {e}")
        return False
    
    # Test 2: Fetch JWKS
    print("\n2. Fetching JWKS (JSON Web Key Set)...")
    try:
        jwks_url = f"{config.KEYCLOAK_SERVER_URL}/realms/{config.KEYCLOAK_REALM}/protocol/openid-connect/certs"
        response = requests.get(jwks_url, timeout=10)
        print(f"   JWKS status: {response.status_code}")
        
        if response.status_code == 200:
            jwks = response.json()
            keys_count = len(jwks.get('keys', []))
            print(f"   ✅ Found {keys_count} keys in JWKS")
            
            if keys_count > 0:
                key = jwks['keys'][0]
                print(f"   Key ID (kid): {key.get('kid', 'unknown')}")
                print(f"   Algorithm: {key.get('alg', 'unknown')}")
                print(f"   Key Type: {key.get('kty', 'unknown')}")
                print(f"   Use: {key.get('use', 'unknown')}")
            else:
                print("   ⚠️  No keys found in JWKS")
                return False
        else:
            print(f"   ❌ Failed to fetch JWKS: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error fetching JWKS: {e}")
        return False
    
    # Test 3: Test AuthService public key fetching
    print("\n3. Testing AuthService public key fetching...")
    try:
        from app.services.auth_service import AuthService
        
        auth_service = AuthService()
        public_key = auth_service.get_keycloak_public_key()
        
        if public_key:
            print("   ✅ Successfully fetched and converted public key")
            print(f"   Key length: {len(public_key)} characters")
            print(f"   Key preview: {public_key[:50]}...")
        else:
            print("   ❌ Failed to fetch public key")
            return False
            
    except Exception as e:
        print(f"   ❌ Error in AuthService: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False
    
    print("\n✅ All tests passed! Your Keycloak setup is working correctly.")
    return True

if __name__ == "__main__":
    success = test_keycloak_connection()
    sys.exit(0 if success else 1)
