#!/usr/bin/env python3
"""
Script de test pour vérifier le fonctionnement de l'authentification Flask
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_auth_status():
    """Test du statut d'authentification"""
    print("🔍 Test du statut d'authentification...")
    
    try:
        response = requests.get(f"{BASE_URL}/auth/status")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Statut d'authentification: {data['message']}")
            return data['auth_enabled']
        else:
            print(f"❌ Erreur lors du test du statut: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        return None

def test_chatbot_without_auth():
    """Test du chatbot sans authentification"""
    print("🤖 Test du chatbot sans authentification...")
    
    try:
        response = requests.get(f"{BASE_URL}/chatbot/test")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Test endpoint accessible: {data['message']}")
            print(f"   Auth enabled: {data['auth_enabled']}")
            return True
        else:
            print(f"❌ Erreur lors du test: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        return False

def test_chatbot_with_auth():
    """Test du chatbot avec authentification"""
    print("🔐 Test du chatbot avec authentification...")
    
    try:
        # Test sans token (devrait échouer si auth activée)
        response = requests.post(f"{BASE_URL}/chatbot/query", 
                               json={"question": "Test question"})
        
        if response.status_code == 401:
            print("✅ Authentification requise (comportement attendu)")
            return True
        elif response.status_code == 200:
            print("⚠️  Authentification non requise (auth désactivée)")
            return True
        else:
            print(f"❌ Réponse inattendue: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        return False

def test_oidc_endpoints():
    """Test des endpoints OIDC"""
    print("🔑 Test des endpoints OIDC...")
    
    try:
        response = requests.get(f"{BASE_URL}/auth/oidc/userinfo")
        if response.status_code == 200:
            data = response.json()
            if data.get('auth_enabled') == False:
                print("✅ Endpoint OIDC gère correctement l'auth désactivée")
                return True
            else:
                print("⚠️  Endpoint OIDC actif")
                return True
        else:
            print(f"❌ Erreur endpoint OIDC: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🚀 Démarrage des tests d'authentification Flask")
    print("=" * 50)
    
    # Attendre que le service soit prêt
    print("⏳ Attente du démarrage du service...")
    time.sleep(5)
    
    # Tests
    tests = [
        test_auth_status,
        test_chatbot_without_auth,
        test_chatbot_with_auth,
        test_oidc_endpoints
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
            print()
        except Exception as e:
            print(f"❌ Erreur lors du test: {e}")
            results.append(False)
            print()
    
    # Résumé
    print("=" * 50)
    print("📊 Résumé des tests:")
    
    passed = sum(1 for r in results if r is True)
    total = len(results)
    
    print(f"✅ Tests réussis: {passed}/{total}")
    
    if passed == total:
        print("🎉 Tous les tests sont passés avec succès!")
    else:
        print("⚠️  Certains tests ont échoué")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 