import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of, throwError } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';

/**
 * Modèle utilisateur courant (dérivé du JWT et/ou de l'API).
 */
export interface User {
  id: string;
  username: string;
  email: string;
  roles: string[];
  exp?: number;
}

/**
 * Réponse de refresh héritée (Keycloak). Conserve la compatibilité.
 */
export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

// Nouveau format de réponse de l'API pour la connexion
interface LoginApiResponseUser {
  email?: string;
  username?: string;
  id?: string;
}

interface LoginApiResponse {
  token: string;
  refresh_token?: string;
  expires_in?: number;
  user: LoginApiResponseUser;
}

/**
 * Service d'authentification: gère la session, le stockage du token
 * et expose l'état utilisateur.
 */
@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private currentUserSubject: BehaviorSubject<User | null>;
  public currentUser: Observable<User | null>;

  /**
   * Restaure l'utilisateur depuis localStorage.
   * Sécurité: aucun mot de passe stocké; état en mémoire seulement.
   */
  constructor(private http: HttpClient) {
    this.currentUserSubject = new BehaviorSubject<User | null>(
      JSON.parse(localStorage.getItem('currentUser') || 'null')
    );
    this.currentUser = this.currentUserSubject.asObservable();
  }

  /**
   * Snapshot synchrone de l'utilisateur courant.
   */
  public get currentUserValue(): User | null {
    return this.currentUserSubject.value;
  }

  /**
   * Authentifie l'utilisateur: appelle l'API, stocke le JWT,
   * dérive l'utilisateur depuis la réponse/JWT.
   * Sécurité: le serveur émet un JWT signé; aucun secret côté client.
   */
  login(username: string, password: string): Observable<User> {
    const body = {
      username: username,
      password: password
    };

    return this.http.post<LoginApiResponse>(`${environment.apiUrl}/auth/login`, body)
      .pipe(map(response => {
        // Stocker le token et refresh token issus de la nouvelle API
        localStorage.setItem('access_token', response.token);
        if (response.refresh_token) {
          localStorage.setItem('refresh_token', response.refresh_token);
        }

        // Construire l'utilisateur depuis la réponse et/ou le token
        const decodedFromToken = this.safeDecodeRaw(response.token);
        const apiUser = response.user || {};

        const user: User = {
          id: apiUser.id || decodedFromToken.sub || '',
          username: apiUser.username || decodedFromToken.preferred_username || decodedFromToken.username || '',
          email: apiUser.email || decodedFromToken.email || '',
          roles: (decodedFromToken.realm_access?.roles as string[] | undefined) || [],
          exp: typeof decodedFromToken.exp === 'number' ? decodedFromToken.exp : undefined
        };

        localStorage.setItem('currentUser', JSON.stringify(user));
        this.currentUserSubject.next(user);
        return user;
      }));
  }

  /**
   * Déconnecte: purge token et état.
   * Sécurité: invalide immédiatement la session côté client.
   */
  logout(): void {
    // Supprimer les tokens et informations utilisateur
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('currentUser');
    this.currentUserSubject.next(null);
  }

  /**
   * Vérifie la présence du token et son expiration (exp).
   * Sécurité: empêche l'usage de tokens périmés.
   */
  isAuthenticated(): boolean {
    const token = localStorage.getItem('access_token');
    if (!token) return false;

    // Vérifier si le token n'est pas expiré
    try {
      const decoded = this.safeDecodeRaw(token);
      const exp = typeof decoded.exp === 'number' ? decoded.exp : undefined;
      const currentTime = Date.now() / 1000;
      return exp ? exp > currentTime : true; // si pas d'exp, considérer valide tant que présent
    } catch {
      return false;
    }
  }

  /**
   * Récupère le JWT pour les appels HTTP.
   * Sécurité: centralise l'accès au token.
   */
  getAccessToken(): string | null {
    return localStorage.getItem('access_token');
  }

  /**
   * Rafraîchit le token si le backend le supporte (héritage Keycloak).
   * Sécurité: rotation des tokens pour limiter l'exposition.
   */
  refreshToken(): Observable<AuthResponse> {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
      throw new Error('Aucun refresh token disponible');
    }

    const body = {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: environment.keycloak.clientId
    };

    return this.http.post<AuthResponse>(`${environment.apiUrl}/auth/refresh`, body)
      .pipe(map(response => {
        localStorage.setItem('access_token', response.access_token);
        localStorage.setItem('refresh_token', response.refresh_token);
        
        // Mettre à jour l'utilisateur si nécessaire
        const currentUser = this.currentUserValue;
        if (currentUser) {
          const decodedFromToken = this.safeDecodeRaw(response.access_token);
          const updatedUser: User = {
            ...currentUser,
            exp: typeof decodedFromToken.exp === 'number' ? decodedFromToken.exp : undefined
          };
          localStorage.setItem('currentUser', JSON.stringify(updatedUser));
          this.currentUserSubject.next(updatedUser);
        }
        
        return response;
      }), catchError(error => {
        this.handleRefreshError(error);
        return throwError(() => error);
      }));
  }
  
  /**
   * Décodage sûr du payload JWT (sans vérifier la signature).
   * Sécurité: évite les crashs; les assertions sensibles restent côté serveur.
   */
  private safeDecodeRaw(token: string): any {
    const base64Url = token.split('.')[1];
    if (!base64Url) return {};
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  }

  /**
   * Vérifie si le token va expirer dans les prochaines minutes
   * @param minutesBeforeExpiry Nombre de minutes avant expiration pour déclencher le refresh
   */
  isTokenExpiringSoon(minutesBeforeExpiry: number = 5): boolean {
    const token = localStorage.getItem('access_token');
    if (!token) return true;

    try {
      const decoded = this.safeDecodeRaw(token);
      const exp = typeof decoded.exp === 'number' ? decoded.exp : undefined;
      if (!exp) return false;
      
      const currentTime = Date.now() / 1000;
      const timeUntilExpiry = exp - currentTime;
      const minutesUntilExpiry = timeUntilExpiry / 60;
      
      return minutesUntilExpiry <= minutesBeforeExpiry;
    } catch {
      return true;
    }
  }

  /**
   * Rafraîchit automatiquement le token s'il va expirer bientôt
   * @param minutesBeforeExpiry Nombre de minutes avant expiration pour déclencher le refresh
   */
  refreshTokenIfNeeded(minutesBeforeExpiry: number = 5): Observable<boolean> {
    if (this.isTokenExpiringSoon(minutesBeforeExpiry)) {
      return this.refreshToken().pipe(
        map(() => true),
        catchError(error => {
          console.error('Erreur lors du refresh automatique du token:', error);
          this.logout();
          return of(false);
        })
      );
    }
    return of(true);
  }

  /**
   * Gère les erreurs de refresh token et déconnecte l'utilisateur si nécessaire
   */
  private handleRefreshError(error: any): void {
    console.error('Erreur lors du refresh token:', error);
    
    // Si le refresh token est invalide ou expiré, déconnecter l'utilisateur
    if (error.status === 401 || error.status === 400) {
      console.log('Refresh token invalide, déconnexion de l\'utilisateur');
      this.logout();
    }
  }

  /**
   * Vérifie si un refresh token est disponible
   */
  hasRefreshToken(): boolean {
    return !!localStorage.getItem('refresh_token');
  }
}
