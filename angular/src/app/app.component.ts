import { Component, OnInit, OnDestroy } from '@angular/core';
import { AuthService } from './services/auth.service';
import { interval, Subscription } from 'rxjs';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit, OnDestroy {
  title = 'atexo-chatbot-stagiaires';
  private tokenCheckSubscription?: Subscription;

  constructor(private authService: AuthService) {}

  ngOnInit() {
    // Nettoyer les tokens expirés au démarrage
    this.cleanupExpiredTokens();
    
    // Vérifier le token toutes les 2 minutes
    this.tokenCheckSubscription = interval(2 * 60 * 1000).subscribe(() => {
      if (this.authService.isAuthenticated()) {
        this.authService.refreshTokenIfNeeded().subscribe();
      }
    });
  }

  private cleanupExpiredTokens(): void {
    // Si l'utilisateur n'est pas authentifié mais qu'il y a des tokens, les nettoyer
    if (!this.authService.isAuthenticated()) {
      this.authService.logout();
    }
  }

  ngOnDestroy() {
    if (this.tokenCheckSubscription) {
      this.tokenCheckSubscription.unsubscribe();
    }
  }
}
