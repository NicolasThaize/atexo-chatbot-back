import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { environment } from '../../environments/environment';

export interface ChatMessage {
  id?: string;
  content: string;
  timestamp: Date;
  isUser: boolean;
}

export interface ChatResponse {
  id?: string;
  sql?: string;
  summary?: string;
  type?: string;
  explanation?: string;
  error?: string;
  invalidSql?: string;
  results?: any[];
  threadId: string;
}

export interface ChatRequest {
  question: string;
  threadId?: string;
}

@Injectable({
  providedIn: 'root'
})
export class ChatService {
  private currentThreadId: string | null = null;

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

  private getHeaders(): HttpHeaders {
    const token = this.authService.getAccessToken();
    return new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    });
  }

  sendMessage(question: string): Observable<ChatResponse> {
    const request: ChatRequest = {
      question: question,
      threadId: this.currentThreadId || undefined
    };

    // Vérifier et rafraîchir le token si nécessaire avant l'envoi
    return this.authService.refreshTokenIfNeeded().pipe(
      switchMap(() => {
        return this.http.post<ChatResponse>(
          `${environment.apiUrl}/chatbot/query`,
          request,
          { headers: this.getHeaders() }
        );
      })
    );
  }

  // Méthode pour démarrer une nouvelle conversation
  startNewConversation(): void {
    this.currentThreadId = null;
  }

  // Méthode pour récupérer le threadId actuel
  getCurrentThreadId(): string | null {
    return this.currentThreadId;
  }

  // Méthode pour définir le threadId (utile pour reprendre une conversation)
  setThreadId(threadId: string): void {
    this.currentThreadId = threadId;
  }
}
