import { Component, OnInit, ViewChild, ElementRef, AfterViewChecked } from '@angular/core';
import { UntypedFormBuilder, UntypedFormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService, User } from '../../services/auth.service';
import { ChatService, ChatMessage, ChatResponse } from '../../services/chat.service';

@Component({
  selector: 'app-chat',
  templateUrl: './chat.component.html',
  styleUrls: ['./chat.component.css']
})
export class ChatComponent implements OnInit, AfterViewChecked {
  @ViewChild('messagesContainer') private messagesContainer!: ElementRef;
  
  chatForm: UntypedFormGroup;
  messages: ChatMessage[] = [];
  currentUser: User | null = null;
  loading = false;

  constructor(
    private formBuilder: UntypedFormBuilder,
    private authService: AuthService,
    public chatService: ChatService,
    private router: Router
  ) {
    this.chatForm = this.formBuilder.group({
      message: ['', Validators.required]
    });
  }

  ngOnInit(): void {
    this.currentUser = this.authService.currentUserValue;
    // Démarrer une nouvelle conversation
    this.chatService.startNewConversation();
  }

  ngAfterViewChecked(): void {
    this.scrollToBottom();
  }

  private scrollToBottom(): void {
    try {
      this.messagesContainer.nativeElement.scrollTop = this.messagesContainer.nativeElement.scrollHeight;
    } catch (err) {}
  }

  onSubmit(): void {
    if (this.chatForm.invalid || this.loading) {
      return;
    }

    const question = this.chatForm.get('message')?.value;
    if (!question) {
      return;
    }

    // Ajouter le message utilisateur
    const userMessage: ChatMessage = {
      content: question,
      timestamp: new Date(),
      isUser: true
    };
    this.messages.push(userMessage);

    // Réinitialiser le formulaire
    this.chatForm.reset();
    this.loading = true;

    // Envoyer le message au backend
    this.chatService.sendMessage(question).subscribe({
      next: (response: ChatResponse) => {
        this.loading = false;
        
        // Stocker le threadId pour la suite de la conversation
        if (response.threadId) {
          this.chatService.setThreadId(response.threadId);
        }
        
        // Construire la réponse du chatbot selon le type de réponse
        let botResponse = '';
        
        if (response.explanation) {
          // Priorité à l'explication si elle est présente
          botResponse = this.cleanMarkdownContent(response.explanation);
        } else if (response.type === 'NON_SQL_QUERY') {
          // Réponse pour les questions non-SQL
          botResponse = 'Je ne peux pas traiter cette question avec les données disponibles.';
        } else if (response.error) {
          // Gestion des erreurs
          botResponse = `**Erreur:** ${response.error}`;
          if (response.invalidSql) {
            botResponse += `\n\n**SQL généré:**\n\`\`\`sql\n${response.invalidSql}\n\`\`\``;
          }
        } else {
          // Réponse normale avec SQL et résumé
          if (response.sql) {
            botResponse += `## Requête SQL générée\n\`\`\`sql\n${response.sql}\n\`\`\`\n\n`;
          }
          if (response.summary) {
            botResponse += `## Résultat\n${response.summary}`;
          }
        }
        
        // Ajouter la réponse du chatbot
        const botMessage: ChatMessage = {
          content: botResponse,
          timestamp: new Date(),
          isUser: false
        };
        this.messages.push(botMessage);
      },
      error: (error) => {
        this.loading = false;
        console.error('Erreur lors de l\'envoi du message:', error);
        
        // Ajouter un message d'erreur
        const errorMessage: ChatMessage = {
          content: 'Désolé, une erreur s\'est produite. Veuillez réessayer.',
          timestamp: new Date(),
          isUser: false
        };
        this.messages.push(errorMessage);
      }
    });
  }

  // Méthode pour démarrer une nouvelle conversation
  startNewConversation(): void {
    this.messages = [];
    this.chatService.startNewConversation();
  }

  logout(): void {
    this.authService.logout();
    this.router.navigate(['/login']);
  }

  formatTimestamp(timestamp: Date): string {
    return new Date(timestamp).toLocaleTimeString('fr-FR', {
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  onKeyDown(event: Event): void {
    const keyboardEvent = event as KeyboardEvent;
    if (!keyboardEvent.shiftKey) {
      keyboardEvent.preventDefault();
      this.onSubmit();
    }
  }

  /**
   * Nettoie le contenu markdown en remplaçant les caractères d'échappement
   * et en formatant correctement le markdown
   */
  private cleanMarkdownContent(content: string): string {
    if (!content) return '';
    
    return content
      // Remplacer les \n par de vrais retours à la ligne
      .replace(/\\n/g, '\n')
      // Remplacer les \t par des espaces
      .replace(/\\t/g, '  ')
      // Remplacer les \r par des retours à la ligne
      .replace(/\\r/g, '\n')
      // Remplacer les \\ par un seul \
      .replace(/\\\\/g, '\\')
      // Nettoyer les espaces en début et fin
      .trim();
  }
}
