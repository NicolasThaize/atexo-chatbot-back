# Intégration ngx-markdown dans Atexo Chatbot

## Vue d'ensemble

Ce projet utilise **ngx-markdown** pour afficher le contenu markdown retourné par le service de chat. Cette intégration permet d'afficher de manière élégante et structurée les réponses du chatbot qui contiennent du markdown.

## Installation

Les dépendances ont été installées avec :

```bash
npm install ngx-markdown@18.0.0 marked --legacy-peer-deps
```

## Configuration

### 1. Module principal (`app.module.ts`)

```typescript
import { MarkdownModule } from 'ngx-markdown';

@NgModule({
  imports: [
    // ... autres imports
    MarkdownModule.forRoot(),
  ],
})
export class AppModule { }
```

### 2. Utilisation dans les templates

Remplacer `[innerHTML]` par le composant `markdown` :

```html
<!-- Avant -->
<div class="message-text" [innerHTML]="message.content"></div>

<!-- Après -->
<div class="message-text">
  <markdown [data]="message.content"></markdown>
</div>
```

## Fonctionnalités supportées

Le rendu markdown supporte les éléments suivants :

### Titres
```markdown
# Titre 1
## Titre 2
### Titre 3
```

### Texte formaté
```markdown
**Gras** et *italique*
`code inline`
```

### Blocs de code
```markdown
```sql
SELECT * FROM users WHERE active = true;
```
```

### Listes
```markdown
- Élément 1
- Élément 2
  - Sous-élément
```

### Tableaux
```markdown
| Colonne 1 | Colonne 2 |
|-----------|-----------|
| Donnée 1  | Donnée 2  |
```

### Citations
```markdown
> Ceci est une citation
```

### Liens
```markdown
[Texte du lien](https://example.com)
```

## Styles CSS

### Styles globaux (`styles.css`)

Les styles globaux pour ngx-markdown sont définis dans `src/styles.css` et incluent :
- Mise en forme des titres avec bordures
- Styles pour les blocs de code avec coloration syntaxique
- Tableaux avec alternance de couleurs
- Citations avec bordure gauche colorée
- Liens avec effets de survol

### Styles spécifiques au chat (`chat.component.css`)

Les styles spécifiques au composant chat incluent :
- Adaptation des couleurs pour les messages utilisateur vs bot
- Espacement optimisé pour l'interface de chat
- Responsive design pour mobile

## Exemple d'utilisation

### Dans le service de chat

Le service de chat retourne des réponses formatées en markdown :

```typescript
// Exemple de réponse formatée
const botResponse = `## Requête SQL générée
\`\`\`sql
SELECT * FROM users WHERE active = true;
\`\`\`

## Résultat
La requête a retourné **15 utilisateurs actifs**.
`;
```

### Test de rendu

Un bouton de test est disponible dans l'interface pour démontrer le rendu markdown :
- Cliquez sur l'icône `code` dans la barre d'outils
- Un message de test avec différents éléments markdown sera affiché

## Avantages

1. **Sécurité** : ngx-markdown sanitise automatiquement le contenu HTML
2. **Performance** : Rendu optimisé avec mise en cache
3. **Flexibilité** : Support complet de la syntaxe markdown
4. **Accessibilité** : Génération automatique de la structure sémantique
5. **Personnalisation** : Styles CSS facilement modifiables

## Dépannage

### Problèmes courants

1. **Contenu non rendu** : Vérifiez que le contenu est bien une chaîne de caractères
2. **Styles non appliqués** : Vérifiez que les styles CSS sont bien chargés
3. **Erreurs de compilation** : Vérifiez la version de ngx-markdown compatible avec Angular 18

### Logs de débogage

Pour activer les logs de débogage, ajoutez dans `app.module.ts` :

```typescript
MarkdownModule.forRoot({
  markedOptions: {
    provide: MarkedOptions,
    useValue: {
      gfm: true,
      breaks: true,
    },
  },
})
```

## Ressources

- [Documentation ngx-markdown](https://github.com/jfcere/ngx-markdown)
- [Guide Markdown](https://www.markdownguide.org/)
- [Angular Material](https://material.angular.io/)
