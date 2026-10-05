# Vulnerable LLM Demo App — Labo Sécurité

⚠️ **Application volontairement vulnérable**, créée pour un labo de
cybersécurité (Cégep de l'Outaouais). Ne sert pas de modèle pour un vrai
projet.

## Vulnérabilité démontrée

Un secret (clé d'API) est chargé depuis le fichier `.env`, et ce fichier
est **intentionnellement committé dans Git** au lieu d'être exclu via
`.gitignore`. C'est l'une des causes les plus fréquentes de fuite de
secrets en entreprise (CWE-798 — Use of Hard-coded Credentials /
CWE-547 — Use of Hard-coded, Security-relevant Constants).

But : vérifier que l'intégration Snyk + GitLab (et/ou la détection de
secrets native de GitLab) attrape bien ce secret une fois le code poussé.

## Structure

- `app.py` — mini appli Flask : route `/chat` qui appelle l'API Claude
  (Anthropic) avec la clé chargée via `python-dotenv`, et un système
  d'authentification (`/register`, `/login`, `/logout`) — voir section
  dédiée plus bas.
- `.env` — contient `ANTHROPIC_API_KEY`, une clé **factice** (générée
  aléatoirement, ne fonctionne pas, ne correspond à aucun compte réel).
- `.gitignore` — volontairement **sans** `.env` dedans (voir commentaire
  dans le fichier). Contient par contre `users.db` (voir plus bas) : ce
  n'est pas la vulnérabilité étudiée ici, pas de raison de l'exposer.
- `requirements.txt` — dépendances Python.
- `users.db` — base SQLite créée automatiquement au premier démarrage.
  Jamais commitée (contient les mots de passe/hash des comptes de test).

## Lancer localement (optionnel)

```bash
pip install -r requirements.txt
python app.py
```

La clé étant factice, tout appel à `/chat` renverra une erreur 401 de
l'API Anthropic — c'est normal et attendu. Seul le mécanisme de
détection du secret exposé nous intéresse ici, pas le fonctionnement
réel du chatbot.

## Authentification — migration du hachage de mots de passe

En plus de la vulnérabilité ci-dessus, ce dépôt documente une 2ᵉ étude :
comment le *stockage* d'un mot de passe migre d'une méthode à l'autre, un
commit à la fois.

```bash
git log --oneline
```
```
7e72a00 Authentification (4/4) : migration vers BCrypt
40131e5 Authentification (3/4) : migration vers SHA1
c607c82 Authentification (2/4) : migration vers MD5
c29d7fc Authentification (1/4) : mots de passe en texte clair
2571357 Initial commit: vulnerable LLM demo app
```

| # | Méthode | Salt ? | Volontairement lent ? | Verdict |
|---|---|---|---|---|
| 1 | Texte clair | — | — | Catastrophique : une fuite de la base = tous les mots de passe lisibles directement |
| 2 | MD5 | ❌ | ❌ | Mauvais : deux mots de passe identiques = même hash, et calcul trop rapide pour résister au brute-force |
| 3 | SHA1 | ❌ | ❌ | Même problème que MD5, malgré un hash plus long |
| 4 | BCrypt | ✅ (automatique) | ✅ (cost factor ajustable) | Bon choix actuel pour des mots de passe |

Seules les fonctions `hash_password()` et `verify_password()` changent
d'un commit à l'autre dans `app.py` — tout le reste (routes, schéma de la
base) reste identique exprès, pour isoler la leçon dans le plus petit
bout de code possible. Voir les commentaires au-dessus de ces deux
fonctions dans `app.py` pour le détail de chaque étape, et le message de
chaque commit pour le résumé.

### Routes ajoutées

| Route | Méthode | Body JSON | Rôle |
|---|---|---|---|
| `/register` | POST | `{"username", "password"}` | Crée un compte |
| `/login` | POST | `{"username", "password"}` | Ouvre une session |
| `/logout` | POST | — | Ferme la session |
| `/chat` | POST | `{"message"}` | Nécessite maintenant une session active (401 sinon) |

### Tester chaque étape

Le schéma de `users.db` ne change jamais (toujours une colonne
`password`), donc **se mettre sur un ancien commit sans supprimer
`users.db`** ne pose pas de problème technique — mais un compte créé à
l'étape 4 (hash bcrypt) ne se reconnectera évidemment pas correctement si
on revient tester l'étape 1 (qui compare le mot de passe tel quel) : le
contenu stocké n'a plus le même sens d'une étape à l'autre. Pour un test
propre de chaque étape, supprime `users.db` avant de créer un nouveau
compte :

```bash
git checkout <hash-du-commit>   # ex. c29d7fc pour l'étape 1
rm -f users.db
pip install -r requirements.txt
python app.py
```

Puis, dans un autre terminal :

```bash
# Créer un compte
curl -X POST http://127.0.0.1:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "monkey123"}'

# Se connecter (-c pour sauvegarder le cookie de session)
curl -c cookies.txt -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "monkey123"}'

# Vérifier que /chat est bien protégé (-b pour réutiliser le cookie)
curl -b cookies.txt -X POST http://127.0.0.1:5000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "salut"}'
```

Pour voir ce qui est réellement stocké dans la base à chaque étape :

```bash
python3 -c "import sqlite3; print(list(sqlite3.connect('users.db').execute('SELECT * FROM users')))"
```

## Dans un vrai projet, il faudrait plutôt

**Pour les secrets (clé API) :**

- Ne jamais committer `.env` — toujours l'ajouter à `.gitignore`.
- Fournir un `.env.example` avec des valeurs bidon pour l'équipe.
- Stocker les vrais secrets dans un gestionnaire dédié (variables
  CI/CD masquées, GitLab CI/CD Variables, Vault, etc.).
- Faire une rotation immédiate de toute clé qui a fuité, même par erreur,
  et vérifier l'historique Git complet (le retirer d'un commit ne suffit
  pas si l'historique n'est pas nettoyé aussi).

**Pour les mots de passe :**

- BCrypt (étape 4) est un bon choix, mais pas le seul : Argon2 et scrypt
  sont deux autres algorithmes modernes conçus pour le même usage.
- Migrer une base existante (contrairement à ce labo, où chaque étape
  repart d'une base vide) demande une stratégie particulière : on ne peut
  pas re-hacher un mot de passe qu'on ne connaît pas en clair. L'approche
  courante est la "migration paresseuse" — garder l'ancien hash, et le
  remplacer par le nouveau seulement au prochain login réussi de chaque
  usager (c'est le seul moment où l'app voit le mot de passe en clair).
- Ne jamais utiliser `hash_password`/`verify_password` "maison" en
  production sans passer par une librairie éprouvée (`bcrypt`, `argon2-cffi`,
  etc.) — les détails d'implémentation (comparaison en temps constant,
  génération du salt, etc.) sont faciles à mal faire soi-même.
