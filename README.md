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

- `app.py` — mini appli Flask, route `/chat` qui appelle l'API Claude
  (Anthropic) avec la clé chargée via `python-dotenv`.
- `.env` — contient `ANTHROPIC_API_KEY`, une clé **factice** (générée
  aléatoirement, ne fonctionne pas, ne correspond à aucun compte réel).
- `.gitignore` — volontairement **sans** `.env` dedans (voir commentaire
  dans le fichier).
- `requirements.txt` — dépendances Python.

## Lancer localement (optionnel)

```bash
pip install -r requirements.txt
python app.py
```

La clé étant factice, tout appel à `/chat` renverra une erreur 401 de
l'API Anthropic — c'est normal et attendu. Seul le mécanisme de
détection du secret exposé nous intéresse ici, pas le fonctionnement
réel du chatbot.

## Dans un vrai projet, il faudrait plutôt

- Ne jamais committer `.env` — toujours l'ajouter à `.gitignore`.
- Fournir un `.env.example` avec des valeurs bidon pour l'équipe.
- Stocker les vrais secrets dans un gestionnaire dédié (variables
  CI/CD masquées, GitLab CI/CD Variables, Vault, etc.).
- Faire une rotation immédiate de toute clé qui a fuité, même par erreur,
  et vérifier l'historique Git complet (le retirer d'un commit ne suffit
  pas si l'historique n'est pas nettoyé aussi).
