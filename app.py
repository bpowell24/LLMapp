"""
Petite application de démonstration qui appelle l'API Anthropic (Claude).

⚠️ PROJET VOLONTAIREMENT VULNÉRABLE — voir README.md
Créé pour un labo de sécurité : la clé API est chargée depuis .env, et ce
fichier .env est commité dans Git au lieu d'être ignoré. Vulnérabilité
testée : secret exposé dans le dépôt (CWE-798 / CWE-547).

=== Labo authentification ===
Ce fichier contient aussi un système d'authentification (inscription /
connexion / déconnexion) dont le mécanisme de stockage des mots de passe
évolue à travers 4 commits successifs, du pire au meilleur :

    1. Texte clair      (ce commit)
    2. MD5
    3. SHA1
    4. BCrypt

Seules les fonctions hash_password() et verify_password() changent d'un
commit à l'autre — tout le reste (routes, base de données) reste identique.
C'est volontaire : ça isole la leçon de sécurité dans le plus petit bout de
code possible, et ça montre que le reste de l'application n'a JAMAIS besoin
de savoir comment les mots de passe sont stockés en interne.
"""

import os
import sqlite3

from flask import Flask, request, jsonify, session
from dotenv import load_dotenv
import anthropic

load_dotenv()  # charge les variables définies dans .env

API_KEY = os.getenv("ANTHROPIC_API_KEY")

app = Flask(__name__)
# Nécessaire pour que Flask puisse chiffrer/signer le cookie de session.
# Générée aléatoirement à chaque démarrage : correct pour un labo (chacun
# perd sa session si le serveur redémarre), mais PAS pour de la prod, où on
# voudrait une valeur fixe et secrète (ex. variable d'environnement), sinon
# tous les cookies de session émis avant un redémarrage deviennent invalides.
app.secret_key = os.urandom(24)

client = anthropic.Anthropic(api_key=API_KEY)


# ---------------------------------------------------------------------------
# Base de données (SQLite — un simple fichier local, aucun serveur à
# installer, suffisant pour un labo).
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


def get_db() -> sqlite3.Connection:
    """Ouvre une nouvelle connexion à la base SQLite.

    row_factory = sqlite3.Row permet d'accéder aux colonnes par nom
    (ex. user["password"]) plutôt que par index numérique — plus lisible
    et moins fragile si l'ordre des colonnes change un jour.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Crée la table users si elle n'existe pas déjà.

    La colonne s'appelle "password" dans les 4 commits, même une fois
    qu'elle contiendra un hash plutôt qu'un mot de passe en clair — exprès,
    pour que le schéma de la base ne change jamais entre les étapes (voir
    README.md, section "Tester chaque étape").
    """
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    db.commit()
    db.close()


init_db()


# ---------------------------------------------------------------------------
# ÉTAPE 1/4 — Mots de passe en texte clair.
#
# Le pire des cas : le mot de passe est stocké tel quel dans la base.
# Quiconque obtient un accès en lecture à la base (fuite de backup, injection
# SQL, employé malveillant, etc.) voit instantanément le mot de passe de
# TOUS les usagers, en clair, prêt à être réutilisé ailleurs.
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Ne fait rien : retourne le mot de passe tel quel.

    Nommée "hash_password" même ici pour que son nom reste correct dans les
    3 prochains commits sans avoir à changer les appels dans register().
    """
    return password


def verify_password(password: str, stored: str) -> bool:
    """Compare directement les deux chaînes."""
    return password == stored


# ---------------------------------------------------------------------------
# Routes d'authentification.
# ---------------------------------------------------------------------------

@app.route("/register", methods=["POST"])
def register():
    """Crée un compte. Attend un JSON {"username": ..., "password": ...}."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username et password sont requis"}), 400

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing is not None:
        db.close()
        return jsonify({"error": "Ce nom d'utilisateur existe déjà"}), 409

    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hash_password(password)),
    )
    db.commit()
    db.close()
    return jsonify({"message": "Compte créé avec succès"}), 201


@app.route("/login", methods=["POST"])
def login():
    """Vérifie les identifiants et ouvre une session si c'est bon."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    db = get_db()
    user = db.execute(
        "SELECT password FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()

    # Même message d'erreur que l'utilisateur n'existe pas OU que le mot de
    # passe soit faux : ne jamais révéler lequel des deux a échoué, sinon on
    # donne gratuitement à un attaquant la liste des comptes qui existent.
    if user is None or not verify_password(password, user["password"]):
        return jsonify({"error": "Nom d'utilisateur ou mot de passe invalide"}), 401

    session["username"] = username
    return jsonify({"message": f"Connecté en tant que {username}"}), 200


@app.route("/logout", methods=["POST"])
def logout():
    """Efface la session en cours."""
    session.pop("username", None)
    return jsonify({"message": "Déconnecté"}), 200


# ---------------------------------------------------------------------------
# Routes existantes.
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return "Vulnerable LLM demo app — voir README.md"


@app.route("/chat", methods=["POST"])
def chat():
    # /chat exige maintenant d'être connecté — sans ça, l'authentification
    # qu'on vient d'ajouter ne protégerait rien du tout dans cette appli.
    if "username" not in session:
        return jsonify({"error": "Authentification requise"}), 401

    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not message:
        return jsonify({"error": "Le champ 'message' est requis"}), 400

    try:
        response = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=500,
            messages=[{"role": "user", "content": message}],
        )
        return jsonify({"reply": response.content[0].text})
    except Exception as e:
        # Avec la clé factice du .env, on s'attend ici à une erreur 401
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
