"""
Petite application de démonstration qui appelle l'API Anthropic (Claude).

⚠️ PROJET VOLONTAIREMENT VULNÉRABLE — voir README.md
Créé pour un labo de sécurité : la clé API est chargée depuis .env, et ce
fichier .env est commité dans Git au lieu d'être ignoré. Vulnérabilité
testée : secret exposé dans le dépôt (CWE-798 / CWE-547).
"""

import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import anthropic

load_dotenv()  # charge les variables définies dans .env

API_KEY = os.getenv("ANTHROPIC_API_KEY")

app = Flask(__name__)
client = anthropic.Anthropic(api_key=API_KEY)


@app.route("/")
def home():
    return "Vulnerable LLM demo app — voir README.md"


@app.route("/chat", methods=["POST"])
def chat():
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
