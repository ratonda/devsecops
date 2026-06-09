# 📑 Guide Complet : Installation, Configuration et Attaque avec OWASP ZAP

Ce guide est optimisé pour **Windows avec Git Bash**. Il détaille la configuration réseau, la mise en place de l'application cible et l'extraction des rapports.

---

## 🛠️ Étape 1 : Préparation de la cible (L'application vulnérable)

Pour que ZAP puisse injecter ses attaques, l'application Flask doit être configurée pour accepter les connexions externes et posséder une page d'accueil (route `/`) pour guider le scanner.

1. Créez un fichier nommé **`app.py`** et collez-y ce code corrigé :

```python
import sqlite3, subprocess, hashlib, os, pickle
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# FAILLE 1 — Hardcoded credentials
SECRET_KEY  = 'hardcoded_secret_123'

# CONFIGURATION RÉSEAU — Ajout des en-têtes de sécurité (Optionnel pour tester les alertes)
# Décommentez les lignes ci-dessous si vous voulez voir les alertes d'en-têtes disparaître
# @app.after_request
# def add_security_headers(response):
#     response.headers['X-Content-Type-Options'] = 'nosniff'
#     return response

# POINT D'ENTRÉE POUR LE SPIDER DE ZAP (Évite l'erreur 404)
@app.route('/')
def index():
    return '''
    <h1>Laboratoire de Test SecOps</h1>
    <ul>
        <li><a href="/user?id=1">Profil Utilisateur (Injection SQL)</a></li>
        <li><a href="/hello?name=ZAP">Salutations (Injection XSS)</a></li>
        <li><a href="/ping?host=localhost">Outil Ping (Injection de Commande)</a></li>
        <li><a href="/health">Statut API</a></li>
    </ul>
    '''

# FAILLE 2 — SQL Injection (CWE-89)
@app.route('/user')
def get_user():
    uid = request.args.get('id', '')
    conn = sqlite3.connect('users.db')
    rows = conn.execute('SELECT * FROM users WHERE id=' + uid).fetchall()
    return jsonify(rows)

# FAILLE 3 — Command Injection (CWE-78)
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Note : Adapté pour Windows/Linux selon votre OS hôte
    cmd = f'ping -n 1 {host}' if os.name == 'nt' else f'ping -c 1 {host}'
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return f"<pre>{out.decode('utf-8', errors='ignore')}</pre>"
    except Exception as e:
        return f"<pre>Erreur : {str(e)}</pre>"

# FAILLE 4 — XSS Reflété (CWE-79)
@app.route('/hello')
def hello():
    name = request.args.get('name', 'world')
    return render_template_string(f'<h1>Hello {name}</h1>')

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0'})

if __name__ == '__main__':
    conn = sqlite3.connect('users.db')
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INT, name TEXT, email TEXT)')
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'Alice','alice@corp.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'Bob','bob@corp.com')")
    conn.commit()
    # Écoute obligatoire sur 0.0.0.0 pour Docker
    app.run(host='0.0.0.0', port=5000, debug=True)

```

2. **Lancez votre application** dans un terminal classique ou Git Bash :
```bash
python app.py

```


3. **Vérification :** Ouvrez votre navigateur sur `http://localhost:5000/`. Vous devez voir la page d'accueil avec la liste des liens. **Laissez ce terminal ouvert.**

---

## ⚙️ Étape 2 : Résolution des blocages réseau (Pare-feu Windows)

L'erreur `[Errno 5] ZAP failed to access` arrive parce que Windows bloque la communication entre le conteneur Docker et votre application Flask.

### Action requise :

1. Ouvrez le **Pare-feu Windows Defender** (via le menu Démarrer).
2. Cliquez sur **Paramètres avancés**.
3. Dans **Règles de trafic entrant**, cliquez sur **Nouvelle règle...**
4. Choisissez **Port**, puis spécifiez le port local **`5000`**.
5. Sélectionnez **Autoriser la connexion**, et cochez les cases (Domaine, Privé, Public).
6. Nommez la règle `Flask-Test-ZAP` et validez.

> 💡 *Alternative rapide pour le test :* Désactivez temporairement votre Pare-feu Windows le temps de lancer le conteneur Docker.

---

## 🐳 Étape 3 : Configuration de ZAP et Création des Dossiers

Ouvrez un **deuxième terminal (Git Bash)** pour exécuter les commandes Docker.

1. Téléchargez la dernière version stable de ZAP :
```bash
docker pull ghcr.io/zaproxy/zaproxy:stable

```


2. Créez le dossier de destination des rapports :
```bash
mkdir -p reports

```


3. Configurez la variable d'environnement contenant l'IP de la passerelle Docker :
```bash
HOST_IP=$(docker network inspect bridge --format='{{range .IPAM.Config}}{{.Gateway}}{{end}}') && echo "L'IP de l'hôte est : $HOST_IP"

```



---

## ⚡ Étape 4 : Lancement des Attaques (Full Scan Actif)

Le mode **Full Scan** va explorer les liens de l'application, puis injecter des payloads agressifs pour forcer les erreurs SQL, XSS et injections de commandes.

Exécutez la commande suivante dans Git Bash :

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$(pwd)/reports:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py \
    -t "http://$HOST_IP:5000/" \
    -r zap-output.html \
    -J zap-output.json \
    -I -d

```

### 🔍 Décryptage des arguments utilisés :

* `MSYS_NO_PATHCONV=1` : Empêche Git Bash d'altérer le chemin du volume Windows transmis à Docker.
* `-v "$(pwd)/reports:/zap/wrk:rw"` : Monte votre dossier local dans le conteneur pour y écrire le rapport avec les droits d'écriture (`:rw`).
* `-t "http://$HOST_IP:5000/"` : La cible exacte (votre adresse IP locale + port de Flask).
* `-r zap-output.html` & `-J zap-output.json` : Spécifie les formats des rapports de sortie.
* `-I` : Ignore les erreurs mineures pour ne pas bloquer le script.
* `-d` : Affiche le détail des modules chargés (mode debug).

---

## 📊 Étape 5 : Analyse du Rapport de Sécurité

Une fois les attaques terminées, ZAP génère les fichiers directement dans votre dossier `reports/`.

Ouvrez le rapport interactif dans votre navigateur par défaut depuis Git Bash :

```bash
start reports/zap-output.html

```

### 🎯 Ce que vous allez voir dans le rapport :

Grâce aux failles volontairement insérées dans `app.py`, votre rapport contiendra désormais des alertes de niveau rouge (**High**) :

* **SQL Injection (High)** : Détectée sur la route `/user?id=1`.
* **Cross-Site Scripting / XSS (High)** : Détectée sur la route `/hello?name=ZAP`.
* **Remote Command Execution (High)** : Détectée sur la route `/ping?host=localhost`.