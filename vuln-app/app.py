# app.py — NE PAS déployer en production
import sqlite3, subprocess, hashlib, os, pickle
from flask import Flask, request, jsonify, render_template_string
 
app = Flask(__name__)
 
# FAILLE 1 — Hardcoded credentials (CWE-798)
SECRET_KEY  = 'hardcoded_secret_123'
DB_PASSWORD = 'admin'
AWS_KEY     = 'AKIAIOSFODNN7EXAMPLE'

# AJOUT : Point d'entrée pour que le scanner Docker trouve les autres failles
@app.route('/')
def index():
    return '''
    <h1>Application Vulnérable de Test</h1>
    <ul>
        <li><a href="/user?id=1">Profil Utilisateur (Injectable SQL)</a></li>
        <li><a href="/hello?name=ZAP">Salutations (Injectable XSS)</a></li>
        <li><a href="/ping?host=localhost">Outil Ping (Injectable Commande)</a></li>
        <li><a href="/health">Santé de l'application</a></li>
    </ul>
    '''

# AJOUT : Corrige les alertes d'en-têtes manquants signalées par ZAP
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    # Note : Le header "Server" est géré par Werkzeug, pour le modifier il faudrait configurer le serveur WSGI.
    return response
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
    out  = subprocess.check_output(f'ping -c1 {host}', shell=True)
    return out
 
# FAILLE 4 — XSS Reflété (CWE-79)
@app.route('/hello')
def hello():
    name = request.args.get('name', 'world')
    return render_template_string(f'<h1>Hello {name}</h1>')
 
# FAILLE 5 — Désérialisation pickle (CWE-502)
@app.route('/load', methods=['POST'])
def load_data():
    return str(pickle.loads(request.get_data()))
 
# FAILLE 6 — MD5 pour mots de passe (CWE-327)
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
 
# FAILLE 7 — debug=True en production
@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0'})
 
if __name__ == '__main__':
    conn = sqlite3.connect('users.db')
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INT, name TEXT, email TEXT)')
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'Alice','alice@corp.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'Bob','bob@corp.com')")
    conn.commit()
    app.run(host='0.0.0.0', port=5000, debug=True)
