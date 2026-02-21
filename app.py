from flask import Flask, render_template, request, jsonify, redirect, url_for, session  # [web:117]
from werkzeug.security import generate_password_hash, check_password_hash  # [web:175]
from models import get_db, init_db

import os
import re
import requests
from dotenv import load_dotenv

# Load .env
load_dotenv()
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
print("API KEY LOADED?", SAFE_BROWSING_API_KEY is not None)

app = Flask(__name__)
app.secret_key = "super_secret_change_later"

# ---------- Helper ----------

username_pattern = re.compile(r'^[a-zA-Z0-9_]{3,20}$')  # letters, digits, underscore, 3–20 chars[web:171]

def is_strong_password(pwd: str) -> bool:
    """Min 8 chars, upper, lower, digit, special symbol."""  # [web:166][web:167]
    if len(pwd) < 8:
        return False
    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?\\" for c in pwd)
    return has_lower and has_upper and has_digit and has_special

def current_user():
    if not session.get('user_id'):
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    conn.close()
    return user

# ---------- Auth routes ----------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            return render_template('register.html', error="Email and password required.")

        # Username rule
        if name and not username_pattern.match(name):
            return render_template(
                'register.html',
                error="Name can use a–z, 0–9, underscore, 3–20 characters."
            )

        # Password strength rule
        if not is_strong_password(password):
            return render_template(
                'register.html',
                error="Password must be 8+ chars with upper, lower, number and special symbol."
            )

        email = email.lower()
        password_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, password_hash)
            )
            conn.commit()
        except Exception:
            conn.close()
            return render_template('register.html', error="Email already registered.")
        conn.close()
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            return render_template('login.html', error="Email and password required.")

        email = email.lower()

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid email or password")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------- Main page ----------

@app.route('/')
def index():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT url, risk, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
        (user['id'],)
    )
    recent_scans = cur.fetchall()
    conn.close()

    return render_template(
        'index.html',
        user_email=user['email'],
        recent_scans=recent_scans
    )

# ---------- Scan API ----------

@app.route('/scan', methods=['POST'])
def scan_url():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    url = data.get('url', '')

    # 1) Google Safe Browsing check
    gs_risk = "Unknown"
    gs_explanation = ""

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"  # [web:120]
        body = {
            "client": {"clientId": "ThreatLens", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        resp = requests.post(endpoint, json=body)
        data_gs = resp.json()
        if data_gs.get("matches"):
            gs_risk = "Dangerous"
            gs_explanation = "Google Safe Browsing reports this URL as malicious or deceptive."
        else:
            gs_risk = "Clean"
            gs_explanation = "Google Safe Browsing has no known threats for this URL."
    except Exception:
        gs_explanation = "Safe Browsing check failed (network or quota issue)."

    # 2) Rule-based AI explanation
    suspicious_words = ['free-money', 'win-prize', '.ru', 'bit.ly']
    explanations = []

    for word in suspicious_words:
        if word in url.lower():
            if word == '.ru':
                explanations.append("Domain uses a foreign TLD often seen in spam.")
            elif word == 'bit.ly':
                explanations.append("Shortened URL can hide the real destination.")
            else:
                explanations.append("Contains typical scam keywords like free money or prizes.")

    if gs_risk == "Dangerous" or explanations:
        risk = 'High'
    else:
        risk = 'Low'

    combined_threat = gs_explanation
    if explanations:
        combined_threat += " " + " ".join(explanations)

    # 2b) Extra educational tip based on risk
    if risk == 'High':
        tip = (
            "Tip: Do not enter passwords or personal details on this site. "
            "Always double-check the sender and URL before clicking links."
        )
    else:
        tip = (
            "Tip: Even on safe-looking sites, avoid reusing passwords and "
            "always check the address bar before logging in."
        )

    combined_threat += " " + tip

    # 3) Save to DB
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (user_id, url, risk, details) VALUES (?, ?, ?, ?)",
        (user['id'], url, risk, combined_threat)
    )
    conn.commit()
    conn.close()

    return jsonify({
        'url': url,
        'risk': risk,
        'threat': combined_threat
    })

# ---------- Start app ----------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
