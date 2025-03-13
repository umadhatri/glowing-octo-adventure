#!/bin/bash

# ===============================
# Cookie Monster CTF Challenge Setup Script
# Challenge: CSRF with SameSite Bypass
# ===============================

set -e  # Exit immediately on error

# Text colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "   _____            _    _        __  __                 _            "
echo "  / ____|          | |  (_)      |  \/  |               | |           "
echo " | |     ___   ___ | | ___ ___   | \  / | ___  _ __  ___| |_ ___ _ __ "
echo " | |    / _ \ / _ \| |/ | / _ \  | |\/| |/ _ \| '_ \/ __| __/ _ \ '__|"
echo " | |___| (_) | (_) | |  | |  __/ | |  | | (_) | | | \__ \ ||  __/ |   "
echo "  \_____\___/ \___/|_|  |_|\___| |_|  |_|\___/|_| |_|___/\__\___|_|   "
echo -e "${NC}"
echo -e "${YELLOW}CSRF with SameSite Bypass Challenge${NC}"
echo ""

# Configuration variables
CHALLENGE_PORT=8443
CHALLENGE_DIR="$HOME/cookie_monster_ctf"
FLAG_FILE="$CHALLENGE_DIR/app/flag.txt"

# Check if the challenge is already installed
if [ -d "$CHALLENGE_DIR" ]; then
    echo -e "${YELLOW}Challenge directory already exists. Reinstall?${NC}"
    read -p "Reinstall? (y/n): " choice
    if [ "$choice" != "y" ]; then
        echo "Exiting without changes."
        exit 0
    fi
    rm -rf "$CHALLENGE_DIR"
fi

# Create challenge directory
echo -e "${GREEN}Creating challenge directory...${NC}"
mkdir -p "$CHALLENGE_DIR/app/static" "$CHALLENGE_DIR/app/templates" "$CHALLENGE_DIR/app/ssl"

# Install required dependencies
echo -e "${GREEN}Installing dependencies...${NC}"
if [[ "$(uname -s)" == "Linux" ]]; then
    sudo apt update && sudo apt install -y python3 python3-pip openssl
elif [[ "$(uname -s)" == "Darwin" ]]; then
    brew install python3 openssl
fi

pip3 install flask flask-sqlalchemy flask-wtf pymysql pyopenssl --user

# Generate SSL certificate
echo -e "${GREEN}Generating SSL certificate...${NC}"
openssl req -x509 -newkey rsa:4096 -nodes -out "$CHALLENGE_DIR/app/ssl/cert.pem" -keyout "$CHALLENGE_DIR/app/ssl/key.pem" -days 365 -subj "/CN=localhost/O=Cookie Monster CTF"

# Generate random flag
echo -e "${GREEN}Generating random flag...${NC}"
FLAG="flag{$(head /dev/urandom | tr -dc 'a-zA-Z0-9_' | fold -w 32 | head -n 1)}"
echo "$FLAG" > "$FLAG_FILE"
chmod 600 "$FLAG_FILE"
echo -e "${GREEN}Flag generated.${NC}"

# Create the main Flask application
echo -e "${GREEN}Creating Flask application...${NC}"
cat > "$CHALLENGE_DIR/app/app.py" << 'EOF'
from flask import Flask, render_template, request, make_response, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os, time, random, string

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Integer, default=100)

def set_password(self, password):
    self.password_hash = generate_password_hash(password)

def check_password(self, password):
    return check_password_hash(self.password_hash, password)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin_password')
        db.session.add(admin)
    if not User.query.filter_by(username='user').first():
        user = User(username='user')
        user.set_password('user_password')
        db.session.add(user)
    db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('session_id', f"{user.id}:{int(time.time())}", max_age=3600, secure=True, httponly=True, samesite='Lax')
            session['user_id'] = user.id
            return resp
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /admin\nAllow: /"

if __name__ == '__main__':
    app.run(ssl_context=('ssl/cert.pem', 'ssl/key.pem'), host='0.0.0.0', port=8443)
EOF

# Create a basic UI with hints and red herrings
echo -e "${GREEN}Creating UI files...${NC}"
cat > "$CHALLENGE_DIR/app/templates/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Cookie Monster CTF</title>
</head>
<body>
    <h1>Welcome to Cookie Monster CTF</h1>
    <a href="/login">Login</a>
    <!-- Hint: CSRF is powerful when methods change -->
    <!-- Red Herring: 'X-Frame-Options: DENY' header is a decoy -->
</body>
</html>
EOF

# Set up file permissions
chmod -R 755 "$CHALLENGE_DIR"

# Final message
echo -e "${GREEN}Setup complete! Run the challenge with:${NC}"
echo -e "${YELLOW}cd $CHALLENGE_DIR/app && python3 app.py${NC}"