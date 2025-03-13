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
    session_id = request.cookies.get('session_id')
    if not session_id:
        return redirect(url_for('login'))  # Redirect to login if session is missing

    try:
        user_id, _ = session_id.split(':')
        user = db.session.get(User, int(user_id))
        if not user:
            return redirect(url_for('login'))  # Redirect if user not found
    except ValueError:
        return redirect(url_for('login'))  # Handle potential split errors

    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.delete_cookie('session_id')
    session.clear()
    return resp

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /admin\nAllow: /"

if __name__ == '__main__':
    app.run(ssl_context=('/workspaces/glowing-octo-adventure/cookie_monster_ctf/app/ssl/cert.pem', '/workspaces/glowing-octo-adventure/cookie_monster_ctf/app/ssl/key.pem'), host='0.0.0.0', port=8443)
