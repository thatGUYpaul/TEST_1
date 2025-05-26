from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import mysql.connector
from mysql.connector import Error
import re
import random
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# MySQL Configuration for XAMPP
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',  # Default XAMPP username
    'password': '',  # Default XAMPP password (empty)
    'database': 'network_model',
    'port': 3306  # Default MySQL port in XAMPP
}


# Database setup
def init_db():
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        print("Database initialized successfully")

    except Error as e:
        print(f"Error initializing database: {e}")
        flash('Database initialization failed', 'error')
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


# Helper functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    return True, "Password is valid"


def user_exists(username, email):
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id FROM users WHERE username = %s OR email = %s',
            (username, email)
        )
        return cursor.fetchone() is not None
    except Error as e:
        print(f"Error checking user existence: {e}")
        return False
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def create_user(username, email, password):
    password_hash = generate_password_hash(password)
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)',
            (username, email, password_hash)
        )
        conn.commit()
        return True
    except Error as e:
        print(f"Error creating user: {e}")
        return False
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def authenticate_user(username, password):
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, password_hash FROM users WHERE username = %s',
            (username,)
        )
        row = cursor.fetchone()

        if row and check_password_hash(row[1], password):
            return row[0]
        return None
    except Error as e:
        print(f"Error authenticating user: {e}")
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('register'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm_password']

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters long")
        if not validate_email(email):
            errors.append("Please enter a valid email address")
        valid_pw, msg = validate_password(password)
        if not valid_pw:
            errors.append(msg)
        if password != confirm:
            errors.append("Passwords do not match")
        if user_exists(username, email):
            errors.append("Username or email already exists")

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('registration.html')

        if create_user(username, email, password):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'error')

    return render_template('registration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_id = authenticate_user(username, password)
        if user_id:
            session['user_id'] = user_id
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('Dashboard.html', username=session.get('username'))


@app.route('/api/alert-trends')
@login_required
def alert_trends():
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    counts = [random.randint(5, 50) for _ in range(12)]
    return jsonify({'labels': months, 'counts': counts})

@app.route('/api/traffic')
@login_required
def traffic_data():
    hours = [f"{i:02d}:00" for i in range(24)]
    inbound = [random.randint(1000, 50000) for _ in range(24)]
    outbound = [random.randint(500, 25000) for _ in range(24)]
    return jsonify({
        'labels': hours,
        'inbound': inbound,
        'outbound': outbound
    })

@app.route('/api/alerts')
@login_required
def recent_alerts():
    alert_types = ['DDoS', 'Brute Force', 'SQL Injection', 'XSS', 'Malware']
    severities = ['Critical', 'High', 'Medium', 'Low']
    alerts = []
    for i in range(5):
        alerts.append({
            'type': random.choice(alert_types),
            'source_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'time_reported': (datetime.now() - timedelta(hours=random.randint(1,24)))\
                            .strftime('%Y-%m-%dT%H:%M:%S'),
            'severity': random.choice(severities)
        })
    return jsonify(alerts)

@app.route('/api/vulnerabilities')
@login_required
def vulnerabilities():
    return jsonify({
        'labels': ['Critical', 'High', 'Medium', 'Low'],
        'counts': [random.randint(1,10) for _ in range(4)]
    })

@app.route('/api/attack-sources')
@login_required
def attack_sources():
    return jsonify({
        'labels': ['External', 'Internal'],
        'percentages': [random.randint(60,90), random.randint(10,40)]
    })

@app.route('/api/attack-vectors')
@login_required
def attack_vectors():
    vectors = ['Phishing', 'Malware', 'DDoS', 'MITM', 'Zero-Day']
    return jsonify({
        'labels': vectors,
        'counts': [random.randint(5,30) for _ in range(len(vectors))]
    })


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)