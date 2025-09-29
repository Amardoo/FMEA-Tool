# Simple Flask app to demonstrate FMEA with SQLite database
# Includes form page, dashboard, and reports page
# Uses Chart.js for charts and jsPDF for PDF export
# Added authentication with sign up, sign in, and session management
# Added success message with RPN after form submission
# Run with: python app.py
# Access at: http://127.0.0.1:5000/

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure random key

# Initialize database
def init_db():
    conn = sqlite3.connect('fmea.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS failure_modes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  step TEXT,
                  failure_mode TEXT,
                  cause TEXT,
                  control TEXT,
                  effect TEXT,
                  s INTEGER,
                  o INTEGER,
                  d INTEGER,
                  rpn INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT)''')
    conn.commit()
    conn.close()

# Retrieve all data
def get_all_data():
    conn = sqlite3.connect('fmea.db')
    c = conn.cursor()
    c.execute('SELECT id, step, failure_mode, cause, control, effect, s, o, d, rpn FROM failure_modes ORDER BY rpn DESC')
    rows = c.fetchall()
    data = [{
        'id': row[0],
        'Step': row[1],
        'Failure Mode': row[2],
        'Cause': row[3],
        'Control': row[4],
        'Effect': row[5],
        'S': row[6],
        'O': row[7],
        'D': row[8],
        'RPN': row[9]
    } for row in rows]
    conn.close()
    return data

# Get statistics
def get_stats(data):
    if not data:
        return {'average': 0, 'max': 0, 'min': 0, 'high_risk': 0}
    df = pd.DataFrame(data)
    avg_rpn = df['RPN'].mean()
    max_rpn = df['RPN'].max()
    min_rpn = df['RPN'].min()
    high_risk = len(df[df['RPN'] > 60])
    return {'average': round(avg_rpn, 2), 'max': max_rpn, 'min': min_rpn, 'high_risk': high_risk}

# Get additional stats for dashboard
def get_additional_stats(data):
    if not data:
        return {'severity': 0, 'occurrence': 0, 'detection': 0}, {}
    df = pd.DataFrame(data)
    avg_scores = {
        'severity': round(df['S'].mean(), 2),
        'occurrence': round(df['O'].mean(), 2),
        'detection': round(df['D'].mean(), 2)
    }
    severity_dist = df['S'].value_counts().sort_index().to_dict()
    return avg_scores, severity_dist

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('fmea.db')
        c = conn.cursor()
        
        if action == 'signup':
            try:
                hashed_pw = generate_password_hash(password)
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))
                conn.commit()
                session['user'] = username
                return redirect(url_for('home'))
            except sqlite3.IntegrityError:
                error = 'Username already exists.'
        
        elif action == 'signin':
            c.execute('SELECT password FROM users WHERE username = ?', (username,))
            row = c.fetchone()
            if row and check_password_hash(row[0], password):
                session['user'] = username
                return redirect(url_for('home'))
            else:
                error = 'Invalid username or password.'
        
        conn.close()
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# Home page route
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# Redirect root URL to /login
@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/form', methods=['GET', 'POST'])
@login_required
def form():
    error = None
    success = None
    rpn = None
    if request.method == 'POST':
        step = request.form.get('step')
        failure_mode = request.form.get('failure_mode')
        cause = request.form.get('cause')
        control = request.form.get('control')
        effect = request.form.get('effect')
        try:
            s = int(request.form.get('severity'))
            o = int(request.form.get('occurrence'))
            d = int(request.form.get('detection'))
        except (TypeError, ValueError):
            error = 'Severity, Occurrence, and Detection must be numbers between 1 and 10.'
            return render_template('form.html', error=error, success=success, rpn=rpn)

        if not all([step, failure_mode, cause, control, effect, s, o, d]):
            error = 'All fields are required.'
            return render_template('form.html', error=error, success=success, rpn=rpn)
        if not (1 <= s <= 10 and 1 <= o <= 10 and 1 <= d <= 10):
            error = 'Values must be between 1 and 10.'
            return render_template('form.html', error=error, success=success, rpn=rpn)

        rpn = s * o * d
        conn = sqlite3.connect('fmea.db')
        c = conn.cursor()
        c.execute('INSERT INTO failure_modes (step, failure_mode, cause, control, effect, s, o, d, rpn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                  (step, failure_mode, cause, control, effect, s, o, d, rpn))
        conn.commit()
        conn.close()
        success = f'Failure mode added successfully! Calculated RPN: {rpn}'
        return render_template('form.html', error=error, success=success, rpn=rpn)
    return render_template('form.html', error=error, success=success, rpn=rpn)

@app.route('/dashboard')
@login_required
def dashboard():
    data = get_all_data()
    stats = get_stats(data)
    top_5 = sorted(data, key=lambda x: x['RPN'], reverse=True)[:6]
    risk_dist = {'Low (0-30)': len([d for d in data if d['RPN'] <= 30]),
                 'Medium (31-60)': len([d for d in data if 31 <= d['RPN'] <= 60]),
                 'High (>60)': len([d for d in data if d['RPN'] > 60])}
    avg_scores, severity_dist = get_additional_stats(data)
    return render_template('dashboard.html', data=data, stats=stats, top_5=top_5, risk_dist=risk_dist, avg_scores=avg_scores, severity_dist=severity_dist)

@app.route('/reports')
@login_required
def reports():
    data = get_all_data()
    stats = get_stats(data)
    return render_template('reports.html', data=data, stats=stats)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)