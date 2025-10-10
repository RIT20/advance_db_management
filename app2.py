from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import sqlite3
import os

# ---------------------------------------
# Flask setup
# ---------------------------------------
app = Flask(__name__)
app.secret_key = 'ritikojha00'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'blood_bank.db'


# ---------------------------------------
# Database helper functions
# ---------------------------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database from schema.sql"""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        print("✅ Database initialized successfully!")


# ---------------------------------------
# Flask-Login User class
# ---------------------------------------
class User(UserMixin):
    def __init__(self, id, username, user_type, organization_id=None):
        self.id = id
        self.username = username
        self.user_type = user_type
        self.organization_id = organization_id


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        return User(user['id'], user['username'], user['user_type'], user['organization_id'])
    return None


# ---------------------------------------
# Role-based access decorator
# ---------------------------------------
def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.user_type not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


# ---------------------------------------
# Routes
# ---------------------------------------

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['username'], user['user_type'], user['organization_id'])
            login_user(user_obj)
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type = request.form['user_type']

        db = get_db()

        # Check if username exists
        existing_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Username already exists', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)

        try:
            if user_type == 'donor':
                name = request.form['name']
                blood_type = request.form['blood_type']
                age = request.form['age']
                gender = request.form['gender']
                contact = request.form['contact']
                address = request.form['address']
                medical_history = request.form.get('medical_history', '')
                availability_type = request.form['availability_type']

                cursor = db.execute('''
                    INSERT INTO donors (name, blood_type, age, gender, contact, address, medical_history, availability_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (name, blood_type, age, gender, contact, address, medical_history, availability_type))
                donor_id = cursor.lastrowid

                db.execute('''
                    INSERT INTO users (username, password, user_type, organization_id)
                    VALUES (?, ?, ?, ?)
                ''', (username, hashed_password, user_type, donor_id))

            elif user_type in ['hospital', 'blood_bank']:
                org_name = request.form['org_name']
                location = request.form['location']
                contact = request.form['contact']

                if user_type == 'hospital':
                    cursor = db.execute('''
                        INSERT INTO hospitals (name, location, contact)
                        VALUES (?, ?, ?)
                    ''', (org_name, location, contact))
                else:
                    cursor = db.execute('''
                        INSERT INTO blood_banks (name, location, contact)
                        VALUES (?, ?, ?)
                    ''', (org_name, location, contact))

                org_id = cursor.lastrowid

                db.execute('''
                    INSERT INTO users (username, password, user_type, organization_id)
                    VALUES (?, ?, ?, ?)
                ''', (username, hashed_password, user_type, org_id))

            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()

    if current_user.user_type == 'hospital':
        hospital = db.execute('SELECT * FROM hospitals WHERE id = ?', (current_user.organization_id,)).fetchone()
        own_inventory = db.execute('SELECT * FROM hospital_inventory WHERE hospital_id = ?', (current_user.organization_id,)).fetchall()
        blood_bank_inventory = db.execute('''
            SELECT bb.name as blood_bank_name, bb.location, bbi.*
            FROM blood_bank_inventory bbi
            JOIN blood_banks bb ON bbi.blood_bank_id = bb.id
        ''').fetchall()
        nearby_hospitals = db.execute('''
            SELECT h.name, h.location, hi.*
            FROM hospital_inventory hi
            JOIN hospitals h ON hi.hospital_id = h.id
            WHERE h.id != ?
        ''', (current_user.organization_id,)).fetchall()

        return render_template('hospital_dashboard.html',
                               hospital=hospital,
                               own_inventory=own_inventory,
                               blood_bank_inventory=blood_bank_inventory,
                               nearby_hospitals=nearby_hospitals)

    elif current_user.user_type == 'blood_bank':
        blood_bank = db.execute('SELECT * FROM blood_banks WHERE id = ?', (current_user.organization_id,)).fetchone()
        inventory = db.execute('SELECT * FROM blood_bank_inventory WHERE blood_bank_id = ?', (current_user.organization_id,)).fetchall()
        return render_template('blood_bank_dashboard.html', blood_bank=blood_bank, inventory=inventory)

    elif current_user.user_type == 'donor':
        donor = db.execute('SELECT * FROM donors WHERE id = ?', (current_user.organization_id,)).fetchone()
        donations = db.execute('''
            SELECT t.*, h.name as hospital_name, bb.name as blood_bank_name
            FROM transfers t
            LEFT JOIN hospitals h ON t.to_hospital_id = h.id
            LEFT JOIN blood_banks bb ON t.to_blood_bank_id = bb.id
            WHERE t.from_donor_id = ?
            ORDER BY t.transfer_date DESC
        ''', (current_user.organization_id,)).fetchall()
        requests = db.execute('''
            SELECT br.*, h.name as hospital_name
            FROM blood_requests br
            JOIN hospitals h ON br.hospital_id = h.id
            WHERE br.blood_type = ? AND br.status = 'pending'
            ORDER BY br.request_date DESC
        ''', (donor['blood_type'],)).fetchall()
        return render_template('donor_dashboard.html', donor=donor, donations=donations, requests=requests)

    return render_template('dashboard.html')


# ---------------------------------------
# Start the app
# ---------------------------------------
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
