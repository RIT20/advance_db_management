from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = 'ritikojha00'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'blood_bank.db'

# Database helper functions
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# User class for Flask-Login
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

# Role-based access control decorator
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

# Routes
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
                # Donor registration
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
                # Hospital or Blood Bank registration
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
        # Hospital dashboard
        hospital = db.execute('SELECT * FROM hospitals WHERE id = ?', (current_user.organization_id,)).fetchone()
        
        # Get hospital's own inventory
        own_inventory = db.execute('''
            SELECT * FROM hospital_inventory WHERE hospital_id = ?
        ''', (current_user.organization_id,)).fetchall()
        
        # Get blood bank inventories
        blood_bank_inventory = db.execute('''
            SELECT bb.name as blood_bank_name, bb.location, bbi.*
            FROM blood_bank_inventory bbi
            JOIN blood_banks bb ON bbi.blood_bank_id = bb.id
        ''').fetchall()
        
        # Get nearby hospital inventories
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
        # Blood bank dashboard
        blood_bank = db.execute('SELECT * FROM blood_banks WHERE id = ?', (current_user.organization_id,)).fetchone()
        
        # Get inventory
        inventory = db.execute('''
            SELECT * FROM blood_bank_inventory WHERE blood_bank_id = ?
        ''', (current_user.organization_id,)).fetchall()
        
        return render_template('blood_bank_dashboard.html',
                             blood_bank=blood_bank,
                             inventory=inventory)
    
    elif current_user.user_type == 'donor':
        # Donor dashboard
        donor = db.execute('SELECT * FROM donors WHERE id = ?', (current_user.organization_id,)).fetchone()
        
        # Get donor's donation history
        donations = db.execute('''
            SELECT t.*, h.name as hospital_name, bb.name as blood_bank_name
            FROM transfers t
            LEFT JOIN hospitals h ON t.to_hospital_id = h.id
            LEFT JOIN blood_banks bb ON t.to_blood_bank_id = bb.id
            WHERE t.from_donor_id = ?
            ORDER BY t.transfer_date DESC
        ''', (current_user.organization_id,)).fetchall()
        
        # Get active requests matching donor's blood type
        requests = db.execute('''
            SELECT br.*, h.name as hospital_name
            FROM blood_requests br
            JOIN hospitals h ON br.hospital_id = h.id
            WHERE br.blood_type = ? AND br.status = 'pending'
            ORDER BY br.request_date DESC
        ''', (donor['blood_type'],)).fetchall()
        
        return render_template('donor_dashboard.html',
                             donor=donor,
                             donations=donations,
                             requests=requests)
    
    return render_template('dashboard.html')

@app.route('/inventory/update', methods=['POST'])
@login_required
@role_required('hospital', 'blood_bank')
def update_inventory():
    blood_type = request.form['blood_type']
    units = int(request.form['units'])
    
    db = get_db()
    
    if current_user.user_type == 'hospital':
        # Check if inventory exists
        existing = db.execute('''
            SELECT * FROM hospital_inventory 
            WHERE hospital_id = ? AND blood_type = ?
        ''', (current_user.organization_id, blood_type)).fetchone()
        
        if existing:
            db.execute('''
                UPDATE hospital_inventory 
                SET units = ?, last_updated = ?
                WHERE hospital_id = ? AND blood_type = ?
            ''', (units, datetime.now(), current_user.organization_id, blood_type))
        else:
            db.execute('''
                INSERT INTO hospital_inventory (hospital_id, blood_type, units, last_updated)
                VALUES (?, ?, ?, ?)
            ''', (current_user.organization_id, blood_type, units, datetime.now()))
    
    elif current_user.user_type == 'blood_bank':
        existing = db.execute('''
            SELECT * FROM blood_bank_inventory 
            WHERE blood_bank_id = ? AND blood_type = ?
        ''', (current_user.organization_id, blood_type)).fetchone()
        
        if existing:
            db.execute('''
                UPDATE blood_bank_inventory 
                SET units = ?, last_updated = ?
                WHERE blood_bank_id = ? AND blood_type = ?
            ''', (units, datetime.now(), current_user.organization_id, blood_type))
        else:
            db.execute('''
                INSERT INTO blood_bank_inventory (blood_bank_id, blood_type, units, last_updated)
                VALUES (?, ?, ?, ?)
            ''', (current_user.organization_id, blood_type, units, datetime.now()))
    
    db.commit()
    flash('Inventory updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/request/create', methods=['POST'])
@login_required
@role_required('hospital')
def create_request():
    blood_type = request.form['blood_type']
    units_needed = int(request.form['units_needed'])
    urgency = request.form['urgency']
    patient_info = request.form.get('patient_info', '')
    
    db = get_db()
    db.execute('''
        INSERT INTO blood_requests (hospital_id, blood_type, units_needed, urgency, patient_info, status, request_date)
        VALUES (?, ?, ?, ?, ?, 'pending', ?)
    ''', (current_user.organization_id, blood_type, units_needed, urgency, patient_info, datetime.now()))
    db.commit()
    
    flash('Blood request created successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/request/<int:request_id>/respond', methods=['POST'])
@login_required
@role_required('donor')
def respond_to_request(request_id):
    db = get_db()
    
    # Get donor info
    donor = db.execute('SELECT * FROM donors WHERE id = ?', (current_user.organization_id,)).fetchone()
    
    # Get request info
    blood_request = db.execute('SELECT * FROM blood_requests WHERE id = ?', (request_id,)).fetchone()
    
    if not blood_request or blood_request['status'] != 'pending':
        flash('This request is no longer available.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Create a transfer record
    db.execute('''
        INSERT INTO transfers (from_donor_id, to_hospital_id, blood_type, units, transfer_date)
        VALUES (?, ?, ?, 1, ?)
    ''', (current_user.organization_id, blood_request['hospital_id'], donor['blood_type'], datetime.now()))
    
    # Update request status if fulfilled
    current_units = blood_request['units_needed']
    if current_units <= 1:
        db.execute('UPDATE blood_requests SET status = "fulfilled" WHERE id = ?', (request_id,))
    else:
        db.execute('UPDATE blood_requests SET units_needed = ? WHERE id = ?', (current_units - 1, request_id))
    
    db.commit()
    
    flash('Thank you for responding! The hospital has been notified.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/transfers')
@login_required
def view_transfers():
    db = get_db()
    
    if current_user.user_type == 'hospital':
        # Hospital can see received transfers
        transfers = db.execute('''
            SELECT t.*, 
                   d.name as donor_name, d.gender as donor_gender, d.age as donor_age, d.medical_history,
                   bb.name as blood_bank_name,
                   h.name as hospital_name
            FROM transfers t
            LEFT JOIN donors d ON t.from_donor_id = d.id
            LEFT JOIN blood_banks bb ON t.from_blood_bank_id = bb.id
            LEFT JOIN hospitals h ON t.from_hospital_id = h.id
            WHERE t.to_hospital_id = ?
            ORDER BY t.transfer_date DESC
        ''', (current_user.organization_id,)).fetchall()
    
    elif current_user.user_type == 'blood_bank':
        # Blood bank can see sent and received transfers
        transfers = db.execute('''
            SELECT t.*, 
                   d.name as donor_name,
                   h.name as hospital_name
            FROM transfers t
            LEFT JOIN donors d ON t.from_donor_id = d.id
            LEFT JOIN hospitals h ON t.to_hospital_id = h.id
            WHERE t.from_blood_bank_id = ? OR t.to_blood_bank_id = ?
            ORDER BY t.transfer_date DESC
        ''', (current_user.organization_id, current_user.organization_id)).fetchall()
    
    else:
        transfers = []
    
    return render_template('transfers.html', transfers=transfers)

@app.route('/api/inventory/<blood_type>')
@login_required
def get_inventory_api(blood_type):
    db = get_db()
    
    data = {
        'blood_banks': [],
        'hospitals': []
    }
    
    if current_user.user_type == 'hospital':
        # Get blood bank inventory
        blood_banks = db.execute('''
            SELECT bb.name, bb.location, bbi.units
            FROM blood_bank_inventory bbi
            JOIN blood_banks bb ON bbi.blood_bank_id = bb.id
            WHERE bbi.blood_type = ?
        ''', (blood_type,)).fetchall()
        
        data['blood_banks'] = [dict(row) for row in blood_banks]
        
        # Get other hospital inventory
        hospitals = db.execute('''
            SELECT h.name, h.location, hi.units
            FROM hospital_inventory hi
            JOIN hospitals h ON hi.hospital_id = h.id
            WHERE hi.blood_type = ? AND h.id != ?
        ''', (blood_type, current_user.organization_id)).fetchall()
        
        data['hospitals'] = [dict(row) for row in hospitals]
    
    return jsonify(data)

# if __name__ == '__main__':
#     init_db()
#     app.run(debug=True)

if __name__ == '__main__':
    import os
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
