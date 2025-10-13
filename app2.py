from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3, os, csv
from functools import wraps
import pandas as pd

app = Flask(__name__)
app.secret_key = 'ritikojha00'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'blood_bank.db'
ORG_CSV = os.path.join('organization.csv')
INV_CSV = os.path.join('inventory.csv')
CREDS_CSV = os.path.join('users.csv')   # generated file
# CREDS_CSV = os.path.join('auth_plain.csv')   # generated file

# ------------------------
# DB helpers
# ------------------------
import os
import re
import sqlite3
import pandas as pd
from datetime import datetime
from werkzeug.security import generate_password_hash

# -----------------------------
# DB + paths
# -----------------------------
DATABASE = 'blood_bank.db'
ORG_CSV = os.path.join('organization.csv')   # file with org_id, org_type, name, address, city, state, zip, phone, email
INV_CSV = os.path.join('inventory.csv')      # file with org_id, blood_type, component, units, updated_at
CREDS_CSV = os.path.join('users.csv')   # file with username, password (PLAIN), id (=org_id), role

# -----------------------------
# Connections / utils
# -----------------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def table_exists(db, name):
    return db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;",
        (name,)
    ).fetchone() is not None

def normalize_username(name: str) -> str:
    return (
        str(name)
        .strip()
        .lower()
        .replace(' ', '_')
        .replace('/', '_')
        .replace('\\', '_')
    )

# -----------------------------
# Schema aligned to your screenshots
# -----------------------------
def init_sql_schema_if_needed():
    """
    Create minimal schema for organization + inventory + users (if not present).
    Uses org_id TEXT as the foreign key from inventory/users -> organization.
    """
    db = get_db()

    # organization (singular), with full columns
    db.execute("""
    CREATE TABLE IF NOT EXISTS organization (
        org_id   TEXT PRIMARY KEY,
        org_type TEXT NOT NULL,
        name     TEXT,
        address  TEXT,
        city     TEXT,
        state    TEXT,
        zip      TEXT,
        phone    TEXT,
        email    TEXT
    );
    """)

    # inventory (singular), FK by org_id
    db.execute("""
    CREATE TABLE IF NOT EXISTS inventory (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id     TEXT NOT NULL,
        blood_type TEXT,
        component  TEXT,
        units      INTEGER,
        updated_at TEXT,
        FOREIGN KEY (org_id) REFERENCES organization(org_id)
    );
    """)

    # users mapped to org_id (from auth_plain.csv)
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,     -- hashed
        role     TEXT NOT NULL,     -- e.g., BANK / HOSPITAL / ...
        org_id   TEXT NOT NULL,     -- maps to organization.org_id
        FOREIGN KEY (org_id) REFERENCES organization(org_id)
    );
    """)

    # helpful indexes
    db.execute("CREATE INDEX IF NOT EXISTS idx_inventory_orgid ON inventory(org_id);")
    db.execute("CREATE INDEX IF NOT EXISTS idx_users_orgid ON users(id);")
    db.execute("CREATE INDEX IF NOT EXISTS idx_org_city_state ON organization(city, state);")

    db.commit()

# -----------------------------
# One-time CSV bootstrap (safe to re-run)
# -----------------------------
def import_csvs_into_sqlite():
    """
    Imports data from organization.csv, inventory.csv, auth_plain.csv
    into tables: organization, inventory, users.
    - Upserts organization by org_id
    - Replaces/loads inventory
    - Upserts users by username, hashing the auth_plain passwords
    """
    db = get_db()

    # ---- 1) organization
    if os.path.exists(ORG_CSV):
        org_df = pd.read_csv(ORG_CSV)
        required = ["org_id","org_type","name","address","city","state","zip","phone","email"]
        missing = [c for c in required if c not in org_df.columns]
        if missing:
            raise RuntimeError(f"organization.csv missing columns: {missing}")
        org_df = org_df[required].dropna(subset=["org_id","org_type"]).drop_duplicates(subset=["org_id"])

        # upsert by org_id
        for _, r in org_df.iterrows():
            db.execute("""
                INSERT INTO organization (org_id, org_type, name, address, city, state, zip, phone, email)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id) DO UPDATE SET
                  org_type=excluded.org_type,
                  name=excluded.name,
                  address=excluded.address,
                  city=excluded.city,
                  state=excluded.state,
                  zip=excluded.zip,
                  phone=excluded.phone,
                  email=excluded.email;
            """, (str(r["org_id"]), str(r["org_type"]), str(r["name"]), str(r["address"]), str(r["city"]),
                  str(r["state"]), str(r["zip"]), str(r["phone"]), str(r["email"])))
        db.commit()

    # ---- 2) inventory
    if os.path.exists(INV_CSV):
        inv_df = pd.read_csv(INV_CSV)
        need = ["org_id","blood_type","component","units","updated_at"]
        for c in need:
            if c not in inv_df.columns:
                raise RuntimeError(f"inventory.csv missing required column: {c}")
        inv_df = inv_df[need].copy()

        # replace whole table for simplicity (comment out to do incremental)
        # db.execute("DELETE FROM inventory;")

        for _, r in inv_df.iterrows():
            units = int(r["units"]) if pd.notna(r["units"]) else None
            db.execute("""
                INSERT INTO inventory (org_id, blood_type, component, units, updated_at)
                VALUES (?, ?, ?, ?, ?);
            """, (str(r["org_id"]), str(r["blood_type"]), str(r["component"]), units, str(r["updated_at"])))
        db.commit()

    # ---- 3) users from auth_plain.csv
    # auth_plain: username, password (plain), id (=org_id), role
    if os.path.exists(CREDS_CSV):
        creds_df = pd.read_csv(CREDS_CSV)
        need = ["username","password","id","role"]
        for c in need:
            if c not in creds_df.columns:
                raise RuntimeError(f"users.csv missing column: {c}")
        # normalize usernames; ensure org exists
        for _, r in creds_df.iterrows():
            username = normalize_username(r["username"])
            plain_pw = str(r["password"])
            org_id   = str(r["id"])
            role     = str(r["role"]).upper().strip()

            # only create user if org exists (avoid orphans)
            org = db.execute("SELECT org_id FROM organization WHERE org_id = ?;", (org_id,)).fetchone()
            if not org:
                # skip or create a minimal shell org; here we skip
                continue

            hashed = generate_password_hash(plain_pw)

            # upsert by username
            ex = db.execute("SELECT id FROM users WHERE username = ?;", (username,)).fetchone()
            if ex:
                db.execute("""
                    UPDATE users SET password = ?, role = ?, id = ?
                    WHERE username = ?;
                """, (hashed, role, org_id, username))
            else:
                db.execute("""
                    INSERT INTO users (username, password, role, org_id)
                    VALUES (?, ?, ?, ?);
                """, (username, hashed, role, org_id))
        db.commit()

# -----------------------------
# Queries aligned to new schema
# -----------------------------
def get_org_inventory_rows(db, org_id: str):
    """
    Return the inventory rows for the given org_id (e.g., 'C001').
    """
    return db.execute("""
        SELECT i.org_id, i.blood_type, i.component, i.units, i.updated_at
        FROM inventory i
        WHERE i.org_id = ?
        ORDER BY datetime(i.updated_at) DESC, i.blood_type, i.component;
    """, (org_id,)).fetchall()

def ensure_indexes():
    db = get_db()
    db.execute("CREATE INDEX IF NOT EXISTS idx_inventory_orgid ON inventory(org_id);")
    db.execute("CREATE INDEX IF NOT EXISTS idx_users_orgid ON users(org_id);")
    db.execute("CREATE INDEX IF NOT EXISTS idx_org_city_state ON organization(city, state);")
    db.commit()

# ------------------------
# User model
# ------------------------
# ------------------------
# User model (updated for users: username, password, role, org_id)
# ------------------------
class User(UserMixin):
    def __init__(self, username: str, role: str, id: str):
        # self.id = id
        self.username = username
        self.role = role              # e.g., BANK / HOSPITAL / etc.
        self.org_id = id          # maps to organization.org_id (TEXT)

    # Backward-compat: existing code may reference `user_type` and `organization_id`
    @property
    def user_type(self):
        return self.role

    @property
    def organization_id(self):
        return self.org_id

    # Flask-Login expects a string ID
    # def get_id(self):
    #     return str(self.id)


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute(
        "SELECT id, username, role  FROM users WHERE id = ?;",
        (user_id,)
    ).fetchone()
    if row:
        return User(row["id"], row["username"], row["role"])
    return None


# ------------------------
# Routes
# ------------------------
# ------------------------
# RBAC helper (updated to use role)
# ------------------------
def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


# ------------------------
# Routes
# ------------------------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# --- Self-registration is disabled (keep placeholder so templates don’t error) ---
# @app.route('/register', methods=['GET', 'POST'])
# def register_placeholder():
#     flash('Self-registration is disabled. Please use the credentials provided.', 'info')
    # return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    flash('Self-registration is disabled. Please use the credentials provided.', 'info')
    return redirect(url_for('login'))



# # --- Single unified login using new `users` table (username/password -> role, org_id) ---
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username_in = request.form.get('username', '').strip().lower().replace(' ', '_')
#         password_in = request.form.get('password', '')

#         db = get_db()
#         user = db.execute("""
#             SELECT id, username, password, role
#             FROM users
#             WHERE username = ?;
#         """, (username_in,)).fetchone()

#         if user and check_password_hash(user['password'], password_in):
#             # User model already updated earlier: User(id, username, role, org_id)
#             user_obj = User(user['id'], user['username'], user['role'])
#             login_user(user_obj)
#             flash(f'Welcome, {user["username"]}!', 'success')
#             return redirect(url_for('dashboard'))

#         flash('Invalid username or password', 'danger')

#     return render_template('login.html')  # keep your existing template

from werkzeug.security import check_password_hash

def verify_password(plain_text: str, stored_hash: str) -> bool:
    """
    Compare a plain-text password against a stored hash.
    Usage mirrors your example with check_password_hash().
    """
    return check_password_hash(stored_hash, plain_text)


# --- Single unified login using new `users` table (username/password -> role, org_id) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Plain text from the form:
        username_in = (request.form.get('username') or '').strip().lower().replace(' ', '_')
        password_in = (request.form.get('password') or '')  # plain text

        db = get_db()
        # Pull the stored hash + org_id
        user = db.execute("""
            SELECT id, username, password, role
            FROM users
            WHERE username = ?;
        """, (username_in,)).fetchone()

        # stored_hash = user['password']; compare with the plain text from the form
        if user and verify_password(password_in, user['password']):
            # build User with org_id (so dashboard can fetch inventory by org_id)
            user_obj = User(user['id'], user['username'], user['role'])
            login_user(user_obj)
            flash(f"Welcome, {user['username']}!", 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')  # keep your existing template


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --- Dashboard: show inventory for the logged-in user's org_id ---
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()

    # Pull organization row for context (name/address, etc.)
    org = db.execute("""
        SELECT org_id, org_type, name, address, city, state, zip, phone, email
        FROM organization
        WHERE org_id = ?;
    """, (current_user.org_id,)).fetchone()

    # Inventory scoped to this org_id
    inventory_rows = db.execute("""
        SELECT org_id, blood_type, component, units, updated_at
        FROM inventory
        WHERE org_id = ?
        ORDER BY datetime(updated_at) DESC, blood_type, component;
    """, (current_user.org_id,)).fetchall()

    # Render a single org dashboard (simplest)
    return render_template('org_dashboard.html', org=org, inventory=inventory_rows)


# --- Simple API to fetch current org's inventory (handy for XHR on dashboard) ---
@app.route('/api/org/inventory')
@login_required
def api_org_inventory():
    db = get_db()
    rows = db.execute("""
        SELECT org_id, blood_type, component, units, updated_at
        FROM inventory
        WHERE org_id = ?
        ORDER BY datetime(updated_at) DESC, blood_type, component;
    """, (current_user.org_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

# ------------------------
# App entry
# ------------------------
def first_run_bootstrap():
    # Create tables if missing and load CSVs to match your new schema
    init_sql_schema_if_needed()
    import_csvs_into_sqlite()
    # Optional: build helpful indexes
    try:
        ensure_indexes()
    except Exception:
        pass  # safe if ensure_indexes isn't defined

# if __name__ == "__main__":
#     import os

#     # Ensure the DB file exists before connecting
#     if not os.path.exists(DATABASE):
#         open(DATABASE, "a").close()

#     # One-time bootstrap (idempotent: safe to run every start)
#     first_run_bootstrap()

#     # Run the app
#     app.run(
#         host=os.getenv("HOST", "0.0.0.0"),
#         port=int(os.getenv("PORT", "5000")),
#         debug=os.getenv("FLASK_DEBUG", "1") == "1"
#     )
if __name__ == '__main__':
    import os
    # if not os.path.exists(DATABASE):
        # init_db()
    app.run(debug=True)
