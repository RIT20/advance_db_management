# app2.py  — BLOOD BRIDGE (per-bank accept/reject)

# app2.py  — BLOOD BRIDGE (per-bank accept/reject)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import hmac
import os
import sqlite3
import pandas as pd

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'blood_bank.db')

# ----------------------------------
# Request status helpers
# ----------------------------------
REQUEST_STATUS_OPEN = "OPEN"
REQUEST_STATUS_CLAIMED = "CLAIMED"
REQUEST_STATUS_PARTIAL = "PARTIAL"
REQUEST_STATUS_FULFILLED = "FULFILLED"
REQUEST_STATUS_REJECTED = "REJECTED"  # global reject (per-bank rejections are tracked separately)

VALID_REQUEST_STATUSES = {
    REQUEST_STATUS_OPEN,
    REQUEST_STATUS_CLAIMED,
    REQUEST_STATUS_PARTIAL,
    REQUEST_STATUS_FULFILLED,
    REQUEST_STATUS_REJECTED,
}  # <-- keep this closing brace!

# ----------------------------------
# App / Login setup
# ----------------------------------
app = Flask(__name__)
app.secret_key = 'ritikojha00'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ----------------------------------
# Paths / DB
# ----------------------------------
DATABASE = 'blood_bank.db'
ORG_CSV = os.path.join('organization.csv')   # org_id, org_type, name, address, city, state, zip, phone, email
INV_CSV = os.path.join('inventory.csv')      # org_id, blood_type, component, units, updated_at
CREDS_CSV = os.path.join('users.csv')        # username, password (PLAIN), id (=org_id), role

# ----------------------------------
# DB helpers
# ----------------------------------
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

# ----------------------------------
# Schema
# ----------------------------------
def init_sql_schema_if_needed():
    """
    Create minimal schema for organization + inventory + users + requests/logs (if not present).
    Uses TEXT org_id as FK from inventory/users/requests -> organization(org_id).
    """
    db = get_db()

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

    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role     TEXT NOT NULL,
        org_id   TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organization(org_id)
    );
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS requests (
        request_id   INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id       TEXT NOT NULL,            -- hospital org_id
        blood_type   TEXT NOT NULL,
        component    TEXT NOT NULL,
        units        INTEGER NOT NULL,
        level        TEXT,                     -- optional urgency
        status       TEXT NOT NULL DEFAULT 'OPEN',  -- OPEN / CLAIMED / PARTIAL / FULFILLED / REJECTED
        created_at   TEXT NOT NULL,
        accepted_by_bank_id TEXT,              -- which bank is handling (claim/accept)
        decision_note       TEXT,              -- optional note
        decision_at         TEXT,              -- when a bank acted
        FOREIGN KEY (org_id) REFERENCES organization(org_id)
    );
    """)

    db.execute("""
    CREATE TABLE IF NOT EXISTS transaction_logs (
        transaction_id           INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id               INTEGER,                  -- may be NULL if ad-hoc shipment
        requester_entity_type    TEXT,                     -- 'HOSPITAL'
        requester_entity_id      TEXT,                     -- hospital org_id
        fulfilled_by_entity_type TEXT,                     -- 'BANK'
        fulfilled_by_entity_id   TEXT,                     -- bank org_id
        blood_type               TEXT,
        component                TEXT,
        units_fulfilled          INTEGER,
        level                    TEXT,
        fulfilled_at             TEXT NOT NULL,
        FOREIGN KEY (request_id) REFERENCES requests(request_id),
        FOREIGN KEY (requester_entity_id) REFERENCES organization(org_id),
        FOREIGN KEY (fulfilled_by_entity_id) REFERENCES organization(org_id)
    );
    """)

    # NEW: Per-bank request state (REJECTED / CLAIMED / ACCEPTED) — bank-specific
    db.execute("""
    CREATE TABLE IF NOT EXISTS bank_request_states (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        bank_id    TEXT    NOT NULL,
        state      TEXT    NOT NULL,             -- 'REJECTED' | 'CLAIMED' | 'ACCEPTED'
        note       TEXT,
        acted_at   TEXT    NOT NULL,
        UNIQUE(request_id, bank_id),
        FOREIGN KEY (request_id) REFERENCES requests(request_id),
        FOREIGN KEY (bank_id)    REFERENCES organization(org_id)
    );
    """)

    db.commit()

# ----------------------------------
# One-time CSV bootstrap (idempotent)
# ----------------------------------
def import_csvs_into_sqlite():
    db = get_db()

    # ---- organization
    if os.path.exists(ORG_CSV):
        org_df = pd.read_csv(ORG_CSV)
        required = ["org_id","org_type","name","address","city","state","zip","phone","email"]
        missing = [c for c in required if c not in org_df.columns]
        if missing:
            raise RuntimeError(f"organization.csv missing columns: {missing}")
        org_df = org_df[required].dropna(subset=["org_id","org_type"]).drop_duplicates(subset=["org_id"])
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

    # ---- inventory
    if os.path.exists(INV_CSV):
        inv_df = pd.read_csv(INV_CSV)
        need = ["org_id","blood_type","component","units","updated_at"]
        for c in need:
            if c not in inv_df.columns:
                raise RuntimeError(f"inventory.csv missing required column: {c}")
        inv_df = inv_df[need].copy()
        for _, r in inv_df.iterrows():
            units = int(r["units"]) if pd.notna(r["units"]) else None
            db.execute("""
                INSERT INTO inventory (org_id, blood_type, component, units, updated_at)
                VALUES (?, ?, ?, ?, ?);
            """, (str(r["org_id"]), str(r["blood_type"]), str(r["component"]), units, str(r["updated_at"])))
        db.commit()

    # ---- users
    if os.path.exists(CREDS_CSV):
        creds_df = pd.read_csv(CREDS_CSV)
        need = ["username","password","id","role"]  # id == org_id in your CSV
        for c in need:
            if c not in creds_df.columns:
                raise RuntimeError(f"users.csv missing column: {c}")
        for _, r in creds_df.iterrows():
            username = normalize_username(r["username"])
            plain_pw = str(r["password"])
            org_id   = str(r["id"])
            role     = str(r["role"]).upper().strip()
            org = db.execute("SELECT org_id FROM organization WHERE org_id = ?;", (org_id,)).fetchone()
            if not org:
                continue
            hashed = generate_password_hash(plain_pw)
            ex = db.execute("SELECT id FROM users WHERE username = ?;", (username,)).fetchone()
            if ex:
                db.execute("""
                    UPDATE users
                       SET password = ?, role = ?, org_id = ?
                     WHERE username = ?;
                """, (hashed, role, org_id, username))
            else:
                db.execute("""
                    INSERT INTO users (username, password, role, org_id)
                    VALUES (?, ?, ?, ?);
                """, (username, hashed, role, org_id))
        db.commit()

def ensure_indexes():
    db = get_db()

    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_inventory_orgid ON inventory(org_id);")
    except Exception:
        pass

    try:
        idx_rows = db.execute("PRAGMA index_list('users');").fetchall()
        idx_names = {r['name'] if isinstance(r, sqlite3.Row) else r[1] for r in idx_rows}
        if 'idx_users_orgid' in idx_names:
            info = db.execute("PRAGMA index_info('idx_users_orgid');").fetchall()
            cols = [row['name'] if isinstance(row, sqlite3.Row) else row[2] for row in info]
            if cols != ['org_id']:
                db.execute("DROP INDEX IF EXISTS idx_users_orgid;")
        db.execute("CREATE INDEX IF NOT EXISTS idx_users_orgid ON users(org_id);")
    except Exception:
        pass

    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_org_city_state ON organization(city, state);")
    except Exception:
        pass

    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_requests_org ON requests(org_id);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reqs_status ON requests(status);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_txn_req ON transaction_logs(request_id);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_txn_fulfiller ON transaction_logs(fulfilled_by_entity_id);")
    except Exception:
        pass

    # NEW indexes for per-bank states
    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_brs_req ON bank_request_states(request_id);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_brs_bank ON bank_request_states(bank_id);")
    except Exception:
        pass

    db.commit()

# ----------------------------------
# User model
# ----------------------------------
class User(UserMixin):
    __slots__ = ("id", "username", "role", "org_id")
    def __init__(self, user_pk, username, role, org_id):
        self.id = str(user_pk)
        self.username = username
        self.role = role
        self.org_id = str(org_id)
    def get_id(self) -> str:
        return self.id

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute(
        "SELECT id AS user_pk, username, role, org_id FROM users WHERE id = ?;",
        (user_id,)
    ).fetchone()
    if row:
        return User(row["user_pk"], row["username"], row["role"], row["org_id"])
    return None

# ----------------------------------
# Auth utils
# ----------------------------------
def verify_password(plain_text: str, stored_value: str) -> bool:
    if stored_value is None:
        return False
    try:
        stored_str = stored_value.decode("utf-8")
    except (AttributeError, UnicodeDecodeError):
        stored_str = str(stored_value)
    prefix = stored_str.split(":", 1)[0].lower()
    if ":" in stored_str and prefix in {"scrypt", "pbkdf2:sha256", "pbkdf2:sha1", "argon2"}:
        try:
            return check_password_hash(stored_str, plain_text)
        except Exception:
            pass
    return hmac.compare_digest(stored_str, plain_text)

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

def upsert_inventory(db, org_id: str, blood_type: str, component: str, delta_units: int):
    row = db.execute("""
        SELECT id, units FROM inventory
         WHERE org_id=? AND blood_type=? AND component=?
        ORDER BY id LIMIT 1;
    """, (org_id, blood_type, component)).fetchone()
    now = datetime.utcnow().isoformat(timespec="seconds")
    if row:
        new_units = max(0, int(row["units"] or 0) + int(delta_units))
        db.execute("""
            UPDATE inventory
               SET units=?, updated_at=?
             WHERE id=?;
        """, (new_units, now, row["id"]))
    else:
        new_units = max(0, int(delta_units))
        db.execute("""
            INSERT INTO inventory (org_id, blood_type, component, units, updated_at)
            VALUES (?, ?, ?, ?, ?);
        """, (org_id, blood_type, component, new_units, now))

def find_bank_with_stock(db, blood_type: str, component: str, min_units: int):
    return db.execute("""
        SELECT o.org_id AS bank_id, COALESCE(i.units,0) AS units
          FROM organization o
          JOIN inventory   i ON i.org_id = o.org_id
         WHERE upper(o.org_type)='BANK'
           AND i.blood_type=? AND i.component=? AND COALESCE(i.units,0) >= ?
         ORDER BY i.units DESC, o.org_id
         LIMIT 1;
    """, (blood_type, component, min_units)).fetchone()

def log_transaction(db, request_id, requester_org, fulfiller_org, blood_type, component, units, level):
    now = datetime.utcnow().isoformat(timespec="seconds")
    db.execute("""
        INSERT INTO transaction_logs
        (request_id, requester_entity_type, requester_entity_id,
         fulfilled_by_entity_type, fulfilled_by_entity_id,
         blood_type, component, units_fulfilled, level, fulfilled_at)
        VALUES
        (?, 'HOSPITAL', ?, 'BANK', ?, ?, ?, ?, ?, ?);
    """, (request_id, requester_org, fulfiller_org, blood_type, component, int(units), level, now))

# ----------------------------------
# Small helpers
# ----------------------------------
def get_bank_stock(db, bank_org_id: str, blood_type: str, component: str) -> int:
    row = db.execute("""
        SELECT COALESCE(units, 0) AS units
          FROM inventory
         WHERE org_id=? AND blood_type=? AND component=?
         ORDER BY datetime(COALESCE(updated_at, '1970-01-01T00:00:00')) DESC
         LIMIT 1;
    """, (bank_org_id, blood_type, component)).fetchone()
    return int(row["units"] if row else 0)

def clamp(n, lo, hi):
    return max(lo, min(hi, n))

# NEW: record this bank's state for a specific request
def set_bank_request_state(db, request_id: int, bank_id: str, state: str, note: str = None):
    now = datetime.utcnow().isoformat(timespec="seconds")
    ex = db.execute("""
        SELECT id FROM bank_request_states
         WHERE request_id=? AND bank_id=?;
    """, (request_id, bank_id)).fetchone()
    if ex:
        db.execute("""
            UPDATE bank_request_states
               SET state=?, note=?, acted_at=?
             WHERE id=?;
        """, (state, note, now, ex["id"]))
    else:
        db.execute("""
            INSERT INTO bank_request_states (request_id, bank_id, state, note, acted_at)
            VALUES (?, ?, ?, ?, ?);
        """, (request_id, bank_id, state, note, now))

# ----------------------------------
# Routes
# ----------------------------------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/request/new', methods=['GET', 'POST'])
@login_required
def new_request():
    db = get_db()
    if request.method == 'POST':
        blood_type = (request.form.get('blood_type') or '').strip().upper()
        component  = (request.form.get('component') or '').strip().upper()
        units      = int(request.form.get('units') or 0)
        level      = (request.form.get('level') or '').strip().upper()
        if not blood_type or not component or units <= 0:
            flash('Please provide blood type, component, and units (>0).', 'danger')
            return redirect(url_for('new_request'))
        now = datetime.utcnow().isoformat(timespec="seconds")
        cur = db.execute("""
            INSERT INTO requests (org_id, blood_type, component, units, level, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'OPEN', ?);
        """, (current_user.org_id, blood_type, component, units, level, now))
        request_id = cur.lastrowid

        bank = find_bank_with_stock(db, blood_type, component, units)
        if bank:
            bank_id = bank["bank_id"]
            upsert_inventory(db, bank_id, blood_type, component, -units)       # bank --
            upsert_inventory(db, current_user.org_id, blood_type, component, +units)  # hospital ++
            log_transaction(db, request_id, current_user.org_id, bank_id, blood_type, component, units, level)
            db.execute("UPDATE requests SET status='FULFILLED', accepted_by_bank_id=? WHERE request_id=?;", (bank_id, request_id))
            set_bank_request_state(db, request_id, bank_id, "ACCEPTED", "auto-fulfill")
            db.commit()
            flash(f"Request #{request_id} auto-fulfilled by BANK {bank_id} with {units} units of {blood_type} {component}.", "success")
        else:
            db.commit()
            flash(f"Request #{request_id} created. No bank with sufficient stock found yet.", "warning")
        return redirect(url_for('dashboard'))

    return render_template('request_form.html', org=current_user.org_id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    flash('Self-registration is disabled. Please use the credentials provided.', 'info')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_in = (request.form.get('username') or '').strip()
        password_in = (request.form.get('password') or '')
        if not username_in or not password_in:
            flash('Enter both username and password.', 'danger')
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute("""
            SELECT id AS user_pk, username, password, role, org_id
            FROM users
            WHERE lower(username) = lower(?);
        """, (username_in,)).fetchone()
        if user and verify_password(password_in, user['password']):
            user_obj = User(user['user_pk'], user['username'], user['role'], user['org_id'])
            login_user(user_obj)
            flash(f"Welcome, {user['username']}!", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

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
    org = db.execute("""
        SELECT org_id, org_type, name, address, city, state, zip, phone, email
        FROM organization
        WHERE org_id = ?;
    """, (current_user.org_id,)).fetchone()

    inventory_rows = db.execute("""
        SELECT org_id, blood_type, component, units, updated_at
        FROM inventory
        WHERE org_id = ?
        ORDER BY datetime(updated_at) DESC, blood_type, component;
    """, (current_user.org_id,)).fetchall()

    return render_template('org_dashboard.html', org=org, inventory=inventory_rows)

@app.route('/requests')
@login_required
def view_requests():
    db = get_db()

    # Requests created by *this* org
    my_requests = db.execute("""
        SELECT request_id, org_id, blood_type, component, units,
               level, status, created_at, accepted_by_bank_id, decision_note, decision_at
          FROM requests
         WHERE org_id = ?
         ORDER BY datetime(created_at) DESC;
    """, (current_user.org_id,)).fetchall()

    fulfilled = []
    if current_user.role.upper() == "BANK":
        # All hospital requests + this bank's state
        all_hospital_requests = db.execute("""
            SELECT r.request_id, r.org_id AS hospital_id, r.blood_type, r.component, r.units,
                   r.level, r.status, r.created_at, r.accepted_by_bank_id, r.decision_note, r.decision_at,
                   o.name AS hospital_name, o.city, o.state,
                   (
                     SELECT s.state
                       FROM bank_request_states s
                      WHERE s.request_id = r.request_id AND s.bank_id = ?
                      LIMIT 1
                   ) AS my_bank_state
              FROM requests r
              JOIN organization o ON o.org_id = r.org_id
             WHERE UPPER(o.org_type)='HOSPITAL'
             ORDER BY datetime(r.created_at) DESC;
        """, (current_user.org_id,)).fetchall()

        fulfilled = db.execute("""
            SELECT t.transaction_id, t.request_id,
                   t.requester_entity_id AS hospital,
                   t.blood_type, t.component, t.units_fulfilled,
                   t.level, t.fulfilled_at
              FROM transaction_logs t
             WHERE t.fulfilled_by_entity_id = ?
             ORDER BY datetime(t.fulfilled_at) DESC;
        """, (current_user.org_id,)).fetchall()

        return render_template(
            'requests.html',
            org=current_user.org_id,
            role=current_user.role,
            my_requests=my_requests,
            requests=my_requests,                  # alias for your template
            all_hospital_requests=all_hospital_requests,
            fulfilled=fulfilled
        )

    # Non-BANK users
    return render_template(
        'requests.html',
        org=current_user.org_id,
        role=current_user.role,
        my_requests=my_requests,
        requests=my_requests,                      # alias for your template
        fulfilled=fulfilled
    )

# ---------------------------
# BANK actions
# ---------------------------
@app.route('/requests/accept/<int:request_id>', methods=['POST'])
@login_required
@role_required('BANK')
def accept_request(request_id):
    db = get_db()

    req = db.execute("""
        SELECT request_id, org_id AS hospital_id, blood_type, component,
               units, status, accepted_by_bank_id
          FROM requests
         WHERE request_id = ?;
    """, (request_id,)).fetchone()

    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for('view_requests'))

    bank_id = current_user.org_id

    # If someone else already claimed/accepted, block
    if req["accepted_by_bank_id"] and req["accepted_by_bank_id"] != bank_id:
        flash(f"Request #{request_id} is already being handled by BANK {req['accepted_by_bank_id']}.", "warning")
        return redirect(url_for('view_requests'))

    hospital_id = req["hospital_id"]
    blood_type  = req["blood_type"]
    component   = req["component"]
    need_units  = int(req["units"])

    # Optional partial units from form
    try:
        requested_to_fulfill = int(request.form.get("units") or need_units)
    except Exception:
        requested_to_fulfill = need_units
    requested_to_fulfill = clamp(requested_to_fulfill, 1, need_units)

    available = get_bank_stock(db, bank_id, blood_type, component)
    to_ship   = clamp(min(available, requested_to_fulfill), 0, need_units)

    note = (request.form.get("note") or "").strip()
    now  = datetime.utcnow().isoformat(timespec="seconds")

    if to_ship <= 0:
        # Claim the request globally; mark this bank as handling
        db.execute("""
            UPDATE requests
               SET status=?,
                   accepted_by_bank_id=?,
                   decision_note=?,
                   decision_at=?
             WHERE request_id=?;
        """, (REQUEST_STATUS_CLAIMED, bank_id, note, now, request_id))
        set_bank_request_state(db, request_id, bank_id, "CLAIMED", note)
        db.commit()
        flash(f"Request #{request_id} claimed by your bank; no stock moved yet.", "info")
        return redirect(url_for('view_requests'))

    # Move inventory atomically
    try:
        upsert_inventory(db, bank_id, blood_type, component, -to_ship)      # decrement bank
        upsert_inventory(db, hospital_id, blood_type, component, +to_ship)  # increment hospital
        log_transaction(db, request_id, hospital_id, bank_id, blood_type, component, to_ship, level=None)

        if to_ship == need_units:
            new_status = REQUEST_STATUS_FULFILLED
        else:
            db.execute("UPDATE requests SET units = units - ? WHERE request_id=?;", (to_ship, request_id))
            new_status = REQUEST_STATUS_PARTIAL

        db.execute("""
            UPDATE requests
               SET status=?,
                   accepted_by_bank_id=?,
                   decision_note=?,
                   decision_at=?
             WHERE request_id=?;
        """, (new_status, bank_id, note, now, request_id))

        set_bank_request_state(db, request_id, bank_id, "ACCEPTED", note)
        db.commit()

        msg = f"Request #{request_id} {'fulfilled' if new_status==REQUEST_STATUS_FULFILLED else 'partially fulfilled'} with {to_ship} units."
        flash(msg, "success")
    except Exception as e:
        db.rollback()
        flash(f"Failed to accept/fulfill: {e}", "danger")

    return redirect(url_for('view_requests'))

@app.route('/requests/reject/<int:request_id>', methods=['POST'])
@login_required
@role_required('BANK')
def reject_request(request_id):
    db = get_db()

    req = db.execute("""
        SELECT request_id, accepted_by_bank_id
          FROM requests
         WHERE request_id=?;
    """, (request_id,)).fetchone()

    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for('view_requests'))

    # If another bank already claimed/accepted, don't let this bank act
    if req["accepted_by_bank_id"] and req["accepted_by_bank_id"] != current_user.org_id:
        flash(f"Request #{request_id} is already being handled by BANK {req['accepted_by_bank_id']}.", "warning")
        return redirect(url_for('view_requests'))

    note = (request.form.get("note") or "").strip()
    set_bank_request_state(db, request_id, current_user.org_id, "REJECTED", note)
    db.commit()

    flash(f"Request #{request_id} rejected for your bank only.", "info")
    return redirect(url_for('view_requests'))

# Simple API to fetch current org's inventory
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

def has_column(db, table: str, col: str) -> bool:
    info = db.execute(f"PRAGMA table_info('{table}');").fetchall()
    names = {r["name"] if isinstance(r, sqlite3.Row) else r[1] for r in info}
    return col in names

def run_db_migrations():
    """
    One-shot migrations for older DBs.
    - Ensure users.org_id exists; if not, add it and backfill from users.id.
    - Ensure requests extra columns exist.
    - Ensure inventory has an 'id' primary key (migrate if missing).
    - Ensure per-bank request state table & indexes exist.
    """
    db = get_db()

    # users.org_id
    if table_exists(db, "users") and not has_column(db, "users", "org_id"):
        db.execute('ALTER TABLE "users" ADD COLUMN "org_id" TEXT;')
        db.execute("UPDATE users SET org_id = CAST(id AS TEXT) WHERE org_id IS NULL;")
        db.commit()

    # users(org_id) index
    try:
        info = db.execute("PRAGMA index_list('users');").fetchall()
        names = {r['name'] if isinstance(r, sqlite3.Row) else r[1] for r in info}
        if "idx_users_orgid" in names:
            cols = db.execute("PRAGMA index_info('idx_users_orgid');").fetchall()
            colnames = [c['name'] if isinstance(c, sqlite3.Row) else c[2] for c in cols]
            if colnames != ["org_id"]:
                db.execute("DROP INDEX IF EXISTS idx_users_orgid;")
        db.execute("CREATE INDEX IF NOT EXISTS idx_users_orgid ON users(org_id);")
        db.commit()
    except Exception:
        pass

    # Ensure requests extra columns
    def _ensure_col(table: str, col: str, ddl: str):
        if table_exists(db, table) and not has_column(db, table, col):
            db.execute(f'ALTER TABLE "{table}" ADD COLUMN "{col}" {ddl};')

    _ensure_col("requests", "accepted_by_bank_id", "TEXT")
    _ensure_col("requests", "decision_note", "TEXT")
    _ensure_col("requests", "decision_at", "TEXT")

    try:
        db.execute("UPDATE requests SET status='OPEN' WHERE status IS NULL OR TRIM(status)='';")
    except Exception:
        pass

    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_requests_accepted_by ON requests(accepted_by_bank_id);")
    except Exception:
        pass

    # Ensure inventory has id
    try:
        if table_exists(db, "inventory") and not has_column(db, "inventory", "id"):
            db.execute("""
                CREATE TABLE inventory_new (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id     TEXT NOT NULL,
                    blood_type TEXT,
                    component  TEXT,
                    units      INTEGER,
                    updated_at TEXT,
                    FOREIGN KEY (org_id) REFERENCES organization(org_id)
                );
            """)
            db.execute("""
                INSERT INTO inventory_new (org_id, blood_type, component, units, updated_at)
                SELECT org_id, blood_type, component, units, updated_at FROM inventory;
            """)
            db.execute("DROP TABLE inventory;")
            db.execute("ALTER TABLE inventory_new RENAME TO inventory;")
            db.execute("CREATE INDEX IF NOT EXISTS idx_inventory_orgid ON inventory(org_id);")
            db.commit()
    except Exception:
        pass

    # Ensure per-bank states table & indexes
    db.execute("""
    CREATE TABLE IF NOT EXISTS bank_request_states (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        bank_id    TEXT    NOT NULL,
        state      TEXT    NOT NULL,
        note       TEXT,
        acted_at   TEXT    NOT NULL,
        UNIQUE(request_id, bank_id),
        FOREIGN KEY (request_id) REFERENCES requests(request_id),
        FOREIGN KEY (bank_id)    REFERENCES organization(org_id)
    );
    """)
    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_brs_req ON bank_request_states(request_id);")
        db.execute("CREATE INDEX IF NOT EXISTS idx_brs_bank ON bank_request_states(bank_id);")
    except Exception:
        pass

    db.commit()

# ----------------------------------
# App entry
# ----------------------------------
def first_run_bootstrap():
    if not os.path.exists(DATABASE):
        open(DATABASE, "a").close()
    init_sql_schema_if_needed()
    run_db_migrations()
    import_csvs_into_sqlite()
    ensure_indexes()

if __name__ == '__main__':
    first_run_bootstrap()
    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "1") == "1"
    )
