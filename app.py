from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "trainerhub.db")

# ┌─────────────────────────────────────────────────────────┐
# │  STANDARD ADMIN CODE — only people who know this code   │
# │  can register as an admin. Change it to anything you    │
# │  want. Keep it secret!                                  │
# └─────────────────────────────────────────────────────────┘
ADMIN_CODE = "TRAINER@2026"


# ── Create tables on startup ──────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Students table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            role       TEXT    NOT NULL DEFAULT 'student',
            created_at TEXT    NOT NULL
        )
    ''')

    # Admins table (separate from students)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            admin_code TEXT    NOT NULL,
            created_at TEXT    NOT NULL
        )
    ''')

    # Login logs (tracks both student and admin logins)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'student',
            created_at TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print("  ✓ Database ready → trainerhub.db")
    print(f"  ✓ Admin code   → {ADMIN_CODE}")


# ── Helper: get DB connection ─────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Serve HTML page ───────────────────────────────────────────────
@app.route("/")
def home():
    for name in ["home.html", "index.html"]:
        if os.path.exists(os.path.join(BASE_DIR, name)):
            return send_from_directory(BASE_DIR, name)
    return "home.html not found in project folder", 404

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)


# ── STUDENT SIGN UP ──────────────────────────────────────────────
@app.route("/signup", methods=["POST"])
def signup():
    data     = request.get_json()
    name     = data.get("name", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400

    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()

        if existing:
            return jsonify({"success": False, "message": "Email already registered."}), 409

        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO users (name, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, email, generate_password_hash(password), "student", now)
        )
        conn.commit()
        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        print(f"[SIGNUP] ✓  id={user_id}  name={name}  email={email}  role=student")
        return jsonify({
            "success": True,
            "message": "Student account created successfully!",
            "data": {"id": user_id, "name": name, "email": email, "role": "student", "created_at": now}
        }), 201

    except Exception as e:
        print(f"[SIGNUP] ❌  {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()


# ── ADMIN SIGN UP (requires admin code) ──────────────────────────
@app.route("/admin-signup", methods=["POST"])
def admin_signup():
    data       = request.get_json()
    name       = data.get("name", "").strip()
    email      = data.get("email", "").strip().lower()
    password   = data.get("password", "")
    admin_code = data.get("admin_code", "").strip()

    if not name or not email or not password or not admin_code:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400

    # Verify admin code
    if admin_code != ADMIN_CODE:
        return jsonify({"success": False, "message": "Invalid admin code. Access denied."}), 403

    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM admins WHERE email = ?", (email,)
        ).fetchone()

        if existing:
            return jsonify({"success": False, "message": "Admin email already registered."}), 409

        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO admins (name, email, password, admin_code, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, email, generate_password_hash(password), admin_code, now)
        )
        conn.commit()
        admin_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        print(f"[ADMIN SIGNUP] ✓  id={admin_id}  name={name}  email={email}")
        return jsonify({
            "success": True,
            "message": "Admin account created successfully!",
            "data": {"id": admin_id, "name": name, "email": email, "role": "admin", "created_at": now}
        }), 201

    except Exception as e:
        print(f"[ADMIN SIGNUP] ❌  {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()


# ── LOGIN (student or admin — queries separate tables) ───────────
@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role     = data.get("role", "student")

    if not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    conn = get_db()
    try:
        if role == "admin":
            # Query ADMINS table
            user = conn.execute(
                "SELECT * FROM admins WHERE email = ?", (email,)
            ).fetchone()
        else:
            # Query USERS (students) table
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()

        if not user or not check_password_hash(user["password"], password):
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        # Log the login
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO login_logs (email, role, created_at) VALUES (?, ?, ?)",
            (email, role, now)
        )
        conn.commit()
        log_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        print(f"[LOGIN]  ✓  log_id={log_id}  role={role}  email={email}")
        return jsonify({
            "success": True,
            "message": f"Logged in successfully as {role.capitalize()}!",
            "data": {"id": user["id"], "name": user["name"], "email": email, "role": role}
        }), 200

    except Exception as e:
        print(f"[LOGIN]  ❌  {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()


# ── View stored students ──────────────────────────────────────────
@app.route("/users", methods=["GET"])
def get_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, email, created_at FROM users"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── View stored admins ────────────────────────────────────────────
@app.route("/admins", methods=["GET"])
def get_admins():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, email, created_at FROM admins"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── View login logs ───────────────────────────────────────────────
@app.route("/logs", methods=["GET"])
def get_logs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM login_logs").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Run ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  TrainerHub Flask Server")
    print("=" * 50)
    print("  Home   → http://localhost:5000")
    print("  Users  → http://localhost:5000/users")
    print("  Admins → http://localhost:5000/admins")
    print("  Logs   → http://localhost:5000/logs")
    print("=" * 50)
    app.run(debug=True, port=5000)