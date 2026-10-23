import os
import sqlite3
import secrets
from functools import wraps

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DATABASE = os.environ.get("DATABASE_PATH", "mywg.db")

FRONTEND_URL = os.environ.get(
    "FRONTEND_URL",
    "https://mywg-studios.onrender.com"
)

CORS(
    app,
    origins=[FRONTEND_URL],
    supports_credentials=True
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None"
)


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


initialize_database()


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Please log in first."}), 401

        return function(*args, **kwargs)

    return wrapper


@app.route("/")
def home():
    return jsonify({
        "name": "MYWG Studios API",
        "status": "online"
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "online"})


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(email, str):
        return jsonify({"error": "Invalid details."}), 400

    if not isinstance(password, str):
        return jsonify({"error": "Invalid password."}), 400

    if not 3 <= len(username) <= 20:
        return jsonify({
            "error": "Username must be 3–20 characters."
        }), 400

    if not all(c.isalnum() or c in "_-" for c in username):
        return jsonify({
            "error": "Username can only contain letters, numbers, _ and -."
        }), 400

    if len(email) > 254 or "@" not in email:
        return jsonify({"error": "Enter a valid email address."}), 400

    if not 12 <= len(password) <= 128:
        return jsonify({
            "error": "Password must be 12–128 characters."
        }), 400

    password_hash = generate_password_hash(password)

    try:
        with get_db() as db:
            cursor = db.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )
            user_id = cursor.lastrowid

        session.clear()
        session["user_id"] = user_id

        return jsonify({
            "message": "Account created successfully!",
            "user": {
                "id": user_id,
                "username": username,
                "email": email
            }
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "That username or email is already registered."
        }), 409


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    identifier = data.get("identifier", "").strip()
    password = data.get("password", "")

    if not isinstance(identifier, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid login details."}), 400

    with get_db() as db:
        user = db.execute(
            """
            SELECT * FROM users
            WHERE username = ? OR email = ?
            """,
            (identifier, identifier.lower())
        ).fetchone()

    if not user or not check_password_hash(
        user["password_hash"], password
    ):
        return jsonify({
            "error": "Incorrect username, email or password."
        }), 401

    session.clear()
    session["user_id"] = user["id"]

    return jsonify({
        "message": "Logged in successfully!",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"]
        }
    })


@app.route("/api/me")
@login_required
def me():
    with get_db() as db:
        user = db.execute(
            "SELECT id, username, email FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    if not user:
        session.clear()
        return jsonify({"error": "Account not found."}), 404

    return jsonify({"user": dict(user)})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."})


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
