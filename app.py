import os
import re
import uuid

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Comma-separated list of allowed frontend origins, e.g. https://your-site.netlify.app
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("FRONTEND_ORIGINS", "http://localhost:8888").split(",") if o.strip()]
CORS(app, origins=ALLOWED_ORIGINS, allow_headers=["Content-Type", "Authorization"])

TOKEN_MAX_AGE = 60 * 60 * 8  # admin session lasts 8 hours
serializer = URLSafeTimedSerializer(app.secret_key or "dev-only-secret", salt="admin-token")


def get_db_connection():
    # Supabase Postgres connection string (use the Session pooler URI on Render)
    return psycopg2.connect(os.getenv("DATABASE_URL"), cursor_factory=RealDictCursor)


def is_admin():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False
    try:
        data = serializer.loads(header[7:], max_age=TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return False
    return data.get("admin") is True


def mask_phone(phone):
    return phone[:2] + "******" + phone[-2:]


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/register", methods=["POST"])
def register():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    phone = str(payload.get("phone", "")).strip()
    age = payload.get("age")

    if not name:
        return jsonify(error="Please enter your name."), 400
    if not re.fullmatch(r"\d{10}", phone):
        return jsonify(error="Please enter a valid 10-digit phone number."), 400
    try:
        age = int(age)
    except (TypeError, ValueError):
        return jsonify(error="Please enter a valid age."), 400

    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT ticket_number FROM participants WHERE phone = %s", (phone,))
        existing = cursor.fetchone()

        if existing:
            ticket = existing["ticket_number"]
        else:
            ticket = "LW-" + uuid.uuid4().hex[:8].upper()
            cursor.execute(
                "INSERT INTO participants (name, phone, age, ticket_number) VALUES (%s, %s, %s, %s)",
                (name, phone, age, ticket),
            )
            db.commit()
    finally:
        cursor.close()
        db.close()

    return jsonify(name=name, ticket=ticket, phone=mask_phone(phone))


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")

    if (
        os.getenv("ADMIN_USERNAME")
        and username == os.getenv("ADMIN_USERNAME")
        and password == os.getenv("ADMIN_PASSWORD")
    ):
        return jsonify(token=serializer.dumps({"admin": True}))

    return jsonify(error="Invalid username or password."), 401


@app.route("/api/admin/participants")
def admin_participants():
    if not is_admin():
        return jsonify(error="Unauthorized"), 401

    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute(
            "SELECT id, name, phone, age, ticket_number, created_at FROM participants ORDER BY id DESC"
        )
        participants = cursor.fetchall()
    finally:
        cursor.close()
        db.close()

    for p in participants:
        p["created_at"] = p["created_at"].isoformat() if p["created_at"] else None

    return jsonify(participants=participants)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")
