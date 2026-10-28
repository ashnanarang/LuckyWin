import os
import re
import secrets
import uuid
from datetime import datetime, timezone

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
CORS(app, origins=ALLOWED_ORIGINS, allow_headers=["Content-Type", "Authorization", "Idempotency-Key"])

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


@app.route("/api/admin/participants/count")
def admin_participant_count():
    if not is_admin():
        return jsonify(error="Unauthorized"), 401
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT COUNT(*) AS total FROM participants")
        total = cursor.fetchone()["total"]
    finally:
        cursor.close()
        db.close()
    return jsonify(eligible_count=total)


def create_draw(draw_type, winners):
    created_at = datetime.now(timezone.utc).isoformat()
    return {
        "id": str(uuid.uuid4()),
        "draw_type": draw_type,
        "status": "completed",
        "winner_count": len(winners),
        "created_at": created_at,
        "winners": winners,
    }


@app.route("/api/admin/draws/random", methods=["POST"])
def random_draw():
    if not is_admin():
        return jsonify(error="Unauthorized"), 401
    payload = request.get_json(silent=True) or {}
    try:
        count = int(payload.get("count"))
    except (TypeError, ValueError):
        return jsonify(error="Enter a valid winner count."), 400
    if count < 1 or count > 500:
        return jsonify(error="Winner count must be between 1 and 500."), 400

    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT id, name, age, ticket_number FROM participants ORDER BY id")
        participants = cursor.fetchall()
    finally:
        cursor.close()
        db.close()

    if count > len(participants):
        return jsonify(error="There are not enough registered participants."), 400

    selected = secrets.SystemRandom().sample(participants, count)
    winners = [{
        "id": person["id"],
        "name": person["name"],
        "age": person["age"],
        "ticket_number": person["ticket_number"],
        "counter_number": None,
    } for person in selected]
    return jsonify(draw=create_draw("random", winners))


@app.route("/api/admin/draws/manual", methods=["POST"])
def manual_draw():
    if not is_admin():
        return jsonify(error="Unauthorized"), 401
    payload = request.get_json(silent=True) or {}
    raw_ids = payload.get("participant_ids")
    if not isinstance(raw_ids, list) or not 1 <= len(raw_ids) <= 500:
        return jsonify(error="Select between 1 and 500 participants."), 400
    try:
        ids = [int(value) for value in raw_ids]
    except (TypeError, ValueError):
        return jsonify(error="Invalid participant selection."), 400
    if len(set(ids)) != len(ids):
        return jsonify(error="A participant can only be selected once."), 400

    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute(
            "SELECT id, name, age, ticket_number FROM participants WHERE id = ANY(%s)",
            (ids,),
        )
        found = cursor.fetchall()
    finally:
        cursor.close()
        db.close()

    by_id = {person["id"]: person for person in found}
    if len(by_id) != len(ids):
        return jsonify(error="One or more selected participants no longer exist."), 400
    winners = [{
        "id": by_id[person_id]["id"],
        "name": by_id[person_id]["name"],
        "age": by_id[person_id]["age"],
        "ticket_number": by_id[person_id]["ticket_number"],
        "counter_number": None,
    } for person_id in ids]
    return jsonify(draw=create_draw("manual", winners))


@app.route("/api/admin/draws", methods=["GET"])
def draw_history_unavailable():
    if not is_admin():
        return jsonify(error="Unauthorized"), 401
    # Draw results are kept in the admin's browser because this legacy production
    # database has no draw-history table. This route intentionally does not write.
    return jsonify(draws=[], total=0, page=1, pages=1)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")
