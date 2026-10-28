import os
import re
import secrets
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
    counter_number = str(payload.get("counter_number", "")).strip() or None

    if not name:
        return jsonify(error="Please enter your name."), 400
    if not re.fullmatch(r"\d{10}", phone):
        return jsonify(error="Please enter a valid 10-digit phone number."), 400
    try:
        age = int(age)
    except (TypeError, ValueError):
        return jsonify(error="Please enter a valid age."), 400
    if not 1 <= age <= 120:
        return jsonify(error="Please enter an age from 1 to 120."), 400
    if counter_number and (len(counter_number) > 32 or not re.fullmatch(r"[\\w-]+", counter_number, flags=re.ASCII)):
        return jsonify(error="Please enter a valid counter number."), 400

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
                "INSERT INTO participants (name, phone, age, ticket_number, counter_number) VALUES (%s, %s, %s, %s, %s)",
                (name, phone, age, ticket, counter_number),
            )
            db.commit()
    finally:
        cursor.close()
        db.close()

    return jsonify(name=name, ticket=ticket, phone=mask_phone(phone), counter_number=counter_number)


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


def json_draw(cursor, draw_id):
    cursor.execute(
        "SELECT id, draw_type, winner_count, status, created_at, created_by FROM draws WHERE id = %s",
        (draw_id,),
    )
    draw = cursor.fetchone()
    if not draw:
        return None
    created_at = draw["created_at"]
    draw["created_at"] = created_at.isoformat() if created_at else None
    cursor.execute(
        """
        SELECT p.id, p.name, p.ticket_number, p.counter_number
        FROM draw_winners AS dw
        JOIN participants AS p ON p.id = dw.participant_id
        WHERE dw.draw_id = %s
        ORDER BY dw.position
        """,
        (draw_id,),
    )
    draw["winners"] = cursor.fetchall()
    return draw


def admin_required_response():
    return jsonify(error="Unauthorized"), 401


@app.route("/api/admin/participants/count")
def participant_count():
    if not is_admin():
        return admin_required_response()
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT count(*) AS total FROM participants")
        return jsonify(eligible_count=cursor.fetchone()["total"])
    except psycopg2.Error:
        if db:
            db.rollback()
        app.logger.exception("Participant count query failed")
        return jsonify(error="Lucky Win is temporarily unavailable. Please try again shortly."), 503
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


def _idempotency_key():
    key = request.headers.get("Idempotency-Key", "")
    try:
        return str(uuid.UUID(key)) if key else str(uuid.uuid4())
    except (ValueError, AttributeError):
        return None


@app.route("/api/admin/draws/random", methods=["POST"])
def random_draw():
    if not is_admin():
        return admin_required_response()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Enter a valid winner count."), 400
    count_value = payload.get("count")
    if isinstance(count_value, bool) or not isinstance(count_value, (int, str)):
        return jsonify(error="Enter a valid winner count."), 400
    try:
        count = int(count_value)
    except (TypeError, ValueError):
        return jsonify(error="Enter a valid winner count."), 400
    if not 1 <= count <= 500:
        return jsonify(error="Select between 1 and 500 winners."), 400
    request_key = _idempotency_key()
    if request_key is None:
        return jsonify(error="Invalid draw request key."), 400

    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        # Serialize retries with the same key so a network retry cannot create a second draw.
        cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s), 0)", (request_key,))
        cursor.execute("SELECT id FROM draws WHERE request_key = %s", (request_key,))
        previous = cursor.fetchone()
        if previous:
            draw = json_draw(cursor, previous["id"])
            db.commit()
            return jsonify(draw=draw), 200

        cursor.execute("SELECT id FROM participants ORDER BY id")
        eligible_ids = [row["id"] for row in cursor.fetchall()]
        if count > len(eligible_ids):
            db.rollback()
            return jsonify(error="Winner count exceeds the eligible participant count."), 400

        winner_ids = secrets.SystemRandom().sample(eligible_ids, count)
        cursor.execute(
            """
            INSERT INTO draws (draw_type, winner_count, status, request_key, created_by)
            VALUES ('random', %s, 'completed', %s, %s)
            RETURNING id
            """,
            (count, request_key, os.getenv("ADMIN_USERNAME")),
        )
        draw_id = cursor.fetchone()["id"]
        cursor.executemany(
            "INSERT INTO draw_winners (draw_id, participant_id, position) VALUES (%s, %s, %s)",
            [(draw_id, participant_id, position) for position, participant_id in enumerate(winner_ids, 1)],
        )
        draw = json_draw(cursor, draw_id)
        db.commit()
        return jsonify(draw=draw), 201
    except psycopg2.Error:
        if db:
            db.rollback()
        app.logger.exception("Random draw failed")
        return jsonify(error="Lucky Win is temporarily unavailable. Please try again shortly."), 503
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


@app.route("/api/admin/draws")
def draw_history():
    if not is_admin():
        return admin_required_response()
    try:
        page = max(1, min(int(request.args.get("page", 1)), 1_000_000))
    except ValueError:
        return jsonify(error="Invalid pagination."), 400
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT count(*) AS total FROM draws")
        total = cursor.fetchone()["total"]
        cursor.execute(
            "SELECT id FROM draws ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s",
            (20, (page - 1) * 20),
        )
        draw_ids = [row["id"] for row in cursor.fetchall()]
        draws = [json_draw(cursor, draw_id) for draw_id in draw_ids]
        return jsonify(draws=draws, total=total, page=page, pages=(total + 19) // 20)
    except psycopg2.Error:
        if db:
            db.rollback()
        app.logger.exception("Draw history query failed")
        return jsonify(error="Lucky Win is temporarily unavailable. Please try again shortly."), 503
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


@app.route("/api/admin/draws/<int:draw_id>")
def get_draw(draw_id):
    if not is_admin():
        return admin_required_response()
    db = None
    cursor = None
    try:
        db = get_db_connection()
        cursor = db.cursor()
        draw = json_draw(cursor, draw_id)
        return (jsonify(draw=draw), 200) if draw else (jsonify(error="Draw not found."), 404)
    except psycopg2.Error:
        if db:
            db.rollback()
        app.logger.exception("Draw lookup failed")
        return jsonify(error="Lucky Win is temporarily unavailable. Please try again shortly."), 503
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")
