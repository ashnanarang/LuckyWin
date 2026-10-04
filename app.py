from flask import Flask, render_template, request
import mysql.connector
import uuid
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password=os.getenv("LuckyWin@2026!"),
        database="luckywin"
    )

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    name = request.form["name"]
    phone = request.form["phone"]

    if not phone.isdigit() or len(phone) != 10:
        return "Please enter a valid 10-digit phone number."

    age = request.form["age"]

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute(
        "SELECT ticket_number FROM participants WHERE phone = %s",
        (phone,)
    )

    existing_participant = cursor.fetchone()

    if existing_participant:
        ticket = existing_participant["ticket_number"]
        cursor.close()
        db.close()
        return f"You are already registered. Your ticket number is {ticket}"

    ticket_number = "LW-" + uuid.uuid4().hex[:8].upper()

    cursor.execute(
        """
        INSERT INTO participants (name, phone, age, ticket_number)
        VALUES (%s, %s, %s, %s)
        """,
        (name, phone, age, ticket_number)
    )

    db.commit()
    cursor.close()
    db.close()

    return f"Registration successful! Your ticket number is {ticket_number}"

@app.route("/participants")
def participants():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, name, phone, age, ticket_number, created_at
        FROM participants
        ORDER BY id DESC
    """)

    participants = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "participants.html",
        participants=participants
    )
@app.route("/admin/participants")
def admin_participants():
    return participants()

if __name__ == "__main__":
    app.run(debug=True)