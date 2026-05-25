import random
import base64
import hashlib
import os
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    session,
    redirect
)

from cryptography.fernet import Fernet

app = Flask(__name__)

# Secret key for login session
app.secret_key = "supersecretkey"

# Folders
UPLOAD_FOLDER = "uploads/"
ENCRYPTED_FOLDER = "encrypted/"
DECRYPTED_FOLDER = "decrypted/"

# Create folders automatically
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# Failed attempt tracker
attempts = {}

# OTP storage
generated_otp = ""

# 🔐 Generate encryption key
def generate_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

# 📝 Activity logger
def log_activity(action, filename):
    with open("log.txt", "a") as log:
        log.write(
            f"{datetime.now()} - {action} - {filename}\n"
        )

# 🔑 LOGIN WITH OTP
@app.route("/login", methods=["GET", "POST"])
def login():

    global generated_otp

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username == "admin" and password == "1234":

            # Generate 6-digit OTP
            generated_otp = str(
                random.randint(100000, 999999)
            )

            print("\n🔐 OTP:", generated_otp)

            # temporary session
            session["temp_user"] = username

            return redirect("/verify-otp")

        else:

            return render_template(
                "login.html",
                message="❌ Invalid Credentials"
            )

    return render_template("login.html")

# 🔐 OTP VERIFICATION
# 🔐 OTP VERIFICATION
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    global generated_otp

    if request.method == "POST":

        entered_otp = request.form["otp"]

        if entered_otp == generated_otp:

            if "temp_user" in session:

                session["user"] = session["temp_user"]

                session.pop("temp_user", None)

                return redirect("/")

            else:

                return redirect("/login")

        else:

            return render_template(
                "otp.html",
                message="❌ Invalid OTP"
            )

    return render_template("otp.html")

# 🚪 LOGOUT
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

# 🏠 HOME
@app.route("/")
def index():

    if "user" not in session:
        return redirect("/login")

    return render_template("index.html")

# 🔒 ENCRYPT
@app.route("/encrypt", methods=["POST"])
def encrypt():

    if "user" not in session:
        return redirect("/login")

    file = request.files["file"]
    password = request.form["password"]

    filepath = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    file.save(filepath)

    key = generate_key(password)

    f = Fernet(key)

    with open(filepath, "rb") as f1:
        data = f1.read()

    encrypted_data = f.encrypt(data)

    enc_path = os.path.join(
        ENCRYPTED_FOLDER,
        file.filename + ".enc"
    )

    with open(enc_path, "wb") as f2:
        f2.write(encrypted_data)

    log_activity(
        "ENCRYPTED",
        file.filename
    )

    return send_file(
        enc_path,
        as_attachment=True
    )

# 🔓 DECRYPT
@app.route("/decrypt", methods=["POST"])
def decrypt():

    if "user" not in session:
        return redirect("/login")

    file = request.files["file"]
    password = request.form["password"]

    # User IP
    user_ip = request.remote_addr

    # Initialize attempts
    if user_ip not in attempts:
        attempts[user_ip] = 0

    # Block after 3 failures
    if attempts[user_ip] >= 3:
        return "❌ Too many failed attempts!"

    filepath = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    file.save(filepath)

    key = generate_key(password)

    f = Fernet(key)

    try:

        with open(filepath, "rb") as f1:
            data = f1.read()

        decrypted_data = f.decrypt(data)

        # Reset attempts
        attempts[user_ip] = 0

        # Remove .enc
        original_name = file.filename.replace(
            ".enc",
            ""
        )

        dec_path = os.path.join(
            DECRYPTED_FOLDER,
            "decrypted_" + original_name
        )

        with open(dec_path, "wb") as f2:
            f2.write(decrypted_data)

        log_activity(
            "DECRYPTED",
            original_name
        )

        return send_file(
            dec_path,
            as_attachment=True
        )

    except:

        attempts[user_ip] += 1

        return render_template(
            "index.html",
            message="❌ Wrong password or corrupted file!"
        )

# 📊 VIEW LOGS
@app.route("/logs")
def view_logs():

    # login protection
    if "user" not in session:
        return redirect("/login")

    # no log file
    if not os.path.exists("log.txt"):
        return "No logs available."

    with open("log.txt", "r") as f:
        logs = f.readlines()

    formatted_logs = "<h1>📊 Activity Logs</h1><hr>"

    for log in logs:
        formatted_logs += f"<p>{log}</p>"

    return formatted_logs

# ▶️ RUN APP
if __name__ == "__main__":
    app.run(debug=True)