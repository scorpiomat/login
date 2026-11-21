import os
import re
import sqlite3
import secrets
import smtplib
import time
import hmac
import importlib

from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session
)
from werkzeug.security import generate_password_hash, check_password_hash

try:
    CSRFProtect = importlib.import_module("flask_wtf.csrf").CSRFProtect
except ModuleNotFoundError:
    from flask import abort

    class CSRFProtect:
        """Small Flask-WTF-compatible fallback when Flask-WTF is unavailable."""

        def __init__(self, app=None):
            if app is not None:
                self.init_app(app)

        def init_app(self, app):
            def csrf_token():
                token = session.get("csrf_token")
                if token is None:
                    token = secrets.token_urlsafe(32)
                    session["csrf_token"] = token
                return token

            app.jinja_env.globals["csrf_token"] = csrf_token

            @app.before_request
            def protect_from_csrf():
                if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                    expected = session.get("csrf_token")
                    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
                    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
                        abort(400, description="CSRF token missing or invalid")


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "scorpio.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ganti-secret-key-ini")
CSRFProtect(app)

MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")

OTP_EXPIRE_SECONDS = 600
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_WAIT = 60
OTP_MAX_PER_HOUR = 5


# ================= DATABASE =================

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def siapkan_database():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    kolom = {
        row["name"]
        for row in cursor.execute("PRAGMA table_info(users)").fetchall()
    }

    if "email" not in kolom:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")

    if "email_verified" not in kolom:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0
        """)

    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
        ON users(email COLLATE NOCASE)
        WHERE email IS NOT NULL
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            purpose TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used_at INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    db.commit()
    db.close()


# ================= EMAIL DAN OTP =================

def kirim_email(tujuan, subjek, isi):
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        print("Atur MAIL_USERNAME dan MAIL_PASSWORD terlebih dahulu.")
        return False

    pesan = EmailMessage()
    pesan["Subject"] = subjek
    pesan["From"] = MAIL_USERNAME
    pesan["To"] = tujuan
    pesan.set_content(isi)

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(pesan)
        return True
    except Exception as error:
        print("Pengiriman email gagal:", error)
        return False


def kirim_otp(user_id, email, purpose):
    sekarang = int(time.time())
    db = get_db()

    terakhir = db.execute("""
        SELECT created_at FROM email_codes
        WHERE user_id = ? AND purpose = ?
        ORDER BY created_at DESC LIMIT 1
    """, (user_id, purpose)).fetchone()

    if terakhir and sekarang - terakhir["created_at"] < OTP_RESEND_WAIT:
        db.close()
        return False, "Tunggu 60 detik sebelum meminta kode baru."

    jumlah = db.execute("""
        SELECT COUNT(*) AS total FROM email_codes
        WHERE user_id = ? AND purpose = ? AND created_at >= ?
    """, (user_id, purpose, sekarang - 3600)).fetchone()["total"]

    if jumlah >= OTP_MAX_PER_HOUR:
        db.close()
        return False, "Batas permintaan kode tercapai. Coba lagi nanti."

    db.execute("""
        UPDATE email_codes SET used_at = ?
        WHERE user_id = ? AND purpose = ? AND used_at IS NULL
    """, (sekarang, user_id, purpose))

    kode = f"{secrets.randbelow(1000000):06d}"

    db.execute("""
        INSERT INTO email_codes
        (user_id, purpose, code_hash, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        purpose,
        generate_password_hash(kode),
        sekarang,
        sekarang + OTP_EXPIRE_SECONDS
    ))

    db.commit()
    db.close()

    isi = (
        f"Halo,\n\n"
        f"Kode verifikasi Scorpio kamu adalah: {kode}\n\n"
        f"Kode berlaku selama 10 menit dan hanya dapat digunakan sekali.\n"
        f"Jangan bagikan kode ini kepada siapa pun.\n\n"
        f"Jika kamu tidak meminta kode ini, abaikan email ini."
    )

    if not kirim_email(email, "Kode Verifikasi Scorpio", isi):
        return False, "Email gagal dikirim. Periksa konfigurasi Gmail."

    return True, "Kode verifikasi berhasil dikirim ke email."


def periksa_otp(user_id, purpose, kode):
    sekarang = int(time.time())
    db = get_db()

    data = db.execute("""
        SELECT * FROM email_codes
        WHERE user_id = ? AND purpose = ? AND used_at IS NULL
        ORDER BY created_at DESC LIMIT 1
    """, (user_id, purpose)).fetchone()

    if not data:
        db.close()
        return False, "Kode tidak valid atau sudah digunakan."

    if sekarang > data["expires_at"]:
        db.execute(
            "UPDATE email_codes SET used_at = ? WHERE id = ?",
            (sekarang, data["id"])
        )
        db.commit()
        db.close()
        return False, "Kode sudah kedaluwarsa. Minta kode baru."

    if data["attempts"] >= OTP_MAX_ATTEMPTS:
        db.close()
        return False, "Batas percobaan tercapai. Minta kode baru."

    if not check_password_hash(data["code_hash"], kode):
        db.execute(
            "UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?",
            (data["id"],)
        )
        db.commit()
        db.close()
        return False, "Kode salah."

    db.execute(
        "UPDATE email_codes SET used_at = ? WHERE id = ?",
        (sekarang, data["id"])
    )
    db.commit()
    db.close()

    return True, "Kode berhasil diverifikasi."


# ================= FUNGSI BANTUAN =================

def login_required(f):
    @wraps(f)
    def pembungkus(*args, **kwargs):
        if "user_id" not in session:
            flash("Silakan login terlebih dahulu.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return pembungkus


def akun_dari_id(user_id):
    if not user_id:
        return None

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    db.close()
    return user


def validasi_email(email):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


# ================= LOGIN =================

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        db.close()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Username atau password salah.", "error")
            return render_template("login.html")

        session.clear()

        if not user["email"]:
            session["pending_user_id"] = user["id"]
            flash("Tambahkan email untuk mengamankan akun lama.", "info")
            return redirect(url_for("add_email"))

        if not user["email_verified"]:
            session["pending_user_id"] = user["id"]
            return redirect(url_for("verify_email"))

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("beranda"))

    return render_template("login.html")


# ================= REGISTRASI =================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(username) < 3:
            flash("Username minimal 3 karakter.", "error")
            return render_template("register.html")

        if not validasi_email(email):
            flash("Format email tidak valid.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password minimal 8 karakter.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Konfirmasi password tidak sama.", "error")
            return render_template("register.html")

        db = get_db()

        try:
            cursor = db.execute("""
                INSERT INTO users
                (username, email, password_hash, email_verified)
                VALUES (?, ?, ?, 0)
            """, (
                username,
                email,
                generate_password_hash(password)
            ))

            user_id = cursor.lastrowid
            db.commit()

        except sqlite3.IntegrityError:
            db.close()
            flash("Username atau email sudah digunakan.", "error")
            return render_template("register.html")

        db.close()

        session.clear()
        session["pending_user_id"] = user_id

        berhasil, pesan = kirim_otp(
            user_id, email, "verify_email"
        )

        flash(pesan, "info" if berhasil else "error")
        return redirect(url_for("verify_email"))

    return render_template("register.html")


# ================= EMAIL AKUN LAMA =================

@app.route("/add-email", methods=["GET", "POST"])
def add_email():
    user_id = session.get("pending_user_id")
    user = akun_dari_id(user_id)

    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not validasi_email(email):
            flash("Format email tidak valid.", "error")
            return render_template("add_email.html")

        db = get_db()

        try:
            db.execute("""
                UPDATE users
                SET email = ?, email_verified = 0
                WHERE id = ?
            """, (email, user_id))
            db.commit()

        except sqlite3.IntegrityError:
            db.close()
            flash("Email sudah digunakan akun lain.", "error")
            return render_template("add_email.html")

        db.close()

        berhasil, pesan = kirim_otp(
            user_id, email, "verify_email"
        )

        flash(pesan, "info" if berhasil else "error")
        return redirect(url_for("verify_email"))

    return render_template("add_email.html")


# ================= VERIFIKASI EMAIL =================

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    user_id = session.get("pending_user_id")
    user = akun_dari_id(user_id)

    if not user:
        return redirect(url_for("login"))

    if user["email_verified"]:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session.pop("pending_user_id", None)
        return redirect(url_for("beranda"))

    if request.method == "POST":
        kode = request.form.get("code", "").strip()

        if not re.fullmatch(r"\d{6}", kode):
            flash("Masukkan kode OTP 6 digit.", "error")
            return render_template("verify_email.html")

        berhasil, pesan = periksa_otp(
            user_id, "verify_email", kode
        )

        if berhasil:
            db = get_db()
            db.execute(
                "UPDATE users SET email_verified = 1 WHERE id = ?",
                (user_id,)
            )
            db.commit()
            db.close()

            session.pop("pending_user_id", None)
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Email berhasil diverifikasi.", "success")
            return redirect(url_for("beranda"))

        flash(pesan, "error")

    return render_template("verify_email.html")


@app.route("/resend-email-code", methods=["POST"])
def resend_email_code():
    user_id = session.get("pending_user_id")
    user = akun_dari_id(user_id)

    if not user or not user["email"]:
        flash("Periksa kembali data akun.", "error")
        return redirect(url_for("login"))

    berhasil, pesan = kirim_otp(
        user["id"], user["email"], "verify_email"
    )

    flash(pesan, "info" if berhasil else "error")
    return redirect(url_for("verify_email"))


# ================= LUPA PASSWORD =================

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not validasi_email(email):
            flash("Masukkan format email yang valid.", "error")
            return render_template("reset_password.html")

        db = get_db()
        user = db.execute("""
            SELECT * FROM users
            WHERE email = ? COLLATE NOCASE
            AND email_verified = 1
        """, (email,)).fetchone()
        db.close()

        session.pop("pending_reset_email", None)
        session.pop("reset_user_id", None)
        session.pop("reset_authorized_until", None)
        session["pending_reset_email"] = email

        if user:
            kirim_otp(
                user["id"], user["email"], "reset_password"
            )

        flash(
            "Jika email terdaftar dan terverifikasi, kode akan dikirim. "
            "Periksa kotak masuk dan folder spam.",
            "info"
        )

        return redirect(url_for("verify_reset"))

    return render_template("reset_password.html")


@app.route("/verify-reset", methods=["GET", "POST"])
def verify_reset():
    email = session.get("pending_reset_email")

    if not email:
        return redirect(url_for("reset_password"))

    if request.method == "POST":
        kode = request.form.get("code", "").strip()

        db = get_db()
        user = db.execute("""
            SELECT * FROM users
            WHERE email = ? COLLATE NOCASE
            AND email_verified = 1
        """, (email,)).fetchone()
        db.close()

        if user and re.fullmatch(r"\d{6}", kode):
            berhasil, pesan = periksa_otp(
                user["id"], "reset_password", kode
            )

            if berhasil:
                session["reset_user_id"] = user["id"]
                session["reset_authorized_until"] = int(time.time()) + 600
                session.pop("pending_reset_email", None)
                return redirect(url_for("new_password"))

            flash(pesan, "error")
        else:
            flash("Kode tidak valid atau sudah kedaluwarsa.", "error")

    return render_template("verify_reset.html")


@app.route("/resend-reset-code", methods=["POST"])
def resend_reset_code():
    email = session.get("pending_reset_email")

    if not email:
        return redirect(url_for("reset_password"))

    db = get_db()
    user = db.execute("""
        SELECT * FROM users
        WHERE email = ? COLLATE NOCASE
        AND email_verified = 1
    """, (email,)).fetchone()
    db.close()

    if user:
        kirim_otp(
            user["id"], user["email"], "reset_password"
        )

    flash(
        "Jika email terdaftar dan terverifikasi, kode baru akan dikirim "
        "jika permintaan memenuhi batas keamanan.",
        "info"
    )

    return redirect(url_for("verify_reset"))


@app.route("/new-password", methods=["GET", "POST"])
def new_password():
    user_id = session.get("reset_user_id")
    batas_waktu = session.get("reset_authorized_until", 0)

    if not user_id or int(time.time()) > batas_waktu:
        session.pop("reset_user_id", None)
        session.pop("reset_authorized_until", None)
        flash("Mulai kembali proses lupa password.", "error")
        return redirect(url_for("reset_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password minimal 8 karakter.", "error")
            return render_template("new_password.html")

        if password != confirm:
            flash("Konfirmasi password tidak sama.", "error")
            return render_template("new_password.html")

        db = get_db()
        db.execute("""
            UPDATE users SET password_hash = ?
            WHERE id = ?
        """, (generate_password_hash(password), user_id))
        db.commit()
        db.close()

        session.pop("reset_user_id", None)
        session.pop("reset_authorized_until", None)
        session.pop("pending_reset_email", None)

        flash("Password berhasil diubah. Silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("new_password.html")


# ================= BERANDA, PROFIL, PENGATURAN =================

@app.route("/dashboard")
@login_required
def dashboard():
    return redirect(url_for("beranda"))


@app.route("/beranda")
@login_required
def beranda():
    return render_template("dashboard.html")


@app.route("/profil")
@login_required
def profil():
    user = akun_dari_id(session["user_id"])
    return render_template("profil.html", user=user)


@app.route("/pengaturan", methods=["GET", "POST"])
@login_required
def pengaturan():
    if request.method == "POST":
        lama = request.form.get("password_lama", "")
        baru = request.form.get("password_baru", "")
        konfirmasi = request.form.get("konfirmasi", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if not check_password_hash(user["password_hash"], lama):
            db.close()
            flash("Password lama tidak sesuai.", "error")
            return redirect(url_for("pengaturan"))

        if len(baru) < 8:
            db.close()
            flash("Password baru minimal 8 karakter.", "error")
            return redirect(url_for("pengaturan"))

        if baru != konfirmasi:
            db.close()
            flash("Konfirmasi password tidak sama.", "error")
            return redirect(url_for("pengaturan"))

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(baru), session["user_id"])
        )
        db.commit()
        db.close()

        flash("Password berhasil diperbarui.", "success")
        return redirect(url_for("pengaturan"))

    return render_template("pengaturan.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Kamu sudah logout.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    siapkan_database()
    app.run(host="127.0.0.1", port=5000, debug=True)