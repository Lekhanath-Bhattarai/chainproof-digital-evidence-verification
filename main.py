import os
from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.utils import secure_filename
from app.hashing import generate_sha256
from app.key_manager import generate_user_keys
from app.user_manager import register_user, authenticate_user, get_user
from app.signing import sign_file
from app.verification import verify_signature

app = Flask(__name__)
app.secret_key = "chainproof_dev_secret_key"

UPLOAD_FOLDER = "evidence"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("signatures", exist_ok=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template("register.html", error="Please enter username and password.")

        private_key_path, public_key_path = generate_user_keys(username)

        user_created = register_user(
            username,
            password,
            private_key_path,
            public_key_path
        )

        if not user_created:
            return render_template("register.html", error="User already exists.")

        return render_template(
            "register.html",
            success=True,
            username=username,
            private_key=private_key_path,
            public_key=public_key_path
        )

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if authenticate_user(username, password):
            user = get_user(username)

            session["username"] = username
            session["role"] = user.get("role", "user")

            if session["role"] == "admin":
                return redirect(url_for("admin"))

            return redirect(url_for("index"))

        return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    if request.method == "POST":
        file = request.files.get("evidence_file")

        if not file or file.filename == "":
            return render_template("upload.html", error="Please select a file.")

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        file.save(file_path)

        file_hash = generate_sha256(file_path)

        private_key_path = os.path.join("keys", f"{username}_private.pem")

        if not os.path.exists(private_key_path):
            return render_template(
                "upload.html",
                error=f"No private key found for user '{username}'. Please register the user first."
            )

        signature_path = sign_file(file_path, private_key_path)

        return render_template(
            "upload.html",
            filename=filename,
            file_hash=file_hash,
            signature_path=signature_path,
            username=username
        )

    return render_template("upload.html", username=username)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username")
        evidence_file = request.files.get("evidence_file")
        signature_file = request.files.get("signature_file")

        if not username or not evidence_file or not signature_file:
            return render_template(
                "verify.html",
                error="Please provide username, evidence file, and signature file.",
                is_valid=None
            )

        evidence_path = os.path.join("evidence", secure_filename(evidence_file.filename))
        signature_path = os.path.join("signatures", secure_filename(signature_file.filename))
        public_key_path = os.path.join("keys", f"{username}_public.pem")

        if not os.path.exists(public_key_path):
            return render_template(
                "verify.html",
                error=f"No public key found for user '{username}'.",
                is_valid=None
            )

        evidence_file.save(evidence_path)
        signature_file.save(signature_path)

        is_valid = verify_signature(evidence_path, signature_path, public_key_path)

        return render_template(
            "verify.html",
            username=username,
            is_valid=is_valid
        )

    return render_template("verify.html", is_valid=None)


@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    from app.user_manager import load_users
    users = load_users()

    stats = {
        "users": len(users),
        "evidence": len(os.listdir("evidence")) if os.path.exists("evidence") else 0,
        "signatures": len(os.listdir("signatures")) if os.path.exists("signatures") else 0,
        "keys": len(os.listdir("keys")) if os.path.exists("keys") else 0,
        "certificates": len(os.listdir("certificates")) if os.path.exists("certificates") else 0
    }

    return render_template("admin.html", users=users, stats=stats)


if __name__ == "__main__":
    app.run(debug=True)