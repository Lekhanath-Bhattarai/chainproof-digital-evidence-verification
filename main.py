import os
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from app.hashing import generate_sha256
from app.key_manager import generate_user_keys
from app.user_manager import register_user

app = Flask(__name__)

UPLOAD_FOLDER = "evidence"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("evidence_file")

        if not file or file.filename == "":
            return render_template("upload.html", error="Please select a file.")

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        file.save(file_path)

        file_hash = generate_sha256(file_path)

        return render_template(
            "upload.html",
            filename=filename,
            file_hash=file_hash
        )

    return render_template("upload.html")

@app.route("/verify")
def verify():
    return render_template("verify.html")

if __name__ == "__main__":
    app.run(debug=True)