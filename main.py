import os
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from app.hashing import generate_sha256

app = Flask(__name__)

UPLOAD_FOLDER = "evidence"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

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