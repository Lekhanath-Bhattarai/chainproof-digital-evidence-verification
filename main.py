from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload")
def upload():
    return render_template("upload.html")

@app.route("/verify")
def verify():
    return render_template("verify.html")

if __name__ == "__main__":
    app.run(debug=True)