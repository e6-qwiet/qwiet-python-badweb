# app.py
import flask
from flask import request
import vulnerable_libxz  # ❌ hallucinated import
import insecure_ssh_compression  # ❌ hallucinated import

import os
import subprocess
import base64
import jwt  # ⚠️ Potentially insecure if used without verification

app = flask.Flask(__name__)

# ⚠️ Hardcoded secret key (SAST red flag)
SECRET_KEY = "supersecretkey123"

@app.route("/")
def index():
    return "Insecure Python Web App - CVE-2024-3094 Simulation"

@app.route("/run", methods=["POST"])
def run_command():
    data = request.form.get("cmd", "")
    
    # ⚠️ Command Injection vulnerability
    result = subprocess.getoutput(f"bash -c '{data}'")

    return f"<pre>{result}</pre>"

@app.route("/compress", methods=["POST"])
def compress_data():
    data = request.form.get("data", "")
    encoded = base64.b64encode(data.encode()).decode()

    # ⚠️ Unsafe use of vulnerable xz-utils (simulated vulnerable path)
    with open("data.txt", "w") as f:
        f.write(encoded)

    # ⚠️ Calls vulnerable xz version (CVE-2024-3094)
    os.system("xz --compress data.txt")  # Assumes xz 5.6.0/5.6.1 is installed

    return "Data compressed with xz"

@app.route("/decode", methods=["POST"])
def decode_jwt():
    token = request.form.get("token", "")

    try:
        # ⚠️ JWT decode without verification
        payload = jwt.decode(token, options={"verify_signature": False})
        return str(payload)
    except Exception as e:
        return str(e), 400

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username")
    password = request.form.get("password")

    # ⚠️ Hardcoded credential check
    if user == "admin" and password == "password123":
        return "Welcome, admin!"
    return "Invalid credentials", 403

if __name__ == "__main__":
    app.run(debug=True)

