from flask import Flask, request, render_template, make_response, send_file
import subprocess
import os
import secrets
import pickle
import base64
import re
# from xz import decompress  # Simulate the vulnerable import.  This will cause an import error.
# from non_existent_module import some_function # Simulate a hallucinated import
import json  # Import json
import badpackages
import hallucinated001

app = Flask(__name__)

# Hardcoded secret key (Vulnerability: Hardcoded Secret)
SECRET_KEY = "supersecretkey123"
app.secret_key = SECRET_KEY


# Vulnerable Deserialization (Vulnerability: Deserialization)
class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /etc/passwd',))  # WARNING:  This is dangerous.  Do NOT use this in real code.

@app.route('/deserialize', methods=['POST'])
def deserialize():
    if request.method == 'POST':
        data = request.form['data']
        try:
            # data_bytes = base64.b64decode(data) # removed to avoid errors.
            # pickled_data = pickle.loads(data_bytes) # The actual vulnerable line
            # return f"Deserialized: {pickled_data}" #This line could leak info
            return "Deserialization attempt made. Check server for potential /etc/passwd execution (if exploit class was active)." # more secure
        except Exception as e:
            return f"Error: {e}"
    return "Send data to deserialize"

# Remote Code Execution (RCE) Vulnerability (Vulnerability: RCE)
@app.route('/rce', methods=['GET', 'POST'])
def rce():
    if request.method == 'POST':
        command = request.form['command']
        #  command = command.replace(";", "") # Attempted fix.  Still vulnerable to many other injection methods.
        try:
            # process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) # VULNERABLE
            # output, error = process.communicate()
            # return f"Output: {output.decode()}, Error: {error.decode()}" # potential information leak
            # More secure approach:
            result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=5) # still vulnerable to command injection, but slightly better
            return f"Output: {result.stdout}, Error: {result.stderr}"

        except Exception as e:
            return f"Error: {e}"
    return render_template('rce.html') #  Create a simple HTML form for this.

# Cross-Site Scripting (XSS) Vulnerability (Vulnerability: XSS)
@app.route('/xss', methods=['GET', 'POST'])
def xss():
    if request.method == 'POST':
        name = request.form['name']
        #  Proper fix:  Use the 'safe' filter in Jinja2, or escape the output.  DO NOT do this:
        #  name = name.replace("<", "&lt;").replace(">", "&gt;") # Incomplete fix!
        return render_template('xss.html', name=name)  # Vulnerable:  name is not escaped.
    return render_template('xss.html', name="")

# Directory Traversal Vulnerability (Vulnerability: Directory Traversal)
@app.route('/file', methods=['GET'])
def file():
    filename = request.args.get('filename')
    if not filename:
        return "Please provide a filename."

    # Vulnerability:  Missing proper path sanitization.
    # filepath = os.path.join("uploads", filename)  #  Still vulnerable if filename starts with ../
    # More secure (but still has potential issues):
    base_dir = "uploads" # Restrict to a specific directory
    filepath = os.path.join(base_dir, os.path.basename(filename)) # Use basename to prevent path traversal.
    if os.path.exists(filepath):
        try:
            return send_file(filepath)
        except Exception as e:
            return f"Error reading file: {e}"
    else:
        return "File not found."

# Example route to show a basic page.
@app.route('/')
def index():
    return "Welcome to the Vulnerable Web App!"

#  Example using json
@app.route('/json', methods=['POST'])
def json_endpoint():
    data = request.get_json()
    if data:
        return jsonify(data)  # jsonify is part of flask, no need to import separately in newer versions
    else:
        return jsonify({"error": "No JSON data provided"}), 400
    
# Function with a potential vulnerability (Vulnerability: Path manipulation)
def process_data(user_input):
    """
    Processes user input, which could be a file path.  This function is vulnerable
    to path manipulation if the input is not carefully validated.
    """
    #  DO NOT DO THIS.  This is vulnerable.
    # file_path = os.path.join("/tmp/", user_input)
    # with open(file_path, "w") as f:
    #     f.write("Processed: " + user_input)

    # A slightly better approach would be to validate and sanitize.
    if not re.match("^[a-zA-Z0-9_-]+$", user_input):  # VERY basic validation.
        raise ValueError("Invalid characters in input.")
    file_path = os.path.join("/tmp/", user_input)
    try:
        with open(file_path, "w") as f:
            f.write("Processed: " + user_input)
    except Exception as e:
        print(f"Error processing data: {e}") # Log the error.

    return f"Data processed and written to {file_path}" # Information Leak.

@app.route('/process', methods=['POST'])
def process():
    user_data = request.form.get('data', '')
    try:
        result = process_data(user_data)
        return result
    except ValueError as e:
        return str(e), 400
    

if __name__ == '__main__':
    # Create a dummy 'uploads' directory if it doesn't exist.  Important for the file serving route.
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
        # Create a dummy file
        with open("uploads/test.txt", "w") as f:
            f.write("This is a test file.")
    app.run(debug=True, port=5001) # Changed port to 5001


