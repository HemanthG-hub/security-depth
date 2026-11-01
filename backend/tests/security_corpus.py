RULE_CASES = (
    {
        "rule": "Hardcoded secret",
        "language": "Python",
        "vulnerable": 'password = "demo-secret-123"',
        "safe": 'password = os.environ.get("APP_PASSWORD")',
    },
    {
        "rule": "Command injection surface",
        "language": "Python",
        "vulnerable": 'subprocess.run("grep " + query, shell=True)',
        "safe": 'subprocess.run(["grep", query], shell=False)',
    },
    {
        "rule": "SQL injection",
        "language": "Python",
        "vulnerable": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        "safe": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    },
    {
        "rule": "Cross-site scripting",
        "language": "JavaScript",
        "vulnerable": "element.innerHTML = request.query.name;",
        "safe": "element.textContent = request.query.name;",
    },
    {
        "rule": "Weak cryptography",
        "language": "Python",
        "vulnerable": "digest = hashlib.sha1(password.encode()).hexdigest()",
        "safe": "digest = hashlib.sha256(password.encode()).hexdigest()",
    },
    {
        "rule": "Unsafe deserialization",
        "language": "Python",
        "vulnerable": "payload = pickle.loads(raw_data)",
        "safe": "payload = json.loads(raw_data)",
    },
    {
        "rule": "Path traversal",
        "language": "Python",
        "vulnerable": "contents = open(filename).read()",
        "safe": "contents = open('/srv/public/help.txt').read()",
    },
    {
        "rule": "Server-side request forgery",
        "language": "Python",
        "vulnerable": "response = requests.get(user_url)",
        "safe": 'response = requests.get("https://api.example.com/status")',
    },
    {
        "rule": "Insecure authentication configuration",
        "language": "Python",
        "vulnerable": 'claims = jwt.decode(token, key, options={"verify_signature": False})',
        "safe": 'claims = jwt.decode(token, key, options={"verify_signature": True})',
    },
    {
        "rule": "Missing input validation",
        "language": "Python",
        "vulnerable": 'user_id = request.args["id"]',
        "safe": 'user_id = request.args.get("id")',
    },
    {
        "rule": "Excessive file permissions",
        "language": "Python",
        "vulnerable": "os.chmod(output_path, 0o777)",
        "safe": "os.chmod(output_path, 0o600)",
    },
    {
        "rule": "Insecure dependency pinning",
        "language": "Plain Text",
        "vulnerable": "npm install example-package@latest",
        "safe": "npm install example-package@1.2.3",
    },
    {
        "rule": "Unencrypted IoT communication",
        "language": "Arduino / ESP32",
        "vulnerable": 'client.setServer("broker.local", 1883);',
        "safe": 'client.setServer("broker.local", 8883);',
    },
    {
        "rule": "Insecure firmware configuration",
        "language": "Arduino / ESP32",
        "vulnerable": 'const char* WIFI_PASSWORD = "device-secret";\nArduinoOTA.begin();',
        "safe": 'const char* WIFI_PASSWORD = readProvisionedSecret();\nstartSignedUpdate();',
    },
)


REPOSITORY_CASES = {
    "vulnerable": {
        "src/app.py": 'password = "repo-secret-value"\nsubprocess.run("grep " + term, shell=True)\n',
        "web/render.js": "element.innerHTML = request.query.name;\n",
        "device/firmware.ino": 'client.setServer("broker.local", 1883);\n',
    },
    "safe": {
        "src/app.py": 'password = os.environ.get("APP_PASSWORD")\nsubprocess.run(["grep", term], shell=False)\n',
        "web/render.js": "element.textContent = request.query.name;\n",
        "device/firmware.ino": 'client.setServer("broker.local", 8883);\n',
    },
}

REPOSITORY_EXPECTED_RULES = {
    "vulnerable": {
        "Hardcoded secret",
        "Command injection surface",
        "Cross-site scripting",
        "Unencrypted IoT communication",
    },
    "safe": set(),
}