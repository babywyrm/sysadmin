import os
import datetime
import jwt

from flask import Flask, request, jsonify, render_template_string
from markupsafe import Markup

app = Flask(__name__)

######
######

# Disable Jinja2 auto-escaping globally (for demonstration/CTF only!)
app.jinja_env.autoescape = False

# The “legacy” HMAC secret for signing tokens
HMAC_SECRET = os.getenv("LEGACY_HMAC_SECRET", "THINGSLOL")
app.config["LEGACY_HMAC_SECRET"] = HMAC_SECRET

@app.route("/")
def home():
    return (
        "<h1>Welcome to the Legacy OAuth Service!</h1>"
        "<p>This service is deprecated but still running...</p>"
    )

@app.route("/token", methods=["POST"])
def issue_token():
    username = request.form.get("username")
    if not username:
        return jsonify({"error": "missing username"}), 400

    payload = {
        "sub": username,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, HMAC_SECRET, algorithm="HS256")
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in_minutes": 30
    })

@app.route("/consent", methods=["GET"])
def consent_page():
    """
    Demonstrates a *double render* approach for server-side template injection.
    """
    client_name_raw = request.args.get("client_name", "Unknown Client")
    requested_scope = request.args.get("scope", "None")

    # Convert user input into a Markup object so Jinja won't escape it on first render
    client_name = Markup(client_name_raw)
    requested_scope = Markup(requested_scope)

    # This is our 'outer' template (will be rendered TWICE)
    outer_template = """
    <html>
    <head>
      <title>Consent for {{ client_name }}</title>
    </head>
    <body>
      <h1>Consent Page</h1>
      <p>The client <b>{{ client_name }}</b> is requesting access to the following scope(s):</p>
      <p><code>{{ requested_scope }}</code></p>
      <p>By continuing, you will grant these permissions to {{ client_name }}.</p>
      <form action="/token" method="POST">
        <label for="username">Enter your username to proceed:</label>
        <input id="username" name="username" type="text" placeholder="e.g. ackbar">
        <button type="submit">Get Token</button>
      </form>
    </body>
    </html>
    """

    # 1) First pass:
    #    Replaces {{ client_name }} with the raw string (e.g. `{{config['LEGACY_HMAC_SECRET']}}`)
    first_pass = render_template_string(
        outer_template,
        client_name=client_name,
        requested_scope=requested_scope
    )

    # 2) Second pass:
    #    Now interpret whatever Jinja expression might have resulted from step 1.
    second_pass = render_template_string(first_pass, config=app.config)

    return second_pass

@app.route("/debug/env", methods=["GET"])
def debug_env():
    """Optional: returns environment variables for debugging."""
    return jsonify(dict(os.environ))

if __name__ == "__main__":
    # For demonstration only, run in debug-like mode on port 666
    app.run(host="0.0.0.0", port=666)

####
####
