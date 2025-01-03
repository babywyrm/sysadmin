import os
import datetime
import jwt

from flask import Flask, request, jsonify, render_template_string
from markupsafe import Markup

app = Flask(__name__)

####
####

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

@app.route("/consentify", methods=["GET"])
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

import os
import datetime
import jwt
from flask import Flask, request, jsonify, render_template_string
from markupsafe import Markup

# ---------------------------------------------------------------------------------
# B E W A R E:
# This code demonstrates a purposeful Server-Side Template Injection (SSTI)
# via "double rendering." In real-world apps, this is highly insecure.
# Use for educational/CTF purposes only.
# ---------------------------------------------------------------------------------

# Create our Flask portal (application)
GalacticPortal = Flask(__name__)

# Toggle off autoescape to ensure Jinja doesn't HTML-escape user inputs
GalacticPortal.jinja_env.autoescape = False

# Grab our "secret sauce" from environment, or use a fallback if none
secretSauce = os.getenv("SPACE_SPICE", "MoonBaseCookie!")
GalacticPortal.config["SPACE_SPICE"] = secretSauce


@GalacticPortal.route("/")
def cosmic_welcome():
    """
    cosmic_welcome: Just a landing page for the curious traveler.
    Demonstrates the 'home' route in an obfuscated manner.
    """
    return (
        "<h1>Galactic Portal - Legacy OAuth Station</h1>"
        "<p>We've replaced this system with something else, but it's still around...</p>"
    )


@GalacticPortal.route("/request_lunar_pass", methods=["POST"])
def manufacture_token():
    """
    manufacture_token: Pretends to issue a JWT ("lunar pass").
    The 'username' field is required; if not found, we deny the request.
    """
    cosmic_handle = request.form.get("username")
    if not cosmic_handle:
        return jsonify({"error": "missing cosmic_handle"}), 400

    # Build the cosmic payload with an expiration
    ephemeral_payload = {
        "sub": cosmic_handle,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
    }

    # Sign the token with our secret sauce (HS256)
    lunar_pass = jwt.encode(ephemeral_payload, secretSauce, algorithm="HS256")

    return jsonify({
        "galactic_pass": lunar_pass,
        "token_type": "Bearer",
        "minutes_until_sunset": 30
    })


@GalacticPortal.route("/disorientation", methods=["GET"])
def ssti_double_render():
    """
    ssti_double_render: Demonstrates the dangerous double-render approach.

    1) We define an HTML template that references {{ user_input }}.
    2) On the first render, user input is inserted verbatim.
    3) On the second render, if user input includes Jinja2 syntax (like {{config['SPACE_SPICE']}}),
       it gets interpreted again, leading to potential secret leakage.
    """
    # Retrieve the "visitor_name" (similar to "client_name" in original code)
    visitor_name_raw = request.args.get("visitor_name", "Temporal Drifter")
    desired_scope = request.args.get("scopes", "None")

    # Markup(...) ensures the input won't be escaped on the first pass.
    visitor_name_prepped = Markup(visitor_name_raw)
    scope_prepped = Markup(desired_scope)

    # Outer template: references {{ visitor_name_prepped }} and {{ scope_prepped }}
    # We'll render this template TWICE
    outer_shell = """
    <html>
    <head>
      <title>Disorientation for {{ visitor_name_prepped }}</title>
    </head>
    <body>
      <h1>Galactic Consent Interface</h1>
      <p><b>{{ visitor_name_prepped }}</b> requests access to: {{ scope_prepped }}</p>
      <p>By continuing, you're granting cosmic permissions to {{ visitor_name_prepped }}.</p>
      <form action="/request_lunar_pass" method="POST">
        <label for="username">Enter your cosmic handle to proceed:</label>
        <input id="username" name="username" type="text" placeholder="e.g. star-lord">
        <button type="submit">Obtain Lunar Pass</button>
      </form>
    </body>
    </html>
    """

    # === First Pass ===
    # The placeholders get replaced with the raw user-supplied strings
    # If the user has injected something like {{config['SPACE_SPICE']}}, it will remain as is
    # in the resulting HTML
    first_pass_render = render_template_string(
        outer_shell,
        visitor_name_prepped=visitor_name_prepped,
        scope_prepped=scope_prepped
    )

    # === Second Pass ===
    # The result of the first pass (which may now contain Jinja2 expressions) is re-rendered.
    # Because we pass in "config=GalacticPortal.config", the user can access config['SPACE_SPICE'].
    # This is the dangerous second rendering that can reveal secrets.
    second_pass_render = render_template_string(first_pass_render, config=GalacticPortal.config)

    return second_pass_render


@GalacticPortal.route("/night_vision", methods=["GET"])
def env_leak():
    """
    env_leak: Another optional route that returns environment variables in JSON form.
    Illustrates how naive debugging endpoints can leak secrets.
    """
    all_env = {k: v for k, v in os.environ.items()}
    return jsonify(all_env)


if __name__ == "__main__":
    # Spin up the portal on port 666, where mischief thrives
    GalacticPortal.run(host="0.0.0.0", port=666)

####
####
