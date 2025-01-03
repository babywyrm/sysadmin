
# What Is Double Rendering?
# Double rendering happens when you:

Render a template that includes user-supplied data.
The output of that first render still contains template syntax (like {{ ... }}).
You then render that newly generated string again using the same (or a compatible) template engine.
In essence, template syntax is processed twice, which can lead to malicious code injection if user input contains dangerous directives.

Why Does It Matter? (Security Risks)
Server-Side Template Injection (SSTI)
When user input is interpreted as template code, an attacker can run arbitrary commands, access environment variables, or read secrets.
This is different from client-side injection: here, the server is executing the malicious code before sending the response to the user.
Example Attack Vectors
Leaking Secrets: Attackers inject {{ config['SECRET_KEY'] }}, {{ os.environ['SECRET'] }}, or any variable stored on the server.
Remote Code Execution: If the template engine is configured unsafely, attackers might execute Python code (e.g., {{ ''.__class__.__mro__[1].__subclasses__()[xx]("rm -rf /",shell=True) }} in extreme cases).
Step-by-Step Example of Double Rendering in Flask
User Submits Malicious String:
Something like {{config['LEGACY_HMAC_SECRET']}} or a more complex Jinja2 expression.
Flask’s First Render:
The template placeholders (e.g. {{ client_name }}) are replaced with the user’s literal string.
The rendered HTML still contains {{config['LEGACY_HMAC_SECRET']}}.
Flask’s Second Render:
That leftover {{config['LEGACY_HMAC_SECRET']}} is now interpreted as a Jinja expression instead of a literal string.
The server reads from config['LEGACY_HMAC_SECRET'], resulting in secret disclosure.
Detailed Walkthrough
Consider a route /disorientation that expects a GET parameter visitor_name. If visitor_name is supplied as {{config['SPACE_SPICE']}}, and the app renders that parameter once and then renders the output a second time, we have double rendering.

User Input:
?visitor_name={{config['SPACE_SPICE']}}
First Pass Output:
```
<p>By continuing, you're granting cosmic permissions to {{config['SPACE_SPICE']}}.</p>
Note that the HTML now literally contains {{config['SPACE_SPICE']}}.
```

Second Pass:
Jinja sees {{config['SPACE_SPICE']}} and expands it using the server’s config dictionary.
Final HTML might read:
```
<p>By continuing, you're granting cosmic permissions to Sup3rZ3cretVal!</p>
```

Thus, the attacker successfully tricked the server into revealing Sup3rZ3cretVal!.

Code Breakdown
Initial Template
We define some HTML that references a variable like {{ visitor_name_prepped }} multiple times:

```
<html>
<head>
  <title>Disorientation for {{ visitor_name_prepped }}</title>
</head>
<body>
  <h1>Galactic Consent Interface</h1>
  <p><b>{{ visitor_name_prepped }}</b> requests access to: {{ scope_prepped }}</p>
  <p>By continuing, you're granting cosmic permissions to {{ visitor_name_prepped }}.</p>
  <!-- form omitted for brevity -->
</body>
</html>
```

Notice: This template has Jinja placeholders like {{ visitor_name_prepped }}.

First Pass Rendering
We feed in visitor_name_prepped as whatever the user typed. For instance, if the user typed {{config['SPACE_SPICE']}}, it gets inserted literally:

```
first_pass_render = render_template_string(
    outer_shell,
    visitor_name_prepped="{{config['SPACE_SPICE']}}",
    scope_prepped="None"
)
```

Second Pass Rendering
The output of the first pass (a string) still contains Jinja syntax ({{config['SPACE_SPICE']}}). We render_template_string on it again, passing config=GalacticPortal.config:

```
second_pass_render = render_template_string(first_pass_render, config=GalacticPortal.config)
```

On this second pass, if the string {{config['SPACE_SPICE']}} is present, Jinja will look up config['SPACE_SPICE'] in GalacticPortal.config. This yields the secret value.

# Why It’s Rare in Real World Production
Security Concerns: Double rendering is dangerous because it can enable SSTI.
Performance & Complexity: Rendering templates twice is generally unnecessary overhead.
Better Alternatives: If you want to re-use partial templates, you can do so without literally re-rendering user input in a second pass.
In other words, it’s typically a sign of a misconfiguration, development hack, or a strange business need, rather than a standard practice.

Legitimate (Though Uncommon) Use Cases
While almost never recommended, there are a few real-world scenarios that can accidentally lead to double rendering:

User-Created “Mini-Templates”

Example: A content management system (CMS) letting users define custom placeholders (macro expansions) that get evaluated after being composed into a main template.
Nested Templates in a Database

If partial templates are stored in a DB and then combined with additional data in separate steps, you can inadvertently create a double render flow.
WYSIWYG + Macro Processing

A user-facing WYSIWYG editor might allow shortcodes/macros.
Step 1: Render the WYSIWYG HTML.
Step 2: Expand macros left behind.
Debugging / Testing Hacks

A developer might quickly hack in a “render once, then re-render for debugging” feature and never remove it.
None of these are ideal; they are accidental or edge cases that can introduce vulnerabilities.

Security Best Practices & Mitigations
Avoid Double Rendering

Render your templates once. If you need dynamic data, incorporate it before the single render pass.
Disable Autoescape Sparingly

By default, Jinja2 auto-escapes HTML. Turning it off is dangerous. In production, keep it on unless you have a very good reason not to.
Sanitize User Input

Never trust user-supplied data if you think it might contain Jinja code or other scripting elements.
Use a Sandbox

If you must evaluate user-supplied templates (like in a CMS), consider sandboxing with libraries that restrict Jinja’s capabilities (e.g., disabling certain functions or references).
Rotate Secrets, Use Asymmetric Keys

If secrets can leak, rotate them regularly, and prefer asymmetric JWT signing (e.g., RS256) over shared HMAC secrets.
Remove Debug/Dev Code

Make sure any debugging “hacks” or second-pass rendering code is removed before pushing to production.
Complete Obfuscated Example
Below is a fully obfuscated Flask application that demonstrates the concept. You can run it locally, set a secret environment variable, and see how an attacker might exploit double rendering:

```python
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

    1) We define an HTML template that references {{ visitor_name_prepped }}.
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
    first_pass_render = render_template_string(
        outer_shell,
        visitor_name_prepped=visitor_name_prepped,
        scope_prepped=scope_prepped
    )

    # === Second Pass ===
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
vbnet
Copy code

### How to Test

1. **Set the environment variable** (optional):
   ```bash
   export SPACE_SPICE="Sup3rZ3cretVal!"
Run the Flask app:
bash
Copy code
python3 obf_app.py
Exploit by visiting (or using curl):
bash
Copy code
curl -g "http://localhost:666/disorientation?visitor_name={{config[%27SPACE_SPICE%27]}}"
Result: The final HTML will display Sup3rZ3cretVal! in place of the Jinja tag.
Conclusion
Double rendering is a powerful but dangerous technique that often crops up in CTFs, security demos, or occasionally in misconfigured systems. While it’s uncommon in production, it’s an excellent educational tool to show how even “simple” templating logic can lead to server-side code execution or secret leakage when user inputs are rendered as code.

```

Key Takeaways:

Render user data only once, and carefully sanitize or escape it.
Avoid re-rendering any strings that could contain template expressions.
Use debug or development hacks (like double rendering) for educational or testing purposes only—never in a production environment handling sensitive data.
