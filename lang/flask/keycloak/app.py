#!/usr/bin/env python3

"""
Keycloak + Flask OIDC demo application.
Modernized from the original flask-oidc example.
"""

import json
import logging
import os
from functools import wraps

import requests
from flask import Flask, g, redirect, render_template_string, request, session, url_for
from flask_oidc import OpenIDConnect

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(__name__)

    app.config.update(
        # ── Core ──────────────────────────────────────────────────────────
        SECRET_KEY=os.environ.get("SECRET_KEY", "change-me-in-production"),
        # ── OIDC / Keycloak ───────────────────────────────────────────────
        OIDC_CLIENT_SECRETS=os.environ.get("OIDC_CLIENT_SECRETS", "client_secrets.json"),
        OIDC_ID_TOKEN_COOKIE_SECURE=os.environ.get("OIDC_COOKIE_SECURE", "false").lower() == "true",
        OIDC_REQUIRE_VERIFIED_EMAIL=False,
        OIDC_USER_INFO_ENABLED=True,
        OIDC_OPENID_REALM=os.environ.get("OIDC_REALM", "flask-demo"),
        OIDC_SCOPES=["openid", "email", "profile", "roles"],
        OIDC_INTROSPECTION_AUTH_METHOD="client_secret_post",
        OIDC_TOKEN_TYPE_HINT="access_token",
        # ── Flask ─────────────────────────────────────────────────────────
        TESTING=os.environ.get("TESTING", "false").lower() == "true",
        DEBUG=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )

    oidc.init_app(app)

    # Register blueprints / routes
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    _register_error_handlers(app)

    return app


oidc = OpenIDConnect()

# ---------------------------------------------------------------------------
# Role-based access control helper
# ---------------------------------------------------------------------------

def require_role(*roles: str):
    """
    Decorator that enforces Keycloak realm roles.
    Must be applied after @oidc.require_login.

    Usage:
        @app.route('/admin')
        @oidc.require_login
        @require_role('admin')
        def admin_panel(): ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token_info = _get_token_info()
            user_roles = (
                token_info.get("realm_access", {}).get("roles", [])
                if token_info
                else []
            )
            missing = [r for r in roles if r not in user_roles]
            if missing:
                logger.warning(
                    "Access denied for user %s — missing roles: %s",
                    token_info.get("sub", "unknown") if token_info else "unknown",
                    missing,
                )
                return _render("error.html", code=403, message="Insufficient permissions."), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _get_token_info() -> dict | None:
    """Return decoded token info for the current user, or None."""
    try:
        user_id = oidc.user_getfield("sub")
        if not user_id or user_id not in oidc.credentials_store:
            return None
        from oauth2client.client import OAuth2Credentials
        creds = OAuth2Credentials.from_json(oidc.credentials_store[user_id])
        return oidc.user_getinfo(["sub", "email", "preferred_username", "realm_access"])
    except Exception:
        logger.exception("Failed to retrieve token info")
        return None


def _get_access_token(user_id: str) -> str | None:
    """Safely extract the access token from the credentials store."""
    try:
        from oauth2client.client import OAuth2Credentials
        creds = OAuth2Credentials.from_json(oidc.credentials_store[user_id])
        return creds.access_token
    except Exception:
        logger.exception("Failed to extract access token for user %s", user_id)
        return None


# ---------------------------------------------------------------------------
# Simple inline templates  (swap for real .html files in production)
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, str] = {
    "home.html": """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Flask + Keycloak</title></head>
<body>
  <h1>Flask + Keycloak Demo</h1>
  {% if logged_in %}
    <p>Hello, <strong>{{ username }}</strong>!</p>
    <ul>
      <li><a href="{{ url_for('auth.private') }}">Private area</a></li>
      <li><a href="{{ url_for('auth.admin') }}">Admin panel</a></li>
      <li><a href="{{ url_for('auth.logout') }}">Log out</a></li>
    </ul>
  {% else %}
    <p>Welcome, anonymous visitor.</p>
    <a href="{{ url_for('auth.private') }}">Log in</a>
  {% endif %}
</body>
</html>
""",
    "private.html": """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Private — Flask + Keycloak</title></head>
<body>
  <h1>Private Area</h1>
  <p><strong>Username:</strong> {{ username }}</p>
  <p><strong>Email:</strong> {{ email }}</p>
  <p><strong>User ID:</strong> {{ user_id }}</p>
  <p><strong>Roles:</strong> {{ roles | join(', ') or 'none' }}</p>
  <hr>
  <p><em>Greeting from backend:</em> {{ greeting }}</p>
  <ul>
    <li><a href="{{ url_for('auth.home') }}">Home</a></li>
    <li>
      <a href="{{ kc_account_url }}">Keycloak Account</a>
    </li>
    <li><a href="{{ url_for('auth.logout') }}">Log out</a></li>
  </ul>
</body>
</html>
""",
    "admin.html": """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Admin — Flask + Keycloak</title></head>
<body>
  <h1>Admin Panel</h1>
  <p>Welcome, <strong>{{ username }}</strong>. You have admin access.</p>
  <ul>
    <li><a href="{{ url_for('auth.home') }}">Home</a></li>
    <li><a href="{{ url_for('auth.logout') }}">Log out</a></li>
  </ul>
</body>
</html>
""",
    "error.html": """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Error {{ code }}</title></head>
<body>
  <h1>{{ code }} — {{ message }}</h1>
  <a href="{{ url_for('auth.home') }}">Return home</a>
</body>
</html>
""",
}


def _render(template_name: str, **context) -> str:
    return render_template_string(_TEMPLATES[template_name], **context)


# ---------------------------------------------------------------------------
# Auth blueprint
# ---------------------------------------------------------------------------

from flask import Blueprint

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def home():
    logged_in = oidc.user_loggedin
    username = oidc.user_getfield("preferred_username") if logged_in else None
    return _render("home.html", logged_in=logged_in, username=username)


@auth_bp.route("/private")
@oidc.require_login
def private():
    info = oidc.user_getinfo(["preferred_username", "email", "sub"])
    username = info.get("preferred_username", "unknown")
    email = info.get("email", "unknown")
    user_id = info.get("sub", "")

    # Realm roles from the token
    token_info = _get_token_info() or {}
    roles = token_info.get("realm_access", {}).get("roles", [])

    # Call backend greeting service if we have a token
    greeting = f"Hello, {username}"
    if user_id in oidc.credentials_store:
        access_token = _get_access_token(user_id)
        if access_token:
            greeting = _fetch_greeting(access_token, username)

    kc_base = os.environ.get("KEYCLOAK_URL", "http://localhost:8081")
    realm = os.environ.get("OIDC_REALM", "flask-demo")
    kc_account_url = (
        f"{kc_base}/auth/realms/{realm}/account"
        f"?referrer=flask-app&referrer_uri={request.host_url}private"
    )

    return _render(
        "private.html",
        username=username,
        email=email,
        user_id=user_id,
        roles=roles,
        greeting=greeting,
        kc_account_url=kc_account_url,
    )


@auth_bp.route("/admin")
@oidc.require_login
@require_role("admin")
def admin():
    username = oidc.user_getfield("preferred_username")
    return _render("admin.html", username=username)


@auth_bp.route("/logout")
def logout():
    oidc.logout()
    session.clear()
    # Redirect to Keycloak's end-session endpoint for SSO logout
    kc_base = os.environ.get("KEYCLOAK_URL", "http://localhost:8081")
    realm = os.environ.get("OIDC_REALM", "flask-demo")
    post_logout = url_for("auth.home", _external=True)
    kc_logout_url = (
        f"{kc_base}/auth/realms/{realm}/protocol/openid-connect/logout"
        f"?redirect_uri={post_logout}"
    )
    logger.info("User logged out, redirecting to Keycloak end-session.")
    return redirect(kc_logout_url)


# ---------------------------------------------------------------------------
# API blueprint
# ---------------------------------------------------------------------------

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/whoami", methods=["GET"])
@oidc.accept_token(require_token=True, scopes_required=["openid"])
def whoami():
    """Return basic identity info for the bearer token owner."""
    sub = g.oidc_token_info.get("sub", "unknown")
    email = g.oidc_token_info.get("email", "unknown")
    roles = g.oidc_token_info.get("realm_access", {}).get("roles", [])
    logger.debug("API /whoami called by sub=%s", sub)
    return json.dumps({"sub": sub, "email": email, "roles": roles}), 200, {
        "Content-Type": "application/json"
    }


@api_bp.route("/hello", methods=["POST"])
@oidc.accept_token(require_token=True, scopes_required=["openid"])
def hello_api():
    """Protected API endpoint — returns a greeting for the token owner."""
    sub = g.oidc_token_info.get("sub", "unknown")
    return json.dumps({"hello": f"Welcome, {sub}"}), 200, {
        "Content-Type": "application/json"
    }


# ---------------------------------------------------------------------------
# Backend service helper
# ---------------------------------------------------------------------------

_GREETING_SERVICE_URL = os.environ.get(
    "GREETING_SERVICE_URL", "http://localhost:8080/greeting"
)
_REQUEST_TIMEOUT = int(os.environ.get("BACKEND_TIMEOUT", "5"))


def _fetch_greeting(access_token: str, fallback_username: str) -> str:
    """Call the downstream greeting service with the user's access token."""
    try:
        resp = requests.get(
            _GREETING_SERVICE_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.text
    except requests.exceptions.HTTPError as exc:
        logger.warning("Greeting service returned HTTP error: %s", exc)
    except requests.exceptions.ConnectionError:
        logger.warning("Could not connect to greeting service at %s", _GREETING_SERVICE_URL)
    except requests.exceptions.Timeout:
        logger.warning("Greeting service timed out after %ss", _REQUEST_TIMEOUT)
    except Exception:
        logger.exception("Unexpected error calling greeting service")
    return f"Hello, {fallback_username}"


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(401)
    def unauthorized(e):
        return _render("error.html", code=401, message="Unauthorized."), 401

    @app.errorhandler(403)
    def forbidden(e):
        return _render("error.html", code=403, message="Forbidden."), 403

    @app.errorhandler(404)
    def not_found(e):
        return _render("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        return _render("error.html", code=500, message="Internal server error."), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
    )

##
##
# .env  (never commit real secrets)
SECRET_KEY=super-secret-change-me
KEYCLOAK_URL=http://localhost:8081
OIDC_REALM=flask-demo
OIDC_CLIENT_SECRETS=client_secrets.json
OIDC_COOKIE_SECURE=false          # set true behind HTTPS
GREETING_SERVICE_URL=http://localhost:8080/greeting
BACKEND_TIMEOUT=5
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
TESTING=false
##
## 
# client_secrets.json structure for Keycloak:
{
  "web": {
    "issuer": "http://localhost:8081/auth/realms/flask-demo",
    "auth_uri": "http://localhost:8081/auth/realms/flask-demo/protocol/openid-connect/auth",
    "client_id": "flask-app",
    "client_secret": "YOUR_CLIENT_SECRET_HERE",
    "redirect_uris": ["http://localhost:5000/*"],
    "userinfo_uri": "http://localhost:8081/auth/realms/flask-demo/protocol/openid-connect/userinfo",
    "token_uri": "http://localhost:8081/auth/realms/flask-demo/protocol/openid-connect/token",
    "token_introspection_uri": "http://localhost:8081/auth/realms/flask-demo/protocol/openid-connect/token/introspect"
  }
}
##
##
