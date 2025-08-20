from flask import Blueprint, jsonify, current_app, request
from werkzeug.utils import import_string
from functools import wraps

admin_api = Blueprint("admin_api", __name__)

def require_admin_token(f):
    """Simple decorator to protect admin endpoints with a token"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Admin-Token")
        expected = current_app.config.get("ADMIN_API_TOKEN")
        if not expected or token != expected:
            return jsonify(code=403, error="Forbidden"), 403
        return f(*args, **kwargs)
    return wrapper

@admin_api.route("/help", methods=["GET"])
@require_admin_token
def routes_info():
    """
    Return all defined routes and their endpoint docstrings.
    Protected with an admin token to avoid leaking sensitive info.
    """
    routes = []
    for rule in current_app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue

        try:
            view_func = current_app.view_functions[rule.endpoint]
            doc = (view_func.__doc__ or "").strip()

            # If the view function has an import_name, try to resolve it
            if hasattr(view_func, "import_name"):
                try:
                    obj = import_string(view_func.import_name)
                    doc = (obj.__doc__ or doc or "").strip()
                except Exception:
                    current_app.logger.warning(
                        "Could not import %s for route %s",
                        view_func.import_name,
                        rule.rule,
                    )

            routes.append({
                "rule": rule.rule,
                "methods": sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS")),
                "endpoint": rule.endpoint,
                "doc": doc or "(no docstring provided)"
            })

        except Exception as exc:
            current_app.logger.error(
                "Invalid route: %s => %s", rule.rule, rule.endpoint, exc_info=True
            )
            routes.append({
                "rule": rule.rule,
                "endpoint": rule.endpoint,
                "error": "Invalid route definition"
            })

    return jsonify(code=200, data=routes)
