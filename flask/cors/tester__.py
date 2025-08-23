from __future__ import annotations

import csv
import io
import json
import logging
import os
from typing import Any, Callable, Dict, Iterable, Tuple

from flask import Flask, Response, jsonify, make_response, request
from flask_cors import CORS

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
ALLOWED_ORIGINS = os.getenv("FRONTEND_ORIGIN", "https://username.github.io").split(",")
DEBUG = os.getenv("FLASK_DEBUG", "true").lower() in {"1", "true", "yes"}

app = Flask(__name__)

# Global JSON behavior
app.config.update(
    JSON_SORT_KEYS=False,
)

# -----------------------------------------------------------------------------
# CORS (scoped to /api/*)
# -----------------------------------------------------------------------------
CORS(
    app,
    resources={r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }},
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("cors-test")

@app.before_request
def _log_request() -> None:
    logger.info("REQ %s %s args=%s json=%s",
                request.method, request.path, dict(request.args),
                _safe_json_preview(request))

def _safe_json_preview(req) -> Any:
    if req.is_json:
        try:
            return req.get_json(silent=True)
        except Exception:
            return "<invalid-json>"
    return None

# -----------------------------------------------------------------------------
# Security headers
# -----------------------------------------------------------------------------
@app.after_request
def _security_headers(resp: Response) -> Response:
    # Reasonably strict defaults for a demo app (adjust for your front-end)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")
    # Inline script is used in this demo page; relax CSP for root only.
    if request.path == "/":
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self' https://httpbin.org; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
        )
    else:
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self' https://httpbin.org"
        )
    return resp

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def json_error(message: str, status: int) -> Response:
    return jsonify(error=message, status=status), status

def csv_response(rows: Iterable[Iterable[Any]], filename: str = "data.csv") -> Response:
    buf = io.StringIO()
    writer = csv.writer(buf)
    for row in rows:
        writer.writerow(row)
    buf.seek(0)
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp

# -----------------------------------------------------------------------------
# API ROUTES
# -----------------------------------------------------------------------------
@app.route("/api/hello", methods=["GET"])
def hello() -> Response:
    return jsonify(message="Hello, world!")

@app.route("/api/datagetter", methods=["GET"])
def get_data() -> Response:
    return jsonify({
        "list": [
            {"id": 1, "userid": 0, "amount": 3},
            {"id": 2, "userid": 1, "amount": 7}
        ]
    })

@app.route("/api/user/<int:user_id>", methods=["GET"])
def get_user(user_id: int) -> Response:
    users = {
        1: {"name": "Alice", "role": "admin"},
        2: {"name": "Bob", "role": "user"}
    }
    return jsonify(users.get(user_id, {"error": "User not found"}))

@app.route("/api/search", methods=["GET"])
def search() -> Response:
    query = request.args.get("q", "").strip()
    if not query:
        return json_error("Missing query parameter 'q'", 400)
    return jsonify(results=[f"Result for {query} #{i}" for i in range(1, 4)])

@app.route("/api/echo", methods=["POST"])
def echo() -> Response:
    if not request.is_json:
        return json_error("Content-Type must be application/json", 415)
    data = request.get_json(silent=True)
    if data is None:
        return json_error("Invalid JSON body", 400)
    return jsonify(received=data)

@app.route("/api/secret", methods=["GET"])
def secret() -> Response:
    return jsonify(error="Forbidden"), 403

@app.route("/api/stream", methods=["GET"])
def stream() -> Response:
    def generate():
        yield "Hello\n"
        yield "This is a streamed response\n"
        yield "Line by line\n"
    return Response(generate(), mimetype="text/plain")

@app.route("/api/download", methods=["GET"])
def download() -> Response:
    rows = [
        ("id", "name", "amount"),
        (1, "Alice", 10),
        (2, "Bob", 20),
    ]
    return csv_response(rows, filename="data.csv")

# -----------------------------------------------------------------------------
# TEST PAGE (no emojis)
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index() -> str:
    return """
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>CORS Test Harness</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.5; }
      pre { background: #f4f4f4; padding: 1rem; border-radius: 6px; white-space: pre-wrap; }
      button { margin: 0.25rem 0; padding: 0.5rem 0.9rem; cursor: pointer; }
      input { padding: 0.4rem; margin-right: 0.5rem; }
      section { margin-bottom: 2rem; }
      h1, h2 { margin: 0.3rem 0 0.8rem; }
      #all-results { background: #eef; }
      .row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
    </style>
    <script>
      // Basic fetch helper with timeout & JSON/text fallback
      async function callApi(endpoint, options = {}, timeoutMs = 8000) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
          const res = await fetch(endpoint, { ...options, signal: controller.signal });
          const ct = res.headers.get("content-type") || "";
          const data = ct.includes("application/json") ? await res.json() : await res.text();
          return { ok: res.ok, status: res.status, data };
        } catch (err) {
          return { ok: false, status: "ERROR", data: String(err) };
        } finally {
          clearTimeout(timer);
        }
      }

      function show(id, value) {
        document.getElementById(id).textContent =
          typeof value === "string" ? value : JSON.stringify(value, null, 2);
      }

      async function fetchHello() {
        const r = await callApi("/api/hello");
        show("hello-result", r);
        return r;
      }

      async function fetchData() {
        const r = await callApi("/api/datagetter");
        show("data-result", r);
        return r;
      }

      async function fetchUser(id = 1) {
        const r = await callApi(`/api/user/${id}`);
        show("user-result", r);
        return r;
      }

      async function fetchSearch(q = "test") {
        const r = await callApi(`/api/search?q=${encodeURIComponent(q)}`);
        show("search-result", r);
        return r;
      }

      async function postEcho(msg = "Hello Echo") {
        const r = await callApi("/api/echo", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ msg })
        });
        show("echo-result", r);
        return r;
      }

      async function fetchSecret() {
        const r = await callApi("/api/secret");
        show("secret-result", r);
        return r;
      }

      async function fetchStream() {
        const r = await callApi("/api/stream");
        show("stream-result", r.data);
        return r;
      }

      async function fetchExternal() {
        try {
          const res = await fetch("https://httpbin.org/get", { method: "GET" });
          const data = await res.json();
          const out = { ok: true, status: res.status, data };
          show("external-result", out);
          return out;
        } catch (err) {
          const out = { ok: false, error: String(err) };
          show("external-result", out);
          return out;
        }
      }

      async function runAllTests() {
        const results = {};
        results.hello = await fetchHello();
        results.datagetter = await fetchData();
        results.user = await fetchUser(1);
        results.search = await fetchSearch("demo");
        results.echo = await postEcho("RunAll demo");
        results.secret = await fetchSecret();
        results.stream = await fetchStream();
        results.external = await fetchExternal();
        show("all-results", results);
      }
    </script>
  </head>
  <body>
    <h1>Flask CORS Test Harness</h1>
    <p>Try each example below, or run them all at once.</p>

    <section>
      <h2>Run All Tests</h2>
      <button onclick="runAllTests()">Run All</button>
      <pre id="all-results"></pre>
    </section>

    <section>
      <h2>1. /api/hello</h2>
      <button onclick="fetchHello()">Fetch Hello</button>
      <pre id="hello-result"></pre>
    </section>

    <section>
      <h2>2. /api/datagetter</h2>
      <button onclick="fetchData()">Fetch Data</button>
      <pre id="data-result"></pre>
    </section>

    <section>
      <h2>3. /api/user/&lt;id&gt;</h2>
      <div class="row">
        <input id="user-id" type="number" placeholder="Enter user id (1 or 2)" />
        <button onclick="fetchUser(document.getElementById('user-id').value)">Fetch User</button>
      </div>
      <pre id="user-result"></pre>
    </section>

    <section>
      <h2>4. /api/search?q=...</h2>
      <div class="row">
        <input id="search-q" type="text" placeholder="Enter search term" />
        <button onclick="fetchSearch(document.getElementById('search-q').value)">Search</button>
      </div>
      <pre id="search-result"></pre>
    </section>

    <section>
      <h2>5. POST /api/echo</h2>
      <div class="row">
        <input id="echo-msg" type="text" placeholder="Message to echo" />
        <button onclick="postEcho(document.getElementById('echo-msg').value)">Send Echo</button>
      </div>
      <pre id="echo-result"></pre>
    </section>

    <section>
      <h2>6. /api/secret</h2>
      <button onclick="fetchSecret()">Fetch Secret</button>
      <pre id="secret-result"></pre>
    </section>

    <section>
      <h2>7. /api/stream</h2>
      <button onclick="fetchStream()">Fetch Stream</button>
      <pre id="stream-result"></pre>
    </section>

    <section>
      <h2>8. /api/download</h2>
      <a href="/api/download" target="_blank"><button>Download CSV</button></a>
    </section>

    <section>
      <h2>9. External CORS Test (httpbin.org)</h2>
      <button onclick="fetchExternal()">Fetch External</button>
      <pre id="external-result"></pre>
    </section>

    <hr>
    <h2>Usage Guide</h2>
    <ul>
      <li><b>/api/hello</b>: Simple JSON health check.</li>
      <li><b>/api/datagetter</b>: Returns fixed test data list.</li>
      <li><b>/api/user/&lt;id&gt;</b>: Fetch user by ID (1=Alice, 2=Bob, others=error).</li>
      <li><b>/api/search?q=term</b>: Example query parameter search (requires <code>q</code>).</li>
      <li><b>POST /api/echo</b>: Send JSON (<code>{"msg": "hi"}</code>) and get it back.</li>
      <li><b>/api/secret</b>: Always returns 403 Forbidden (error example).</li>
      <li><b>/api/stream</b>: Demonstrates streamed text response.</li>
      <li><b>/api/download</b>: Downloads a CSV file.</li>
      <li><b>External CORS Test</b>: Calls <code>https://httpbin.org/get</code> to show cross-domain behavior.</li>
      <li><b>Run All Tests</b>: Executes all endpoints and shows a combined report.</li>
    </ul>
  </body>
</html>
    """

# -----------------------------------------------------------------------------
# Error Handlers (consistent JSON)
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def _404(_: Exception) -> Response:
    return json_error("Not Found", 404)

@app.errorhandler(405)
def _405(_: Exception) -> Response:
    return json_error("Method Not Allowed", 405)

@app.errorhandler(500)
def _500(_: Exception) -> Response:
    logger.exception("Unhandled server error")
    return json_error("Internal Server Error", 500)

# -----------------------------------------------------------------------------
# Entry
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print("Starting Flask CORS Test Harness on http://127.0.0.1:5000/")
    app.run(host="0.0.0.0", port=5000, debug=DEBUG)
