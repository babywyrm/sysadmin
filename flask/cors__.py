from __future__ import annotations

from flask import Flask, jsonify, Response
from flask_cors import CORS

app = Flask(__name__)

# --- CORS CONFIG ---
# Development: allow all origins
# CORS(app, resources={r"/api/*": {"origins": "*"}})

# Production: restrict to GitHub Pages
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://username.github.io"],  # change to your frontend domain
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})


# --- API ROUTES ---
@app.route("/api/hello")
def hello() -> Response:
    """Simple health check"""
    return jsonify(message="Hello, world!")


@app.route("/api/datagetter")
def get_data() -> Response:
    """Return some test data"""
    return jsonify({
        "list": [
            {"id": 1, "userid": 0, "amount": 3},
            {"id": 2, "userid": 1, "amount": 7}
        ]
    })


# --- TEST HTML PAGE ---
@app.route("/")
def index() -> str:
    """Serve a test HTML page that calls the API"""
    return """
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>CORS Test Harness</title>
    <style>
      body { font-family: sans-serif; margin: 2em; }
      pre { background: #f4f4f4; padding: 1em; border-radius: 5px; }
      button { margin-top: 1em; padding: 0.5em 1em; }
    </style>
    <script>
      async function fetchHello() {
        try {
          const res = await fetch("/api/hello");
          const data = await res.json();
          document.getElementById("hello-result").innerText = JSON.stringify(data, null, 2);
        } catch (err) {
          console.error("Error:", err);
        }
      }

      async function fetchData() {
        try {
          const res = await fetch("/api/datagetter");
          const data = await res.json();
          document.getElementById("data-result").innerText = JSON.stringify(data, null, 2);
        } catch (err) {
          console.error("Error:", err);
        }
      }
    </script>
  </head>
  <body>
    <h1>Flask CORS Test Harness</h1>
    <p>This page is served by Flask and makes API calls to the same server.</p>

    <h2>Test 1: /api/hello</h2>
    <button onclick="fetchHello()">Fetch Hello</button>
    <pre id="hello-result"></pre>

    <h2>Test 2: /api/datagetter</h2>
    <button onclick="fetchData()">Fetch Data</button>
    <pre id="data-result"></pre>

    <p>Open the browser console (F12 → Console) to see any CORS errors.</p>
  </body>
</html>
    """


# --- ENTRY POINT ---
if __name__ == "__main__":
    print("🚀 Starting Flask CORS Test Harness on http://127.0.0.1:5000/")
    app.run(host="0.0.0.0", port=5000, debug=True)
