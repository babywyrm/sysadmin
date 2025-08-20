from __future__ import annotations
from flask import Flask, jsonify, Response, request
from flask_cors import CORS
import io
import csv

app = Flask(__name__)

# --- CORS CONFIG ---
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://username.github.io"],  # replace with your frontend domain
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})


# --- API ROUTES ---
@app.route("/api/hello")
def hello() -> Response:
    return jsonify(message="Hello, world!")

@app.route("/api/datagetter")
def get_data() -> Response:
    return jsonify({
        "list": [
            {"id": 1, "userid": 0, "amount": 3},
            {"id": 2, "userid": 1, "amount": 7}
        ]
    })

# Path parameter
@app.route("/api/user/<int:user_id>")
def get_user(user_id: int) -> Response:
    users = {
        1: {"name": "Alice", "role": "admin"},
        2: {"name": "Bob", "role": "user"}
    }
    return jsonify(users.get(user_id, {"error": "User not found"}))

# Query parameter
@app.route("/api/search")
def search() -> Response:
    query = request.args.get("q", "")
    return jsonify(results=[f"Result for {query} #{i}" for i in range(1, 4)])

# POST JSON echo
@app.route("/api/echo", methods=["POST"])
def echo() -> Response:
    data = request.json
    return jsonify(received=data)

# Forbidden
@app.route("/api/secret")
def secret() -> Response:
    return jsonify(error="Forbidden"), 403

# Streaming
@app.route("/api/stream")
def stream() -> Response:
    def generate():
        yield "Hello\n"
        yield "This is a streamed response\n"
        yield "Line by line\n"
    return Response(generate(), mimetype="text/plain")

# File download
@app.route("/api/download")
def download() -> Response:
    data = io.StringIO()
    writer = csv.writer(data)
    writer.writerow(["id", "name", "amount"])
    writer.writerow([1, "Alice", 10])
    writer.writerow([2, "Bob", 20])
    data.seek(0)
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=data.csv"}
    )


# --- TEST HTML PAGE ---
@app.route("/")
def index() -> str:
    return """
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>CORS Test Harness Extended</title>
    <style>
      body { font-family: sans-serif; margin: 2em; line-height: 1.4; }
      pre { background: #f4f4f4; padding: 1em; border-radius: 5px; }
      button { margin: 0.5em 0; padding: 0.5em 1em; }
      input { padding: 0.4em; margin-right: 0.5em; }
      section { margin-bottom: 2em; }
      h2 { margin-top: 1.5em; }
    </style>
    <script>
      async function callApi(endpoint, options = {}) {
        try {
          const res = await fetch(endpoint, options);
          let data;
          const ct = res.headers.get("content-type");
          if (ct && ct.includes("application/json")) {
            data = await res.json();
          } else {
            data = await res.text();
          }
          return { ok: res.ok, status: res.status, data };
        } catch (err) {
          return { ok: false, status: "ERROR", data: err.toString() };
        }
      }

      async function fetchHello() {
        const res = await callApi("/api/hello");
        document.getElementById("hello-result").innerText = JSON.stringify(res, null, 2);
      }

      async function fetchData() {
        const res = await callApi("/api/datagetter");
        document.getElementById("data-result").innerText = JSON.stringify(res, null, 2);
      }

      async function fetchUser() {
        const id = document.getElementById("user-id").value;
        const res = await callApi(`/api/user/${id}`);
        document.getElementById("user-result").innerText = JSON.stringify(res, null, 2);
      }

      async function fetchSearch() {
        const q = document.getElementById("search-q").value;
        const res = await callApi(`/api/search?q=${encodeURIComponent(q)}`);
        document.getElementById("search-result").innerText = JSON.stringify(res, null, 2);
      }

      async function postEcho() {
        const payload = { msg: document.getElementById("echo-msg").value };
        const res = await callApi("/api/echo", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(payload)
        });
        document.getElementById("echo-result").innerText = JSON.stringify(res, null, 2);
      }

      async function fetchSecret() {
        const res = await callApi("/api/secret");
        document.getElementById("secret-result").innerText = JSON.stringify(res, null, 2);
      }

      async function fetchStream() {
        const res = await callApi("/api/stream");
        document.getElementById("stream-result").innerText = res.data;
      }

      async function fetchExternal() {
        try {
          const res = await fetch("https://httpbin.org/get");
          const data = await res.json();
          document.getElementById("external-result").innerText = JSON.stringify({ok: true, status: res.status, data}, null, 2);
        } catch (err) {
          document.getElementById("external-result").innerText = JSON.stringify({ok: false, error: err.toString()}, null, 2);
        }
      }
    </script>
  </head>
  <body>
    <h1>Flask CORS Test Harness (Extended)</h1>
    <p>Try each example. Open the console for CORS/debug output.</p>

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
      <input id="user-id" type="number" placeholder="Enter user id (1 or 2)" />
      <button onclick="fetchUser()">Fetch User</button>
      <pre id="user-result"></pre>
    </section>

    <section>
      <h2>4. /api/search?q=...</h2>
      <input id="search-q" type="text" placeholder="Enter search term" />
      <button onclick="fetchSearch()">Search</button>
      <pre id="search-result"></pre>
    </section>

    <section>
      <h2>5. POST /api/echo</h2>
      <input id="echo-msg" type="text" placeholder="Message to echo" />
      <button onclick="postEcho()">Send Echo</button>
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
      <a href="/api/download" target="_blank">
        <button>Download CSV</button>
      </a>
    </section>

    <section>
      <h2>9. External CORS Test (httpbin.org)</h2>
      <button onclick="fetchExternal()">Fetch External</button>
      <pre id="external-result"></pre>
    </section>

    <hr>
    <h2>📘 Usage Guide</h2>
    <ul>
      <li><b>/api/hello</b>: Simple JSON health check.</li>
      <li><b>/api/datagetter</b>: Returns fixed test data list.</li>
      <li><b>/api/user/&lt;id&gt;</b>: Fetch user by ID (1=Alice, 2=Bob, others=error).</li>
      <li><b>/api/search?q=term</b>: Example query parameter search.</li>
      <li><b>POST /api/echo</b>: Send JSON ({"msg": "hi"}) and get it back.</li>
      <li><b>/api/secret</b>: Always returns 403 Forbidden (error example).</li>
      <li><b>/api/stream</b>: Demonstrates streamed text response.</li>
      <li><b>/api/download</b>: Downloads CSV file.</li>
      <li><b>External CORS Test</b>: Calls <code>https://httpbin.org/get</code> to show how browser handles cross-domain requests.</li>
    </ul>
    <p>
      Use these examples to verify <b>CORS configuration</b>, test <b>different HTTP methods</b>, 
      and confirm how browsers enforce cross-origin rules.
    </p>
  </body>
</html>
    """


# --- ENTRY POINT ---
if __name__ == "__main__":
    print("🚀 Starting Flask CORS Test Harness on http://127.0.0.1:5000/")
    app.run(host="0.0.0.0", port=5000, debug=True)

